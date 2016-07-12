package s3layer

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"github.com/gorilla/mux"

	"github.com/tsileo/s3layer/s3auth"
)

const (
	S3Date = "2006-01-02T15:04:05.007Z"
	Xmlns  = "http://s3.amazonaws.com/doc/2006-03-01/"
)

var S3FakeStorageClass = "STANDARD"

// XXX(tsileo): pre-signed upload url (POST multi-part) using Bewit?

func writeXML(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/xml")
	byteXML, err := xml.MarshalIndent(data, "", `   `)
	if err != nil {
		panic(err)
	}
	w.Write([]byte(xml.Header))
	w.Write(byteXML)

}

type Bucket struct {
	Name         string
	CreationDate time.Time
}

type BucketResult struct {
	Name         string `xml:"Name"`
	CreationDate string `xml:"CreationDate"`
}

type ListAllMyBucketsResult struct {
	XMLName          xml.Name        `xml:"ListAllMyBucketsResult"`
	Xmlns            string          `xml:"xmlns,attr"`
	OwnerID          string          `xml:"Owner>ID"`
	OwnerDisplayName string          `xml:"Owner>DisplayName"`
	Buckets          []*BucketResult `xml:"Buckets>Bucket"`
}

func buildListAllMyBucketsResult(buckets []*BucketResult) *ListAllMyBucketsResult {
	return &ListAllMyBucketsResult{
		Xmlns:   Xmlns,
		Buckets: buckets,
	}
}

type ListBucketResultPrefix struct {
	Prefix string
}

type ListBucketResultContent struct {
	Key          string
	Size         int
	LastModified string
	ETag         string
	StorageClass string
}

type CompleteMultipartUpload struct {
	XMLName xml.Name      `xml:"CompleteMultipartUpload"`
	Xmlns   string        `xml:"xmlns,attr"`
	Parts   []*UploadPart `xml:"Part"`
}

type ListBucketResult struct {
	XMLName        xml.Name `xml:"ListBucketResult"`
	Xmlns          string   `xml:"xmlns,attr"`
	Name           string
	Prefix         string
	KeyCount       int
	MaxKeys        int
	IsTruncated    bool
	Contents       []*ListBucketResultContent
	CommonPrefixes []*ListBucketResultPrefix
}

func buildListBucketResult(name string, contents []*ListBucketResultContent, prefixes []*ListBucketResultPrefix) *ListBucketResult {
	return &ListBucketResult{
		Name:           name,
		Contents:       contents,
		CommonPrefixes: prefixes,
		Xmlns:          Xmlns,
	}
}

type InitiateMultipartUploadResult struct {
	XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
	Xmlns    string   `xml:"xmlns,attr"`
	Bucket   string
	Key      string
	UploadId string
}

type CompleteMultipartUploadResult struct {
	XMLName  xml.Name `xml:"CompleteMultipartUploadResult"`
	Xmlns    string   `xml:"xmlns,attr"`
	Location string
	Bucket   string
	Key      string
	ETag     string
}

type Error struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string
	Message   string
	Resource  string
	RequestId string
}

func buildError(code, message, resource string) *Error {
	return &Error{
		Code:     code,
		Message:  message,
		Resource: resource,
	}
}

type UploadPart struct {
	PartNumber int
	ETag       string // XXX(tsileo): be careful as the ETag may be surrounded by double quote "<ETag>"
}

type UploadPartResponse struct {
	Number       int
	ETag         string
	Size         int
	LastModified string
}

// TODO(tsileo): turn this into an interface
type S3Layer struct {
	BucketsFunc func() ([]*Bucket, error)

	ListBucketFunc func(bucket, prefix string) ([]*ListBucketResultContent, []*ListBucketResultPrefix, error)

	GetObjectFunc func(bucket, key string) (io.Reader, error)
	PutObjectFunc func(bucket, key string, reader io.Reader) error

	CredFunc func(accessKey string) (string, error)

	MultipartInit     func(bucket, key, uploadID string) error
	MultipartUpload   func(uploadID string, partNumber int, etag string, data io.Reader) error
	MulitpartList     func(uploadID string, maxParts, partNumberMarker int) ([]*UploadPartResponse, error) // FIXME(tsileo): handle a time.Time in the struct
	MultipartAbort    func(uploadID string) error
	MultipartComplete func(uploadID string, parts []*UploadPart) error
}

func (sl *S3Layer) Handler() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("URL:%+v\n", r.URL)
		fmt.Printf("Authorization: %+v\n", r.Header.Get("Authorization"))
		fmt.Printf("headers: %v/%+v\n", r.Host, r.Header)
		fmt.Printf("query=%+v", r.URL.Query())
		if _, ok := r.URL.Query()["upload"]; ok {
			fmt.Printf("upload detected\n")
		}

		// FIXME(tsileo): parse the path manually, and drop gorilla/mux
		vars := mux.Vars(r)
		bucket := vars["bucket"]
		path := "/" + vars["path"]
		data, err := ioutil.ReadAll(r.Body)
		if err != nil {
			panic(err)
		}
		payload := fmt.Sprintf("%x", sha256.Sum256(data))

		if err := s3auth.ParseAuth(sl.CredFunc, r.Header.Get("Authorization"), payload, r); err != nil {
			if err == s3auth.ErrInvalidRequest {
				w.WriteHeader(400)
				writeXML(w, buildError("InvalidRequest", "Please use AWS4-HMAC-SHA256", path))
				return
			}
			w.WriteHeader(403)
			writeXML(w, buildError("SignatureDoesNotMatch", "Signature does not match", path))
			return
		}

		if r.URL.Path == "/" {
			buckets, err := sl.BucketsFunc()
			if err != nil {
				panic(err)
			}
			res := []*BucketResult{}
			for _, b := range buckets {
				res = append(res, &BucketResult{
					Name:         b.Name,
					CreationDate: b.CreationDate.Format(S3Date),
				})
			}
			writeXML(w, buildListAllMyBucketsResult(res))
			return
		}

		// Bucket handler
		if path == "/" {
			switch r.Method {
			case "GET", "HEAD":
				// List objects, the only delimiter supported is "/"
				content, prefixes, err := sl.ListBucketFunc(bucket, r.URL.Query().Get("prefix"))
				if err != nil {
					panic(err)
				}
				if r.Method == "HEAD" {
					// XXX(tsileo): should any additional headers be outputed?
					return
				}
				// response, err := buildListBucketResult(bucket, content, prefixes)
				writeXML(w, buildListBucketResult(bucket, content, prefixes))
				return
			case "PUT":
				// Create bucket (check if null, i.e. optional)
			case "DELETE":
				// Delete bucket
			default:
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
		}

		// Object handler
		switch r.Method {
		case "GET", "HEAD":
			if uploadID := r.URL.Query().Get("uploadId"); uploadID != "" {
				// TODO(tsileo): list the parts sl.MultipartList(uploadID,
				return
			}

			// Serve the file content
			reader, err := sl.GetObjectFunc(bucket, path[1:])
			if err != nil {
				panic(err)
			}
			data, err := ioutil.ReadAll(reader)
			if err != nil {
				panic(err)
			}
			w.Header().Set("ETag", fmt.Sprintf("%x", md5.Sum(data)))

			// Returns now if it's a HEAD request
			if r.Method == "HEAD" {
				return
			}

			http.ServeContent(w, r, filepath.Base(path), time.Now(), bytes.NewReader(data))
			return
		case "POST":
			if _, ok := r.URL.Query()["uploads"]; ok {
				uploadID := randomID()
				if err := sl.MultipartInit(bucket, path[1:], uploadID); err != nil {
					panic(err)
				}
				writeXML(w, &InitiateMultipartUploadResult{
					Bucket:   bucket,
					UploadId: uploadID,
					Key:      path[1:],
				})
				return
			}
			if uploadID := r.URL.Query().Get("uploadId"); uploadID != "" {
				completeMultipartUpload := &CompleteMultipartUpload{}
				if err := xml.Unmarshal(data, completeMultipartUpload); err != nil {
					panic(err)
				}
				if err := sl.MultipartComplete(uploadID, completeMultipartUpload.Parts); err != nil {
					panic(err)
				}

				writeXML(w, &CompleteMultipartUploadResult{
					Xmlns:    Xmlns,
					Bucket:   bucket,
					Key:      path[1:],
					ETag:     "TODO",
					Location: "TODO",
				})
				return
			}

		case "PUT":
			// TODO(tsileo): handle Content-MD5 header?
			// FIXME(tsileo): support ACL (/bucket/object?acl)
			// Create an object from the request body
			// FIXME(tsileo): handle the base64-encoded Content-MD5 header
			etag := fmt.Sprintf("%x", md5.Sum(data))
			w.Header().Set("ETag", etag)

			// Check if this is a multi-part upload
			uploadID := r.URL.Query().Get("uploadId")
			if uploadID != "" {
				partNumer, err := strconv.Atoi(r.URL.Query().Get("partNumber"))
				if err != nil {
					panic(err)
				}

				if err := sl.MultipartUpload(uploadID, partNumer, etag, bytes.NewReader(data)); err != nil {
					panic(err)
				}
				return
			}

			// This is a regular upload via PUT (whole file content included in the request body)
			if err := sl.PutObjectFunc(bucket, path[1:], bytes.NewReader(data)); err != nil {
				panic(err)
			}
			return
		case "DELETE":
			if uploadID := r.URL.Query().Get("uploadId"); uploadID != "" {
				if err := sl.MultipartAbort(uploadID); err != nil {
					panic(err)
				}
				// Returns a 204
				w.WriteHeader(http.StatusNoContent)
				return
			}
			// TODO(tsileo): support DELETE object
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	}
}

func randomID() string {
	r := make([]byte, 32)
	if _, err := rand.Read(r); err != nil {
		panic(err)
	}
	return hex.EncodeToString(r)
}
