package s3layer

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"time"

	"github.com/gorilla/mux"

	"github.com/tsileo/s3layer/s3auth"
)

const S3Date = "2006-01-02T15:04:05.007Z"

var S3FakeStorageClass = "STANDARD"

func writeXML(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/xml")
	byteXML, err := xml.MarshalIndent(data, "", `   `)
	if err != nil {
		panic(err)
	}
	w.Write([]byte(xml.Header))
	w.Write(byteXML)
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

type ListBucketResult struct {
	Name           string
	Prefix         string
	KeyCount       int
	MaxKeys        int
	IsTruncated    bool
	Contents       []*ListBucketResultContent
	CommonPrefixes []*ListBucketResultPrefix
	Xmlns          string `xml:"xmlns,attr"`
}

func buildListBucketResult(name string, contents []*ListBucketResultContent, prefixes []*ListBucketResultPrefix) (interface{}, error) {
	tmp := struct {
		ListBucketResult
		XMLName struct{} `xml:"ListBucketResult"`
	}{ListBucketResult: ListBucketResult{
		Name:           name,
		Contents:       contents,
		CommonPrefixes: prefixes,
		Xmlns:          "http://s3.amazonaws.com/doc/2006-03-01/",
	}}
	return tmp, nil
}

type Error struct {
	Code      string
	Message   string
	Resource  string
	RequestId string
}

func buildError(code, message, resource string) interface{} {
	return struct {
		Error
		XMLName struct{} `xml:"Error"`
	}{Error: Error{
		Code:     code,
		Message:  message,
		Resource: resource,
	}}
}

type S3Layer struct {
	ListBucketFunc func(bucket, prefix string) ([]*ListBucketResultContent, []*ListBucketResultPrefix, error)
	GetObjectFunc  func(bucket, key string) (io.Reader, error)
	PutObjectFunc  func(bucket, key string, reader io.Reader) error
	CredFunc       func(accessKey string) (string, error)
}

func (sl *S3Layer) Handler() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("Authorization: %+v\n", r.Header.Get("Authorization"))
		fmt.Printf("headers: %v/%+v\n", r.Host, r.Header)

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
			w.WriteHeader(403)
			writeXML(w, buildError("SignatureDoesNotMatch", "Signature does not match", path))
			return
		}

		// Bucket handler
		if path == "/" {
			switch r.Method {
			case "GET":
				// List objects, the only delimiter supported is "/"
				content, prefixes, err := sl.ListBucketFunc(bucket, r.URL.Query().Get("prefix"))
				response, err := buildListBucketResult(bucket, content, prefixes)
				if err != nil {
					panic(err)
				}
				writeXML(w, response)
				return
			default:
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
		}

		// Object handler
		switch r.Method {
		case "GET", "HEAD":
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
		case "PUT":
			// FIXME(tsileo): support ACL
			// Create an object from the request body
			w.Header().Set("ETag", fmt.Sprintf("%x", md5.Sum(data)))
			if err := sl.PutObjectFunc(bucket, path[1:], bytes.NewReader(data)); err != nil {
				panic(err)
			}
			return
		// TODO(tsileo): support DELETE
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	}
}
