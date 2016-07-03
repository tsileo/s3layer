package s3layer

import (
	"bytes"
	"crypto/md5"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"time"

	"github.com/gorilla/mux"
)

const S3Date = "2006-01-02T15:04:05.007Z"

var S3FakeStorageClass = "STANDARD"

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

func buildListBucketResult(name string, contents []*ListBucketResultContent, prefixes []*ListBucketResultPrefix) (string, error) {
	tmp := struct {
		ListBucketResult
		XMLName struct{} `xml:"ListBucketResult"`
	}{ListBucketResult: ListBucketResult{
		Name:           name,
		Contents:       contents,
		CommonPrefixes: prefixes,
		Xmlns:          "http://s3.amazonaws.com/doc/2006-03-01/",
	}}

	byteXML, err := xml.MarshalIndent(tmp, "", `   `)
	if err != nil {
		panic(err)
	}
	response := xml.Header + string(byteXML)
	return response, nil
}

type S3Layer struct {
	ListBucketFunc func(bucket, prefix string) ([]*ListBucketResultContent, []*ListBucketResultPrefix, error)
	GetObjectFunc  func(bucket, key string) (io.Reader, error)
	PutObjectFunc  func(bucket, key string, reader io.Reader) error
}

func (sl *S3Layer) Handler() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		bucket := vars["bucket"]
		path := "/" + vars["path"]

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
				w.Write([]byte(response))
				return
			default:
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
		}

		// Object handler
		switch r.Method {
		case "GET":
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
			http.ServeContent(w, r, filepath.Base(path), time.Now(), bytes.NewReader(data))
			return
		case "PUT":
			// Create an object from the request body
			data, err := ioutil.ReadAll(r.Body)
			if err != nil {
				panic(err)
			}
			w.Header().Set("ETag", fmt.Sprintf("%x", md5.Sum(data)))
			if err := sl.PutObjectFunc(bucket, path[1:], bytes.NewReader(data)); err != nil {
				panic(err)
			}
			return
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	}
}
