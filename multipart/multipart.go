/*

Package multipart implements a basic multipart upload handler for S3Layer.

It saves each parts in a seperate file, and once completed, it can read from each parts transparently and
delete it once it's read.

*/
package multipart

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"

	"github.com/tsileo/s3layer"
)

// TODO(tsileo): a file func for computing the path

var (
	ErrUploadIncomplete = errors.New("Upload must be completed first")
	ErrUploadNotFound   = errors.New("Upload ID does not exist")
)

type ByPartNumber []*s3layer.UploadPart

func (p ByPartNumber) Len() int           { return len(p) }
func (p ByPartNumber) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p ByPartNumber) Less(i, j int) bool { return p[i].PartNumber < p[j].PartNumber }

type upload struct {
	Bucket   string
	Key      string
	UploadID string
	Parts    map[string]*s3layer.UploadPart
	ACL      s3layer.CannedACL

	path        string
	complete    bool
	offset      int64
	currentPart int
	eof         bool
	finalParts  []*s3layer.UploadPart
}

// New Initialize a new MultipartUploadHandler
func New(path string, completeFunc func(bucket, key string, reader io.Reader, acl s3layer.CannedACL) error) *MultipartUploadHandler {
	return &MultipartUploadHandler{
		root:         path,
		uploads:      map[string]*upload{},
		completeFunc: completeFunc,
	}
}

// MultipartUploadHandler implements S3LayerMultipartUploader
type MultipartUploadHandler struct {
	root         string
	uploads      map[string]*upload
	completeFunc func(bucket, key string, reader io.Reader, acl s3layer.CannedACL) error
}

func (muh *MultipartUploadHandler) MultipartInit(bucket, key, uploadID string, acl s3layer.CannedACL) error {
	u := &upload{
		path:     muh.root,
		Bucket:   bucket,
		Key:      key,
		UploadID: uploadID,
		ACL:      acl,
		Parts:    map[string]*s3layer.UploadPart{},
	}
	muh.uploads[u.UploadID] = u
	return os.MkdirAll(filepath.Join(muh.root, uploadID), 0755)
}

func (muh *MultipartUploadHandler) MultipartUpload(uploadID string, partNumber int, etag string, r io.Reader) error {
	upload, ok := muh.uploads[uploadID]
	if !ok {
		return s3layer.ErrBucketNotFound
	}
	upload.Parts[etag] = &s3layer.UploadPart{
		PartNumber: partNumber,
		ETag:       etag,
	}
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filepath.Join(upload.path, upload.UploadID, fmt.Sprintf("%04d_%s", partNumber, etag)), data, 0644)
}

func (muh *MultipartUploadHandler) MultipartComplete(uploadID string, parts []*s3layer.UploadPart) error {
	upload, ok := muh.uploads[uploadID]
	if !ok {
		return s3layer.ErrBucketNotFound
	}
	// Sort the part
	sort.Sort(ByPartNumber(parts))
	upload.finalParts = parts
	upload.complete = true
	return muh.completeFunc(upload.Bucket, upload.Key, upload, upload.ACL)
}

func (muh *MultipartUploadHandler) MultipartAbort(uploadID string) error {
	upload, ok := muh.uploads[uploadID]
	if !ok {
		return s3layer.ErrBucketNotFound
	}
	for _, part := range upload.Parts {
		partPath := filepath.Join(upload.path, upload.UploadID, fmt.Sprintf("%04d_%s", part.PartNumber, part.ETag))
		if err := os.Remove(partPath); err != nil {
			return err
		}
	}
	return os.RemoveAll(filepath.Join(upload.path, upload.UploadID))
}

// like a `net/http.Request`, you can only read it once, parts are removed once they've been read
func (upload *upload) Read(p []byte) (int, error) {
	// Check if we need to returns EOF
	if upload.eof {
		return 0, io.EOF
	}

	// Ensure the upload is "complete", i.e. if the parts are sorted
	if !upload.complete {
		return 0, ErrUploadIncomplete
	}

	// Keep a temp buffer for the whole read
	buf := []byte{}

	// Keep track of what we need to read
	total := len(p)
	needed := total
	read := 0

	// Iterate over the parts, starting from the last current part
	for _, part := range upload.finalParts[upload.currentPart:] {
		// Update the current part as we're iterating
		upload.currentPart = part.PartNumber

		// Keep a temp buffer for the read on the part
		tmp := make([]byte, needed)

		// Open tu current part
		partPath := filepath.Join(upload.path, upload.UploadID, fmt.Sprintf("%04d_%s", part.PartNumber, part.ETag))

		f, err := os.Open(partPath)
		if err != nil {
			return 0, err
		}
		defer f.Close()

		// Seek to where we stop last read
		if _, err := f.Seek(upload.offset, os.SEEK_SET); err != nil {
			return 0, err
		}

		// Try to read what we need
		n, err := f.Read(tmp)
		if err != nil {
			return 0, err
		}

		read += n

		// Append it to the final buffer
		buf = append(buf, tmp[0:n]...)

		// Update the offset for the next read
		upload.offset += int64(n)

		// Check if we got what we need
		if read == total {
			break
		}

		// Update the number of bytes left to read
		needed -= n

		// Remove the part since we've already read it
		f.Close()
		if err := os.Remove(partPath); err != nil {
			return 0, err
		}

		// If we are here, and it's the last part, then we need to returns EOF at next read
		// (it means we read until the end of the last part)
		if part.PartNumber == len(upload.Parts)-1 {
			upload.eof = true
		}

		// Reset the offset since we'll change file
		upload.offset = 0

	}

	// Actually copy our buffer to the supplied slice
	copy(p, buf[:])

	// Return the number of bytes read
	return read, nil
}
