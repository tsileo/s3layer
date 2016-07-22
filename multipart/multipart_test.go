package multipart

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"testing"

	"github.com/tsileo/s3layer"
)

func TestMultipartReader(t *testing.T) {
	dir, err := ioutil.TempDir("", "s3layer_multipart")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	var h2 string
	completeFunc := func(bucket, key string, reader io.Reader, acl s3layer.CannedACL) error {
		rebuilded, err := ioutil.ReadAll(reader)
		if err != nil {
			panic(err)
		}
		h2 = fmt.Sprintf("%x", md5.Sum(rebuilded))
		return nil
	}

	muh := New(dir, completeFunc)
	bucket := "bucket"
	key := "key"
	uploadID := "uploadID"

	if err := muh.MultipartInit(bucket, key, uploadID, s3layer.Private); err != nil {
		panic(err)
	}

	data := make([]byte, 5000000)
	if _, err := rand.Read(data); err != nil {
		panic(err)
	}

	h := fmt.Sprintf("%x", md5.Sum(data))
	t.Logf("input hash %s\n", h)

	parts := []*s3layer.UploadPart{}
	// l := 0
	// rebuilded := []byte{}
	for i := 0; i < 5; i++ {
		c := data[i*1*1000000 : (i+1)*1000000]
		cHash := fmt.Sprintf("%x", md5.Sum(c))

		parts = append(parts, &s3layer.UploadPart{
			ETag:       cHash,
			PartNumber: i,
		})
		if err := muh.MultipartUpload(uploadID, i, cHash, bytes.NewReader(c)); err != nil {
			panic(err)
		}
		// l += len(c)
		// rebuilded = append(rebuilded, c...)
	}
	// t.Logf("l=%d", l)

	if err := muh.MultipartComplete(uploadID, parts); err != nil {
		panic(err)
	}
	t.Logf("output hash %s\n", h2)
	if h != h2 {
		t.Fatalf("hash mismatch \"%s\" != \"%s\"", h, h2)
	}

}
