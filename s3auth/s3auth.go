package s3auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	alg   = "AWS4-HMAC-SHA256"
	algV2 = "AWS"
)

var (
	ErrInvalidRequest = errors.New("InvalidRequest")
)

// TODO(tsileo): Support a debug mode a la s3cmd
// XXX(tsileo): RequestTimeTooSkewed if now - (Date | X-Amz-Date) > 15min

func ParseAuth(credFunc func(accessKey string) (string, error), auth, payload string, r *http.Request) error {
	switch {
	case strings.HasPrefix(auth, alg):
		return ParseAuthV4(credFunc, auth, payload, r)
	case strings.HasPrefix(auth, algV2):
		return ParseAuthV2(credFunc, auth, payload, r)
	default:
		return ErrInvalidRequest
	}
}

type cred struct {
	accessKey string
	date      time.Time
	region    string
	service   string
	request   string
}

//  <HTTPMethod>\n
//  <CanonicalURI>\n
//  <CanonicalQueryString>\n
//  <CanonicalHeaders>\n
//  <SignedHeaders>\n
//  <HashedPayload>
func canonicalRequest(signedHeaders []string, payload string, r *http.Request) string {
	rawQuery := strings.Replace(r.URL.Query().Encode(), "+", "%20", -1)
	encodedPath := (&url.URL{Path: r.URL.Path}).String()
	// Convert any space strings back to "+".
	encodedPath = strings.Replace(encodedPath, "+", "%20", -1)
	var canonicalsHeadersBuffer bytes.Buffer
	headers := []string{}
	sort.Strings(signedHeaders)
	for _, header := range signedHeaders {
		lheader := strings.ToLower(header)
		headers = append(headers, lheader)
		canonicalsHeadersBuffer.WriteString(lheader)
		canonicalsHeadersBuffer.WriteByte(':')
		if lheader == "host" {
			canonicalsHeadersBuffer.WriteString(r.Host)
		} else {
			canonicalsHeadersBuffer.WriteString(r.Header.Get(lheader))
		}
		canonicalsHeadersBuffer.WriteByte('\n')
	}
	sort.Strings(headers)
	canonicalRequest := strings.Join([]string{
		r.Method,
		encodedPath,
		rawQuery,
		canonicalsHeadersBuffer.String(),
		strings.Join(headers, ";"),
		payload,
	}, "\n")
	return canonicalRequest
}

func ParseAuthV4(credFunc func(accessKey string) (string, error), auth, payload string, r *http.Request) error {
	auth = strings.Replace(auth, " ", "", -1)

	// Ensure the header is not empty
	if auth == "" {
		return fmt.Errorf("empty authorization")
	}

	// Enspure its signature v4
	if !strings.HasPrefix(auth, alg) {
		return fmt.Errorf("bad alg")
	}

	// Remove the alg fron the auth string
	auth = strings.TrimPrefix(auth, alg)

	fields := strings.Split(auth, ",")
	if len(fields) != 3 {
		return fmt.Errorf("invalid number of fields")
	}

	// Parse credentials
	creds := strings.Split(strings.TrimSpace(fields[0]), "=")
	if len(creds) != 2 || creds[0] != "Credential" {
		return fmt.Errorf("invalid cred")
	}
	credParts := strings.Split(strings.TrimSpace(creds[1]), "/")
	if len(credParts) != 5 {
		return fmt.Errorf("invalid number of cred parts")
	}
	cred := &cred{
		accessKey: credParts[0],
		region:    credParts[2],
		service:   credParts[3],
		request:   credParts[4],
	}
	date, err := time.Parse("20060102", credParts[1])
	if err != nil {
		return err
	}
	cred.date = date
	fmt.Printf("cred=%+v\n", cred)

	secretKey, err := credFunc(cred.accessKey)
	if err != nil {
		return err
	}

	// Parse signed headers
	rawSignedHeaders := strings.Split(strings.TrimSpace(fields[1]), "=")
	if len(rawSignedHeaders) != 2 || rawSignedHeaders[0] != "SignedHeaders" {
		return fmt.Errorf("invalid signed headers")
	}
	signedHeaders := strings.Split(rawSignedHeaders[1], ";")
	fmt.Printf("headers=%+v\n", signedHeaders)

	// Parse signature
	rawSignature := strings.Split(strings.TrimSpace(fields[2]), "=")
	if len(rawSignature) != 2 || rawSignature[0] != "Signature" {
		return fmt.Errorf("invalid signature")
	}

	signature := rawSignature[1]
	fmt.Printf("signature=%v\n", signature)

	canonicalReq := canonicalRequest(signedHeaders, payload, r)
	dateHeader, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	if err != nil {
		panic(err)
	}

	stringToSign := alg + "\n" + r.Header.Get("X-Amz-Date") + "\n"
	stringToSign = stringToSign + scope(dateHeader, cred.region) + "\n"
	canonicalRequestBytes := sha256.Sum256([]byte(canonicalReq))
	stringToSign = stringToSign + hex.EncodeToString(canonicalRequestBytes[:])

	hdate := makeHMAC([]byte("AWS4"+secretKey), []byte(dateHeader.Format("20060102")))
	regionBytes := makeHMAC(hdate, []byte(cred.region))
	service := makeHMAC(regionBytes, []byte("s3"))
	signingKey := makeHMAC(service, []byte("aws4_request"))

	computedSig := hex.EncodeToString(makeHMAC(signingKey, []byte(stringToSign)))
	if computedSig != signature {
		return fmt.Errorf("invalid sig")
	}
	return nil
}

func makeHMAC(key []byte, data []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}

func scope(t time.Time, region string) string {
	scope := strings.Join([]string{
		t.Format("20060102"),
		region,
		"s3",
		"aws4_request",
	}, "/")
	return scope
}

func canonicalizedHeaders(r *http.Request) string {
	headers := []string{}
	for k, _ := range r.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-amz-") {
			headers = append(headers, strings.ToLower(k))
		}
	}
	sort.Strings(headers)
	res := ""
	for _, header := range headers {
		res += header + ":" + r.Header.Get(header) + "\n"
	}
	return res[:len(res)-1]
}

func ParseAuthV2(credFunc func(accessKey string) (string, error), auth, payload string, r *http.Request) error {
	auth = strings.Replace(auth, " ", "", -1)

	// Ensure the header is not empty
	if auth == "" {
		return fmt.Errorf("empty authorization")
	}

	// Enspure its signature v4
	if !strings.HasPrefix(auth, algV2) {
		return fmt.Errorf("bad alg")
	}

	// Remove the alg fron the auth string
	auth = strings.TrimPrefix(auth, algV2)

	fields := strings.Split(auth, ":")
	if len(fields) != 2 {
		return fmt.Errorf("invalid number of fields")
	}

	accessKey := fields[0]
	signature := fields[1]

	secretKey, err := credFunc(accessKey)
	if err != nil {
		return err
	}

	dateHeader := r.Header.Get("Date")
	// XXX(tsileo): AWS doc say the X-Amz-Date should take precedence over the Date header,
	// but s3cmd auth v2 implementation, only check the "Date" header, so I stick with that
	// for compatibility with it.
	// amzDate := r.Header.Get("X-Amz-Date")
	// if amzDate != "" {
	// 	return amzDate
	// }
	// return r.Header.Get("Date")

	// StringToSign (AWS v2) =
	// HTTP-Verb + "\n" +
	// Content-MD5 + "\n" +
	// Content-Type + "\n" +
	// Date + "\n" +
	// CanonicalizedAmzHeaders +
	// CanonicalizedResource;
	// fmt.Printf("a=\"%s\"/s=\"%s\"\n", accessKey, secretKey)
	strToSign := r.Method + "\n" + r.Header.Get("Content-MD5")
	strToSign += "\n" + r.Header.Get("Content-Type") + "\n"
	strToSign += dateHeader + "\n" + canonicalizedHeaders(r) + "\n" + r.URL.Path
	// fmt.Printf("strToSign=\"%+v\" (%d)\n", strToSign, len(strToSign))
	// hashed := makeHMAC([]byte(secretKey), []byte(strToSign))

	// XXX(tsileo): HMAC SHA1 to stay compatible with s3cmd
	hash := hmac.New(sha1.New, []byte(secretKey))
	hash.Write([]byte(strToSign))
	hashed := hash.Sum(nil)

	computedSig := base64.StdEncoding.EncodeToString(hashed)

	// fmt.Printf("computed sig=\"%v\"|\"%v\" / %v\n", computedSig, signature)

	if computedSig != signature {
		return fmt.Errorf("invalid sig")
	}

	return nil
}
