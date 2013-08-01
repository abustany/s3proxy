package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s CONFIG_FILE\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "HTTP proxy that authenticates S3 requests\n")
}

type Credentials struct {
	AccessKeyId     string
	SecretAccessKey string
	Token           string
	Expiration      time.Time
}

type BucketInfo struct {
	Name        string
	VirtualHost bool
	Config      *BucketConfig
}

type ProxyHandler struct {
	config          *Config
	client          *http.Client
	credentialCache *CredentialCache
}

func (h *ProxyHandler) GetBucketSecurityCredentials(c *BucketConfig) (*Credentials, error) {
	if c.IAMRole == "" {
		return &Credentials{
			AccessKeyId:     c.AccessKeyId,
			SecretAccessKey: c.SecretAccessKey,
		}, nil
	}

	return h.credentialCache.GetRoleCredentials(c.IAMRole)
}

func (h *ProxyHandler) GetBucketInfo(r *http.Request) *BucketInfo {
	const AwsDomain = "s3.amazonaws.com"

	if !strings.HasSuffix(r.Host, AwsDomain) {
		return nil
	}

	var bucketName string
	// Whether the URL was using bucket.s3.amazonaws.com instead of s3.amazonaws.com/bucket/
	var bucketVirtualHost = false

	if len(r.Host) > len(AwsDomain) {
		bucketName = r.Host[0 : len(r.Host)-len(AwsDomain)-1]
		bucketVirtualHost = true
	} else {
		tokens := strings.Split(r.URL.Path, "/")

		// Split produces empty tokens which we are not interested in
		for _, t := range tokens {
			if t == "" {
				continue
			}

			bucketName = t
			break
		}
	}

	return &BucketInfo{
		Name:        bucketName,
		VirtualHost: bucketVirtualHost,
		Config:      h.config.Buckets[bucketName],
	}
}

func (h *ProxyHandler) PreRequestEncryptionHook(r *http.Request, innerRequest *http.Request, info *BucketInfo) error {
	if info == nil || info.Config == nil || info.Config.EncryptionKey == "" || r.Method != "PUT" {
		return nil
	}

	// If this is a "copy" PUT, we should send no body at all
	for k, _ := range r.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-amz-copy-source") {
			return nil
		}
	}

	encryptedInput, extralen, err := SetupWriteEncryption(r.Body, info)

	if err != nil {
		return err
	}

	innerRequest.Body = encryptedInput

	if length := innerRequest.ContentLength; length != -1 {
		innerRequest.ContentLength += extralen
		innerRequest.Header.Set("Content-Length", strconv.FormatInt(innerRequest.ContentLength, 10))
	}

	return nil
}

func (h *ProxyHandler) PostRequestEncryptionHook(r *http.Request, innerResponse *http.Response, info *BucketInfo) (io.ReadCloser, error) {
	if info == nil || info.Config == nil || info.Config.EncryptionKey == "" || r.Method != "GET" {
		return innerResponse.Body, nil
	}

	// When listing folders, the returned data is not going to be encrypted
	if strings.HasSuffix(r.URL.Path, "/") {
		return innerResponse.Body, nil
	}

	decryptedReader, minuslen, err := SetupReadEncryption(innerResponse.Body, info)

	if err != nil {
		return nil, err
	}

	if length := innerResponse.ContentLength; length != -1 {
		innerResponse.ContentLength -= minuslen
		innerResponse.Header.Set("Content-Length", strconv.FormatInt(innerResponse.ContentLength, 10))
	}

	return decryptedReader, nil
}

func (h *ProxyHandler) SignRequest(r *http.Request, info *BucketInfo) error {
	// See http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html#ConstructingTheAuthenticationHeader

	if info == nil || info.Config == nil {
		return nil
	}
	credentials, err := h.GetBucketSecurityCredentials(info.Config)

	if err != nil {
		return err
	}

	dateStr := r.Header.Get("Date")

	if dateStr == "" && r.Header.Get("x-amz-date") == "" {
		dateStr = time.Now().UTC().Format(time.RFC1123Z)
		r.Header.Set("Date", dateStr)
	}

	if credentials.Token != "" {
		r.Header.Add("x-amz-security-token", credentials.Token)
	}

	canonicalizedResource := bytes.NewBuffer(nil)

	if info.VirtualHost {
		canonicalizedResource.WriteString("/" + info.Name)
	}

	canonicalizedResource.WriteString(r.URL.Path)

	canonicalizedAmzHeaders := bytes.NewBuffer(nil)

	amzHeaders := []string{}

	for k, _ := range r.Header {
		if !strings.HasPrefix(strings.ToLower(k), "x-amz-") {
			continue
		}

		amzHeaders = append(amzHeaders, k)
	}

	sort.Strings(amzHeaders)

	for _, k := range amzHeaders {
		canonicalizedAmzHeaders.WriteString(strings.ToLower(k))
		canonicalizedAmzHeaders.WriteString(":")
		canonicalizedAmzHeaders.WriteString(strings.Join(r.Header[k], ","))
		canonicalizedAmzHeaders.WriteString("\n")
	}

	buf := bytes.NewBuffer(nil)

	buf.WriteString(r.Method)
	buf.WriteString("\n")

	buf.WriteString(r.Header.Get("Content-MD5"))
	buf.WriteString("\n")

	buf.WriteString(r.Header.Get("Content-Type"))
	buf.WriteString("\n")

	buf.WriteString(dateStr)
	buf.WriteString("\n")

	buf.WriteString(canonicalizedAmzHeaders.String())
	buf.WriteString(canonicalizedResource.String())

	signature := hmac.New(sha1.New, ([]byte)(credentials.SecretAccessKey))
	signature.Write(buf.Bytes())

	signature64 := bytes.NewBuffer(nil)

	b64encoder := base64.NewEncoder(base64.StdEncoding, signature64)
	b64encoder.Write(signature.Sum(nil))
	b64encoder.Close()

	r.Header.Set("Authorization", fmt.Sprintf("AWS %s:%s", credentials.AccessKeyId, signature64.String()))

	return nil
}

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	info := h.GetBucketInfo(r)

	innerRequest := &http.Request{
		Method:           r.Method,
		URL:              r.URL,
		Proto:            r.Proto,
		ProtoMajor:       r.ProtoMajor,
		ProtoMinor:       r.ProtoMinor,
		Header:           r.Header,
		Body:             r.Body,
		ContentLength:    r.ContentLength,
		TransferEncoding: r.TransferEncoding,
		Close:            r.Close,
		Host:             r.Host,
		Form:             r.Form,
		PostForm:         r.PostForm,
		MultipartForm:    r.MultipartForm,
		Trailer:          r.Trailer,
	}

	innerRequest.URL.Scheme = "http"
	innerRequest.URL.Host = r.Host

	err := h.SignRequest(innerRequest, info)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error while signing the request: %s\n\nGreetings, the S3Proxy\n", err)
		return
	}

	err = h.PreRequestEncryptionHook(r, innerRequest, info)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error while setting up encryption: %s\n\nGreetings, the S3Proxy\n", err)
		return
	}

	innerResponse, err := h.client.Do(innerRequest)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error while serving the request: %s\n\nGreetings, the S3Proxy\n", err)
		return
	}

	defer innerResponse.Body.Close()

	responseReader, err := h.PostRequestEncryptionHook(r, innerResponse, info)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error while setting up decryption: %s\n\nGreetings, the S3Proxy\n", err)
		return
	}

	for k, vs := range innerResponse.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}

	w.WriteHeader(innerResponse.StatusCode)
	io.Copy(w, responseReader)
}

func NewProxyHandler(config *Config) *ProxyHandler {
	return &ProxyHandler{
		config,
		&http.Client{},
		NewCredentialCache(),
	}
}

func main() {
	flag.Parse()

	if len(flag.Args()) != 1 {
		usage()
		os.Exit(1)
	}

	config, err := parseConfig(flag.Args()[0])

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error while parsing the configuration file: %s\n", err)
		os.Exit(1)
	}

	handler := NewProxyHandler(config)

	listenAddress := fmt.Sprintf("%s:%d", config.Server.Address, config.Server.Port)
	http.ListenAndServe(listenAddress, handler)
}
