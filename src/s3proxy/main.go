package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
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

const S3ProxyMetadataHeader = "X-Amz-Meta-S3proxy"
const S3ProxyMetadataVersion = byte(0x00)

func (h *ProxyHandler) GetBucketSecurityCredentials(c *BucketConfig) (*Credentials, error) {
	if c.AccessKeyId != "" {
		return &Credentials{
			AccessKeyId:     c.AccessKeyId,
			SecretAccessKey: c.SecretAccessKey,
		}, nil
	}

	return h.credentialCache.GetRoleCredentials()
}

var AwsDomain = "s3.amazonaws.com"

func (h *ProxyHandler) GetBucketInfo(r *http.Request) *BucketInfo {
	var portIdx = strings.IndexRune(r.Host, ':')

	if portIdx == -1 {
		portIdx = len(r.Host)
	}

	host := r.Host[0:portIdx]

	if !strings.HasSuffix(host, AwsDomain) {
		return nil
	}

	var bucketName string
	// Whether the URL was using bucket.s3.amazonaws.com instead of s3.amazonaws.com/bucket/
	var bucketVirtualHost = false

	if len(host) > len(AwsDomain) {
		bucketName = host[0 : len(host)-len(AwsDomain)-1]
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

func (h *ProxyHandler) PreRequestEncryptionHook(r *http.Request, innerRequest *http.Request, info *BucketInfo) (*CountingHash, error) {
	if info == nil || info.Config == nil || info.Config.EncryptionKey == "" || r.Method != "PUT" {
		return nil, nil
	}

	// If this is a "copy" PUT, we should send no body at all
	for k, _ := range r.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-amz-copy-source") {
			return nil, nil
		}
	}

	encryptedInput, extralen, err := SetupWriteEncryption(r.Body, info)

	if err != nil {
		return nil, err
	}

	// Since encryption transforms the data, after the inner request succeeds,
	// we'll match the MD5s of the transformed data, and mangle the etag in the
	// response we send to the client with the MD5 of the untransformed data if
	// they match.
	innerBodyHash := NewCountingHash(md5.New())
	teereader := io.TeeReader(encryptedInput, innerBodyHash)
	innerRequest.Body = ioutil.NopCloser(teereader)

	if length := innerRequest.ContentLength; length != -1 {
		innerRequest.ContentLength += extralen
		innerRequest.Header.Set("Content-Length", strconv.FormatInt(innerRequest.ContentLength, 10))
	}

	InfoLogger.Print("Encrypting the request")

	return innerBodyHash, nil
}

func (h *ProxyHandler) PostRequestEncryptionHook(r *http.Request, innerResponse *http.Response, info *BucketInfo) (io.ReadCloser, error) {
	if info == nil || info.Config == nil || info.Config.EncryptionKey == "" {
		return innerResponse.Body, nil
	}

	if r.Method != "GET" && r.Method != "HEAD" {
		return innerResponse.Body, nil
	}

	// When listing folders, the returned data is not going to be encrypted
	if strings.HasSuffix(r.URL.Path, "/") {
		InfoLogger.Print("Directory listing request, skipping decryption")
		return innerResponse.Body, nil
	}

	InfoLogger.Print("Decrypting the response")

	// If we had cached encrypted metadata, decrypt it and return it to the client
	if encryptedMetadata := innerResponse.Header.Get(S3ProxyMetadataHeader); encryptedMetadata != "" {
		var metadataBytes []byte
		_, err := fmt.Sscanf(encryptedMetadata, "%x", &metadataBytes)

		if err != nil {
			return nil, err
		}

		decReader, _, err := SetupReadEncryption(bytes.NewReader(metadataBytes), info)

		if err != nil {
			return nil, err
		}

		metadata, err := UnserializeObjectMetadata(decReader)

		if err != nil {
			return nil, err
		}

		delete(innerResponse.Header, S3ProxyMetadataHeader)
		innerResponse.Header.Set("Etag", metadata.Etag)
		innerResponse.Header.Set("Content-Length", fmt.Sprintf("%d", metadata.Size))

		InfoLogger.Printf("Overwrote the response headers with the cached version (Etag: %s, Content-Length: %d)", metadata.Etag, metadata.Size)
	}

	if r.Method == "HEAD" {
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

	signatureHdr := fmt.Sprintf("AWS %s:%s", credentials.AccessKeyId, signature64.String())

	r.Header.Set("Authorization", signatureHdr)

	InfoLogger.Printf("Signed request (signature: %s )", signatureHdr)

	return nil
}

func failRequest(w http.ResponseWriter, format string, args ...interface{}) {
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprintf(w, format, args...)
	ErrorLogger.Printf(format, args...)
}

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	InfoLogger.Printf("%s %s (Host: %s)", r.Method, r.URL, r.Host)

	info := h.GetBucketInfo(r)

	if info == nil {
		InfoLogger.Print("Not an S3 request")
	} else {
		if info.Config == nil {
			InfoLogger.Printf("No configuration for S3 bucket %s", info.Name)
		} else {
			InfoLogger.Printf("Handling request for bucket %s", info.Name)
		}
	}

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

	var originalBodyHash *CountingHash

	dataCheckNeeded := r.Method == "PUT" && info != nil

	if dataCheckNeeded {
		originalBodyHash = NewCountingHash(md5.New())

		teereader := io.TeeReader(r.Body, originalBodyHash)
		r.Body = ioutil.NopCloser(teereader)
	}

	err := h.SignRequest(innerRequest, info)

	if err != nil {
		failRequest(w, "Error while signing the request: %s\n\nGreetings, the S3Proxy\n", err)
		return
	}

	innerBodyHash, err := h.PreRequestEncryptionHook(r, innerRequest, info)

	if err != nil {
		failRequest(w, "Error while setting up encryption: %s\n\nGreetings, the S3Proxy\n", err)
		return
	}

	innerResponse, err := h.client.Do(innerRequest)

	if err != nil {
		failRequest(w, "Error while serving the request: %s\n\nGreetings, the S3Proxy\n", err)
		return
	}

	defer innerResponse.Body.Close()

	if dataCheckNeeded {
		awsEtag := innerResponse.Header.Get("Etag")

		bodyHash := innerBodyHash

		if bodyHash == nil {
			bodyHash = originalBodyHash
		}

		innerEtag := fmt.Sprintf("\"%.0x\"", bodyHash.Sum(nil))
		originalEtag := fmt.Sprintf("\"%.0x\"", originalBodyHash.Sum(nil))

		// if the Etags don't match, we can leave whatever value there
		if innerEtag == awsEtag {
			innerResponse.Header["Etag"] = []string{originalEtag}
		}

		// Let's also store the original metadata in S3, so we can use it later
		// for HEAD and GET requests (if we uploaded any data). We encrypt the
		// metadata too.
		if innerBodyHash != nil {
			metadata := &ObjectMetadata{
				originalBodyHash.Count(),
				originalEtag,
			}

			err = h.UpdateObjectMetadata(innerRequest.URL, metadata, r.Header, info)

			if err != nil {
				failRequest(w, "Error while updating metadata: %s\n\nGreetings, the S3Proxy\n", err)
				return
			}
		}
	}

	responseReader, err := h.PostRequestEncryptionHook(r, innerResponse, info)

	if err != nil {
		failRequest(w, "Error while setting up decryption: %s\n\nGreetings, the S3Proxy\n", err)
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
	transport := &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		DisableKeepAlives: config.Server.DisableKeepAlives,
	}

	return &ProxyHandler{
		config,
		&http.Client{
			Transport: transport,
		},
		NewCredentialCache(),
	}
}

func main() {
	var debugMode = flag.Bool("debug", false, "Enable debug messages")

	flag.Parse()

	if len(flag.Args()) != 1 {
		usage()
		os.Exit(1)
	}

	if *debugMode {
		enableDebugMode(*debugMode)
		InfoLogger.Print("Enabling debug messages")
	}

	config, err := parseConfig(flag.Args()[0])

	if err != nil {
		ErrorLogger.Printf("Error while parsing the configuration file: %s\n", err)
		os.Exit(1)
	}

	handler := NewProxyHandler(config)

	listenAddress := fmt.Sprintf("%s:%d", config.Server.Address, config.Server.Port)
	http.ListenAndServe(listenAddress, handler)
}
