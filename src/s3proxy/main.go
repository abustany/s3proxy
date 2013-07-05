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
	"strings"
	"time"
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s CONFIG_FILE\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "HTTP proxy that authenticates S3 requests\n")
}

type ProxyHandler struct {
	config *Config
	client *http.Client
}

func (h *ProxyHandler) SignRequest(r *http.Request) {
	// See http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html#ConstructingTheAuthenticationHeader
	const AwsDomain = "s3.amazonaws.com"

	if !strings.HasSuffix(r.Host, AwsDomain) {
		return
	}

	var bucketName string
	// Whether the URL was using bucket.s3.amazonaws.com instead of s3.amazonaws.com/bucket/
	var bucketVirtualHost = false

	if len(r.Host) > len(AwsDomain) {
		bucketName = r.Host[0 : len(r.Host)-len(AwsDomain)-1]
		bucketVirtualHost = true
	} else {
		tokens := strings.Split(r.URL.RequestURI(), "/")

		if len(tokens) > 0 {
			bucketName = tokens[0]
		}
	}

	bucketConfig, bucketExists := h.config.Buckets[bucketName]

	if !bucketExists {
		return
	}

	dateStr := time.Now().UTC().Format(time.RFC1123Z)
	r.Header.Set("Date", dateStr)

	canonicalizedResource := bytes.NewBuffer(nil)

	if bucketVirtualHost {
		canonicalizedResource.WriteString("/" + bucketName)
	}

	canonicalizedResource.WriteString(r.URL.Path)

	canonicalizedAmzHeaders := bytes.NewBuffer(nil)

	for k, vs := range r.Header {
		k = strings.ToLower(k)

		if !strings.HasPrefix(k, "x-amz-") {
			continue
		}

		canonicalizedAmzHeaders.WriteString(k)
		canonicalizedAmzHeaders.WriteString(":")
		canonicalizedAmzHeaders.WriteString(strings.Join(vs, ","))
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

	signature := hmac.New(sha1.New, ([]byte)(bucketConfig.SecretAccessKey))
	signature.Write(buf.Bytes())

	signature64 := bytes.NewBuffer(nil)

	b64encoder := base64.NewEncoder(base64.StdEncoding, signature64)
	b64encoder.Write(signature.Sum(nil))
	b64encoder.Close()

	r.Header.Set("Authorization", fmt.Sprintf("AWS %s:%s", bucketConfig.AccessKeyId, signature64.String()))
}

func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	r.URL.Scheme = "http"
	r.URL.Host = r.Host
	r.RequestURI = ""

	h.SignRequest(r)

	response, err := h.client.Do(r)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error while serving the request: %s\n\nGreetings, the S3Proxy\n", err)
		return
	}

	defer response.Body.Close()

	for k, vs := range response.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}

	w.WriteHeader(response.StatusCode)
	io.Copy(w, response.Body)
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

	handler := &ProxyHandler{
		config,
		&http.Client{},
	}

	listenAddress := fmt.Sprintf("%s:%d", config.Server.Address, config.Server.Port)
	http.ListenAndServe(listenAddress, handler)
}
