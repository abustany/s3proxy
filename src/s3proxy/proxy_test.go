package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var testConfig = &Config{
	&ServerConfig{},
	map[string]*BucketConfig{
		"testbucket": {
			"AccessKey",
			"SecretKey",
			"",
			0,
			0,
		},
		"testbucket2": {
			"AccessKey",
			"SecretKey2",
			"",
			1,
			0,
		},
		"testbucket3": {
			"",
			"",
			"",
			1,
			0,
		},
		"testbucket4": {
			"AccessKey",
			"SecretKey2",
			"",
			1,
			300,
		},
	},
}

type IAMServer struct {
	Port         int
	RequestCount int32
	Creds        map[string]*Credentials
	l            net.Listener
}

// Fails one out of two requests
type FailingServer struct {
	Port         int
	RequestCount int32
	l            net.Listener
}

func GetListeningAddress() (net.Listener, int) {
	var l net.Listener

	addr := &net.TCPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 0, // random port
	}

	l, err := net.ListenTCP("tcp", addr)

	if err != nil {
		panic(fmt.Sprintf("Could not start TCP listener: %s", err))
	}

	tcpaddr, err := net.ResolveTCPAddr("tcp", l.Addr().String())

	if err != nil {
		panic(fmt.Sprintf("Could not parse TCP address: %s", err))
	}

	return l, tcpaddr.Port
}

func NewIAMServer() *IAMServer {
	listener, port := GetListeningAddress()

	server := &IAMServer{
		port,
		0,
		make(map[string]*Credentials),
		listener,
	}

	go http.Serve(listener, server)

	// There is no way to ensure the HTTP server properly started :/
	time.Sleep(50 * time.Millisecond)

	return server
}

func (s *IAMServer) Close() {
	s.l.Close()
}

func (s *IAMServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var pathPrefix = "/latest/meta-data/iam/security-credentials/"

	if !strings.HasPrefix(r.URL.Path, pathPrefix) {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	roleName := r.URL.Path[len(pathPrefix):]

	// Discovery request
	if roleName == "" {
		role := "testrole"
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(role))
		return
	}

	creds := s.Creds[roleName]

	if creds == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Needs to be atomic since each request is served in a separate goroutine
	atomic.AddInt32(&s.RequestCount, 1)

	payload := struct {
		Code            string
		LastUpdated     string
		Type            string
		AccessKeyId     string
		SecretAccessKey string
		Token           string
		Expiration      string
	}{
		"Success",
		"2013-07-05T12:32:43Z",
		"AWS-HMAC",
		creds.AccessKeyId,
		creds.SecretAccessKey,
		creds.Token,
		creds.Expiration.Format(time.RFC3339),
	}

	jsondata, _ := json.Marshal(payload)

	w.Write(jsondata)
}

func NewFailingServer() *FailingServer {
	listener, port := GetListeningAddress()

	server := &FailingServer{
		port,
		0,
		listener,
	}

	go http.Serve(listener, server)

	// There is no way to ensure the HTTP server properly started :/
	time.Sleep(50 * time.Millisecond)

	return server
}

func (s *FailingServer) Close() {
	s.l.Close()
}

func (s *FailingServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt32(&s.RequestCount, 1)

	if strings.HasSuffix(r.URL.Path, "/failtcp") {
		hijacker, ok := w.(http.Hijacker)

		if !ok {
			panic("ResponseWriter is not a Hijacker")
		}

		conn, _, _ := hijacker.Hijack()

		conn.Close()
	} else if strings.HasSuffix(r.URL.Path, "/failhttp") {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("HTTP error"))
	} else if strings.HasSuffix(r.URL.Path, "/notfound") {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("HTTP not found"))
	} else {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("HTTP OK"))
	}
}

func compareCreds(t *testing.T, creds *Credentials, expected *Credentials) bool {
	if creds == nil && expected != nil {
		t.Errorf("Unexpected nil credentials")
		return false
	}

	if creds != nil && expected == nil {
		t.Errorf("Unexpected non-nil credentials")
		return false
	}

	if creds == nil {
		return true
	}

	if creds.AccessKeyId != expected.AccessKeyId {
		t.Errorf("Invalid access key ID: expected '%s', got '%s'", expected.AccessKeyId, creds.AccessKeyId)
		return false
	}

	if creds.SecretAccessKey != expected.SecretAccessKey {
		t.Errorf("Invalid secret access key: expected '%s', got '%s'", expected.SecretAccessKey, creds.SecretAccessKey)
		return false
	}

	if creds.Token != expected.Token {
		t.Errorf("Invalid token: expected '%s', got '%s'", expected.Token, creds.Token)
		return false
	}

	exp1 := creds.Expiration.Format(time.RFC3339)
	exp2 := expected.Expiration.Format(time.RFC3339)

	if exp1 != exp2 {
		t.Errorf("Invalid expiration: expected '%s', got '%s'", exp1, exp2)
		return false
	}

	return true
}

func SetupFakeIAMServer() *IAMServer {
	server := NewIAMServer()

	// Overrides definition in credentialcache.go
	AmzIAMEndpoint = fmt.Sprintf("http://127.0.0.1:%d/latest/meta-data/iam/security-credentials/", server.Port)

	testRoleCreds := &Credentials{
		"AccessKey",
		"SecretKey",
		"SecretToken",
		time.Now().Add(1 * time.Hour),
	}

	server.Creds["testrole"] = testRoleCreds

	return server
}

func TestRoles(t *testing.T) {
	server := SetupFakeIAMServer()
	defer server.Close()

	testData := []struct {
		Name       string
		Role       string
		Creds      *Credentials
		Expiration time.Time
		Cached     bool
	}{
		{
			"First request for an IAM role token (uncached)",
			"testrole",
			server.Creds["testrole"],
			time.Now().Add(1 * time.Hour),
			false,
		},
		{
			"Request for a not-expired-yet IAM role token",
			"testrole",
			server.Creds["testrole"],
			time.Now().Add(1 * time.Hour),
			true,
		},
		{
			"Request for an expired IAM role token",
			"testrole",
			server.Creds["testrole"],
			time.Now().Add(1 * time.Hour),
			true,
		},
	}

	c := NewCredentialCache()

	for _, d := range testData {
		currentCount := server.RequestCount

		if c := server.Creds[d.Role]; c != nil {
			c.Expiration = d.Expiration
		}

		creds, err := c.GetRoleCredentials()

		if d.Creds != nil && err != nil {
			t.Errorf("Unexpected error while fetching role for case '%s': %s", d.Name, err)
			continue
		}

		if !compareCreds(t, creds, d.Creds) {
			continue
		}

		if creds == nil {
			continue
		}

		hasBeenCached := server.RequestCount == currentCount

		if d.Cached != hasBeenCached {
			t.Errorf("Unexpected caching behaviour for case '%s' (has been cached: %v / should have been cached: %v)", d.Name, hasBeenCached, d.Cached)
			continue
		}
	}
}

func TestSignature(t *testing.T) {
	server := SetupFakeIAMServer()
	defer server.Close()

	h := NewProxyHandler(testConfig)

	// The signatures for those were generated with s3cmd
	testData := []struct {
		Name      string
		Host      string
		Path      string
		Signature string
	}{
		{
			"Configured bucket using virtual host",
			"testbucket.s3.amazonaws.com",
			"/folder/file",
			"RpgjresZ/ancNZM3iABqOSLeTnE=",
		},
		{
			"Configured bucket with no virtual host",
			"s3.amazonaws.com",
			"/testbucket/folder/file",
			"RpgjresZ/ancNZM3iABqOSLeTnE=",
		},
		{
			"Other configured bucket (test multi bucket setup)",
			"s3.amazonaws.com",
			"/testbucket2/folder/file",
			"/tkaeRrXgID3wbSFLHduukEkLjo=",
		},
		{
			"Bucket with IAM role",
			"testbucket3.s3.amazonaws.com",
			"/folder/file",
			"Fucd5+FvRyP4ptezvxITdFa6wmc=",
		},
		{
			"Unconfigured bucket",
			"anotherbucket.s3.amazonaws.com",
			"/",
			"",
		},
		{
			"Website (not a bucket)",
			"atotallyunrelatedwebsite.org",
			"/index.html",
			"",
		},
	}

	for _, d := range testData {
		requestUrl, _ := url.Parse("http://" + d.Host + d.Path)

		request := &http.Request{
			Method: "GET",
			Host:   d.Host,
			URL:    requestUrl,
			Header: map[string][]string{
				"Date": []string{"Tue, 09 Jul 2013 13:38:52 GMT"},
			},
		}

		// If the request should *not* be signed, make sure it's the case by
		// generating a header that will get overwritten if the request gets
		// signed.
		if d.Signature == "" {
			request.Header.Add("Authorization", "XXX")
		}

		info := h.GetBucketInfo(request)
		err := h.SignRequest(request, info)

		if err != nil {
			t.Errorf("Unexpected error while signing for test case '%s': %s", d.Name, err)
			continue
		}

		auth := request.Header.Get("Authorization")

		if d.Signature == "" {
			if auth != "XXX" {
				t.Errorf("Unexpected authorization header for test case '%s'", d.Name)
			}

			continue
		}

		if auth == "" {
			t.Errorf("Missing authorization header for test case '%s'", d.Name)
			continue
		}

		authTokens := strings.Split(auth, ":")

		if len(authTokens) != 2 {
			t.Errorf("Invalid authorization header for test case '%s'", d.Name)
			continue
		}

		if authTokens[0] != "AWS AccessKey" {
			t.Errorf("Invalid access key for test case '%s'", d.Name)
			continue
		}

		if authTokens[1] != d.Signature {
			t.Errorf("Invalid signature for test case '%s'\n  Expected: '%s\n  Got '%s'", d.Name, d.Signature, authTokens[1])
			continue
		}
	}
}

func createProxiedRequest(url string, proxyport int) *http.Request {
	r, err := http.NewRequest("GET", url, nil)

	if err != nil {
		panic(fmt.Sprintf("Cannot create HTTP request: %s", err))
	}

	r.Header.Add("Host", r.URL.Host)
	r.URL.Host = fmt.Sprintf("127.0.0.1:%d", proxyport)

	return r
}

func TestRetries(t *testing.T) {
	// Get the ProxyHandler to think AWS is 127.0.0.1 so we get the retries
	AwsDomain = "127.0.0.1"

	handler := NewProxyHandler(testConfig)
	listener, port := GetListeningAddress()

	go http.Serve(listener, handler)
	time.Sleep(50 * time.Millisecond)
	defer listener.Close()

	failingServer := NewFailingServer()
	defer failingServer.Close()

	client := &http.Client{}

	serverURL := fmt.Sprintf("http://127.0.0.1:%d", failingServer.Port)

	testData := []struct {
		Name               string
		Path               string
		ExpectedCode       int
		RequestCount       int32
		MinimumRequestTime int
	}{
		{
			"A good request should pass and not retry",
			"/testbucket2/ok",
			http.StatusOK,
			1,
			0,
		},
		{
			"A 404 should not retry",
			"/testbucket2/notfound",
			http.StatusNotFound,
			1,
			0,
		},
		{
			"A TCP error should retry if specified",
			"/testbucket2/failtcp",
			http.StatusInternalServerError,
			2,
			0,
		},
		{
			"A TCP error should not retry if not specified",
			"/testbucket/failtcp",
			http.StatusInternalServerError,
			1,
			0,
		},
		{
			"An HTTP error should retry if specified",
			"/testbucket2/failhttp",
			http.StatusInternalServerError,
			2,
			0,
		},
		{
			"An HTTP error should not retry if not specified",
			"/testbucket/failhttp",
			http.StatusInternalServerError,
			1,
			0,
		},
		{
			"Throttled buckets should not retry too fast",
			"/testbucket4/failhttp",
			http.StatusInternalServerError,
			2,
			300,
		},
	}

	for _, d := range testData {
		currentReqCount := failingServer.RequestCount

		startTime := time.Now()

		resp, err := client.Do(createProxiedRequest(serverURL+d.Path, port))

		if err != nil {
			t.Fatalf("Error while doing request for case '%s': %s", d.Name, err)
		}

		if resp.StatusCode != d.ExpectedCode {
			t.Fatalf("Unexpected HTTP status %d for test case '%s', expected %d", resp.StatusCode, d.Name, d.ExpectedCode)
		}

		reqCount := failingServer.RequestCount - currentReqCount

		if reqCount != d.RequestCount {
			t.Fatalf("Invalid request count for case '%s': %d (expected %d)", d.Name, reqCount, d.RequestCount)
		}

		reqDuration := time.Now().Sub(startTime)

		if reqDuration < time.Duration(d.MinimumRequestTime)*time.Millisecond {
			t.Fatalf("Retries went too fast, should have taken at least %d milliseconds", d.MinimumRequestTime)
		}
	}
}
