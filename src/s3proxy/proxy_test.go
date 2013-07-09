package main

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestSignature(t *testing.T) {
	config := &Config{
		&ServerConfig{},
		map[string]*BucketConfig{
			"testbucket": {
				"AccessKey",
				"SecretKey",
			},
			"testbucket2": {
				"AccessKey",
				"SecretKey2",
			},
		},
	}

	h := &ProxyHandler{
		config,
		nil,
	}

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

		h.SignRequest(request)

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
