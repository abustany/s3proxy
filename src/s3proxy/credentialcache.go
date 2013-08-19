package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"
)

type CredentialCache struct {
	client       *http.Client
	cache        map[string]*Credentials
	instanceRole string
	cacheMutex   sync.Mutex
}

func NewCredentialCache() *CredentialCache {
	return &CredentialCache{
		client: &http.Client{},
		cache:  make(map[string]*Credentials),
	}
}

var AmzIAMEndpoint = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"

func (c *CredentialCache) discoverInstanceRole() (string, error) {
	rsp, err := c.client.Get(AmzIAMEndpoint)

	if err != nil {
		return "", fmt.Errorf("Cannot make HTTP request: %s", err)
	}

	if rsp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Unexpected HTTP status code: %s", rsp.Status)
	}

	data, err := ioutil.ReadAll(rsp.Body)

	if err != nil {
		return "", fmt.Errorf("Error while reading HTTP response body: %s", err)
	}

	return string(data), nil
}

func (c *CredentialCache) FetchRoleCredentials(role string) (*Credentials, error) {
	url := AmzIAMEndpoint + role

	resp, err := c.client.Get(url)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Error response from the IAM endpoint: %s", resp.Status)
	}

	payload := struct {
		Code            string
		LastUpdated     string
		AccessKeyId     string
		SecretAccessKey string
		Token           string
		Expiration      string
	}{}

	decoder := json.NewDecoder(resp.Body)

	err = decoder.Decode(&payload)

	if err != nil {
		return nil, err
	}

	expiration, err := time.Parse(time.RFC3339, payload.Expiration)

	if err != nil {
		return nil, err
	}

	return &Credentials{
		payload.AccessKeyId,
		payload.SecretAccessKey,
		payload.Token,
		expiration,
	}, nil
}

func (c *CredentialCache) GetRoleCredentials() (*Credentials, error) {
	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()

	if c.instanceRole == "" {
		var err error

		c.instanceRole, err = c.discoverInstanceRole()

		if err != nil {
			return nil, fmt.Errorf("Error while fetching instance role: %s", err)
		}
	}

	credentials := c.cache[c.instanceRole]

	if credentials == nil || time.Now().After(credentials.Expiration) {
		var err error

		credentials, err = c.FetchRoleCredentials(c.instanceRole)

		if err != nil {
			return nil, err
		}

		c.cache[c.instanceRole] = credentials
	}

	return credentials, nil
}
