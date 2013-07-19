package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type CredentialCache struct {
	client     *http.Client
	cache      map[string]*Credentials
	cacheMutex sync.Mutex
}

func NewCredentialCache() *CredentialCache {
	return &CredentialCache{
		client: &http.Client{},
		cache:  make(map[string]*Credentials),
	}
}

var AmzIAMEndpoint = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"

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

func (c *CredentialCache) GetRoleCredentials(role string) (*Credentials, error) {
	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()

	credentials := c.cache[role]

	if credentials == nil || time.Now().After(credentials.Expiration) {
		var err error

		credentials, err = c.FetchRoleCredentials(role)

		if err != nil {
			return nil, err
		}

		c.cache[role] = credentials
	}

	return credentials, nil
}
