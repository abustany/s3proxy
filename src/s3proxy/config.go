package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type ServerConfig struct {
	Address string
	Port    uint16
}

type BucketConfig struct {
	AccessKeyId     string
	SecretAccessKey string
	IAMRole         string
}

type Config struct {
	Server  *ServerConfig
	Buckets map[string]*BucketConfig
}

func parseConfig(filename string) (*Config, error) {
	fd, err := os.Open(filename)

	if err != nil {
		return nil, err
	}

	defer fd.Close()

	decoder := json.NewDecoder(fd)

	c := &Config{}

	err = decoder.Decode(c)

	if err != nil {
		return nil, err
	}

	if c.Server.Address == "" {
		return nil, fmt.Errorf("Missing config parameter Server.Address")
	}

	if c.Server.Port <= 0 {
		return nil, fmt.Errorf("Missing or invalid config parameter Server.Port")
	}

	for name, config := range c.Buckets {
		if config.IAMRole == "" {
			if config.AccessKeyId == "" {
				return nil, fmt.Errorf("Missing config parameter AccessKeyId for bucket '%s'", name)
			}

			if config.SecretAccessKey == "" {
				return nil, fmt.Errorf("Missing config parameter SecretAccessKey for bucket '%s'", name)
			}
		}
	}

	return c, nil
}
