package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

type Config struct {
	BindAddress     string
	AccessKeyId     string
	SecretAccessKey string
}

func parseConfig(filename string) (*Config, error) {
	fd, err := os.Open(filename)

	if err != nil {
		return nil, err
	}

	defer fd.Close()

	scanner := bufio.NewScanner(fd)

	currentLine := 0

	c := &Config{}

	values := make(map[string]string)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		currentLine++

		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		tokens := strings.SplitN(line, "=", 2)

		if len(tokens) != 2 {
			return nil, fmt.Errorf("Invalid configuration directive at line %d", currentLine)
		}

		key := strings.TrimSpace(tokens[0])
		value := strings.TrimSpace(tokens[1])

		if key == "" || value == "" {
			return nil, fmt.Errorf("Empty key or value at line %d", currentLine)
		}

		values[key] = value

		switch key {
		case "BindAddress":
			c.BindAddress = value
		case "AccessKeyId":
			c.AccessKeyId = value
		case "SecretAccessKey":
			c.SecretAccessKey = value
		}
	}

	requiredKeys := []string{"BindAddress", "AccessKeyId", "SecretAccessKey"}

	for _, k := range requiredKeys {
		if _, ok := values[k]; !ok {
			return nil, fmt.Errorf("Missing configuration parameter: %s", k)
		}
	}

	c.BindAddress = values["BindAddress"]
	c.AccessKeyId = values["AccessKeyId"]
	c.SecretAccessKey = values["SecretAccessKey"]

	return c, nil
}
