package config

import (
	"fmt"
	"strings"

	"github.com/go-ini/ini"
)

const (
	// ConfigLocation denotes the section of the *.ini file where the server configuration can
	// be found
	ConfigLocation = "BlobStore"
	// KeyHost is the configuration key where the value is the server host
	KeyHost = "host"
	// mongo host, db, user, pwd
	// minio host, bucked, accesskey, accesssecret, region
	// auth url, roles
)

// Config contains the server configuration.
type Config struct {
	// Host is the host for the server, e.g. localhost:[port] or 0.0.0.0:[port]
	Host string
}

// New creates a new config struct from the given config file.
func New(configFilePath string) (*Config, error) {
	errstr := "Error opening config file " + configFilePath + ": %s"
	cfg, err := ini.Load(configFilePath)
	if err != nil {
		return nil, fmt.Errorf(errstr, strings.TrimSpace(err.Error()))
	}
	sec, err := cfg.GetSection(ConfigLocation)
	if err != nil {
		return nil, fmt.Errorf(errstr, err.Error())
	}
	host, err := getString(configFilePath, sec, KeyHost, true)
	if err != nil {
		return nil, err
	}

	return &Config{Host: host}, nil
}

func getString(filepath string, sec *ini.Section, key string, required bool) (string, error) {
	s, err := sec.GetKey(key)
	if err != nil {
		// there's only one error mode in the current source.
		return "", fmt.Errorf("Missing key %s in section %s of config file %s",
			key, sec.Name(), filepath)
	}
	v := strings.TrimSpace(s.Value())
	if required && v == "" {
		return "", fmt.Errorf("Missing value for key %s in section %s of config file %s",
			key, sec.Name(), filepath)
	}
	return v, nil
}
