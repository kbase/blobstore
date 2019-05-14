// Package config parses the config file for the blobstore.
package config

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/go-ini/ini"
)

const (
	// ConfigLocation denotes the section of the *.ini file where the server configuration can
	// be found
	ConfigLocation = "BlobStore"
	// KeyHost is the configuration key where the value is the server host
	KeyHost = "host"
	// KeyMongoHost is the configuration key where the value is the MongoDB host
	KeyMongoHost = "mongodb-host"
	// KeyMongoDatabase is the configuration key where the value is the MongoDB database
	KeyMongoDatabase = "mongodb-database"
	// KeyMongoUser is the configuration key where the value is the MongoDB user name
	KeyMongoUser = "mongodb-user"
	// KeyMongoPwd is the configuration key where the value is the MongoDB user pwd
	KeyMongoPwd = "mongodb-pwd"
	// KeyS3Host is the configuration key where the value is the S3 host
	KeyS3Host = "s3-host"
	// KeyS3Bucket is the configuration key where the value is the S3 bucket in which files will
	// be stored.
	KeyS3Bucket = "s3-bucket"
	// KeyS3AccessKey is the configuration key where the value is the S3 access key
	KeyS3AccessKey = "s3-access-key"
	// KeyS3AccessSecret is the configuration key where the value is the S3 access secret
	KeyS3AccessSecret = "s3-access-secret"
	// KeyS3DisableSSL is the configuration key that determines whether SSL is to be used.
	// any value other than 'true' is treated as false.
	KeyS3DisableSSL = "s3-disable-ssl"
	// KeyS3Region is the configuration key where the value is the S3 region
	KeyS3Region = "s3-region"
	// KeyAuthURL is the configuration key where the value is the KBase auth server URL
	KeyAuthURL = "kbase-auth-url"
	// KeyAuthAdminRoles is the configuration key where the value is comma-delimited auth server
	// roles that denote that a user is a blobstore admin
	KeyAuthAdminRoles = "kbase-auth-admin-roles"
)

// Config contains the server configuration.
type Config struct {
	// Host is the host for the server, e.g. localhost:[port] or 0.0.0.0:[port]
	Host string
	// MongoHost is the host for the MongoDB database server.
	MongoHost string
	// MongoDatabase is the name of the MongoDB database to use.
	MongoDatabase string
	// MongoUser is the user name of the account to use to contact MongoDB.
	MongoUser string
	// MongoPwd is the password for the MongoDB account.
	MongoPwd string
	// S3Host is the host for the S3 API where files will be stored.
	S3Host string
	// S3Bucket the S3 bucket in which files will be stored.
	S3Bucket string
	// S3AccessKey is the S3 access key
	S3AccessKey string
	// S3AccessSecret is the S3 access secret
	S3AccessSecret string
	// S3DisableSSL determines whether SSL should be used
	S3DisableSSL bool
	// S3Region is the S3 region
	S3Region string
	// AuthURL is the KBase auth server URL. It is never nil.
	AuthURL *url.URL
	// AuthAdminRoles are the auth server roles that denote that a user is a blobstore admin.
	// It is never nil but may be empty.
	AuthAdminRoles *[]string
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
	host, err := getString(nil, configFilePath, sec, KeyHost, true)
	mongohost, err := getString(err, configFilePath, sec, KeyMongoHost, true)
	mongodb, err := getString(err, configFilePath, sec, KeyMongoDatabase, true)
	mongouser, err := getString(err, configFilePath, sec, KeyMongoUser, false)
	mongopwd, err := getString(err, configFilePath, sec, KeyMongoPwd, false)
	s3host, err := getString(err, configFilePath, sec, KeyS3Host, true)
	s3bucket, err := getString(err, configFilePath, sec, KeyS3Bucket, true)
	s3key, err := getString(err, configFilePath, sec, KeyS3AccessKey, true)
	s3secret, err := getString(err, configFilePath, sec, KeyS3AccessSecret, true)
	s3disableSSL, err := getString(err, configFilePath, sec, KeyS3DisableSSL, false)
	s3region, err := getString(err, configFilePath, sec, KeyS3Region, true)
	authurl, err := getURL(err, configFilePath, sec, KeyAuthURL)
	roles, err := getStringList(err, configFilePath, sec, KeyAuthAdminRoles)
	if err != nil {
		return nil, err
	}
	if (mongouser == "") != (mongopwd == "") { // xor
		return nil, fmt.Errorf(
			"Either both or neither of %s and %s must be supplied in section %s of config file %s",
			KeyMongoUser, KeyMongoPwd, sec.Name(), configFilePath)
	}

	return &Config{
			Host:           host,
			MongoHost:      mongohost,
			MongoDatabase:  mongodb,
			MongoUser:      mongouser,
			MongoPwd:       mongopwd,
			S3Host:         s3host,
			S3Bucket:       s3bucket,
			S3AccessKey:    s3key,
			S3AccessSecret: s3secret,
			S3DisableSSL:   "true" == s3disableSSL,
			S3Region:       s3region,
			AuthURL:        authurl,
			AuthAdminRoles: roles,
		},
		nil
}

func getURL(
	preverr error,
	filepath string,
	sec *ini.Section,
	key string,
) (*url.URL, error) {
	if preverr != nil {
		return nil, preverr
	}
	putativeURL, err := getString(nil, filepath, sec, key, true)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(putativeURL)
	if err != nil {
		return nil, fmt.Errorf(
			"Value for key %s in section %s of config file %s is not a valid url: %s",
			key, sec.Name(), filepath, err)
	}
	return u, nil
}

func getString(
	preverr error,
	filepath string,
	sec *ini.Section,
	key string,
	required bool,
) (string, error) {
	if preverr != nil {
		return "", preverr
	}
	s, err := sec.GetKey(key)
	if err != nil {
		if !required {
			return "", nil
		}
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

func getStringList(
	preverr error,
	filepath string,
	sec *ini.Section,
	key string,
) (*[]string, error) {
	if preverr != nil {
		return nil, preverr
	}
	lst := []string{}
	s, err := sec.GetKey(key)
	if err != nil {
		// there's only one error mode in the current source, which is a missing key.
		return &lst, nil
	}
	for _, v := range strings.Split(s.Value(), ",") {
		v = strings.TrimSpace(v)
		if v != "" {
			lst = append(lst, v)
		}
	}
	return &lst, nil
}
