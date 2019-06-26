package config

import (
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/kbase/blobstore/test/testhelpers"
	"github.com/stretchr/testify/suite"
)

type TestSuite struct {
	suite.Suite
	tempDir       string
	deleteTempDir bool
}

func (t *TestSuite) SetupSuite() {
	tcfg, err := testhelpers.GetConfig()
	if err != nil {
		t.FailNow(err.Error())
	}
	t.tempDir = filepath.Join(tcfg.TempDir, "ConfigTest-"+uuid.New().String())
	err = os.MkdirAll(t.tempDir, 0700)
	if err != nil {
		t.FailNow(err.Error())
	}
	t.deleteTempDir = tcfg.DeleteTempDir
}

func (t *TestSuite) TearDownSuite() {
	if t.deleteTempDir {
		os.RemoveAll(t.tempDir)
	}
}

func TestRunSuite(t *testing.T) {
	suite.Run(t, new(TestSuite))
}

func (t *TestSuite) writeFile(lines ...string) string {
	return t.writeFileWithSec("BlobStore", lines...)
}

func (t *TestSuite) writeFileWithSec(section string, lines ...string) string {
	f, err := ioutil.TempFile(t.tempDir, "config*.tmp")
	if err != nil {
		t.FailNow(err.Error())
	}
	defer f.Close()
	_, err = f.WriteString("[" + section + "]\n")
	if err != nil {
		t.FailNow(err.Error())
	}
	for _, l := range lines {
		_, err := f.WriteString(l + "\n")
		if err != nil {
			t.FailNow(err.Error())
		}
	}
	return f.Name()
}

func (t *TestSuite) TestMinimalConfig() {
	filePath := t.writeFile(
		"host = localhost:12345     ",
		"mongodb-host = localhost:67890 \t  ",
		"mongodb-database = mydb",
		"s3-host = localhost:34567",
		"s3-bucket =        \t      mybucket",
		"s3-access-key = akey",
		"s3-access-secret = sooporsekrit",
		"s3-region = us-west-1",
		"kbase-auth-url = https://kbase.us/authyauth",
	)
	cfg, err := New(filePath)
	t.Nil(err, "unexpected error")
	u, _ := url.Parse("https://kbase.us/authyauth")
	expected := Config{
		Host:                "localhost:12345",
		MongoHost:           "localhost:67890",
		MongoDatabase:       "mydb",
		S3Host:              "localhost:34567",
		S3Bucket:            "mybucket",
		S3AccessKey:         "akey",
		S3AccessSecret:      "sooporsekrit",
		S3Region:            "us-west-1",
		S3DisableSSL:        false,
		AuthURL:             u,
		AuthAdminRoles:      &[]string{},
		DontTrustXIPHeaders: false,
	}
	t.Equal(&expected, cfg, "incorrect config")
}

func (t *TestSuite) TestMinimalConfigWhitespaceFields() {
	filePath := t.writeFile(
		"host = localhost:12345     ",
		"mongodb-host = localhost:67890 \t  ",
		"mongodb-database = mydb",
		"mongodb-user =     ",
		"mongodb-pwd =     ",
		"s3-host = localhost:34567",
		"s3-bucket =        \t      mybucket",
		"s3-access-key = akey",
		"s3-access-secret = sooporsekrit",
		"s3-disable-ssl =     \t   tru  ",
		"s3-region =       us-west-1    \t   ",
		"kbase-auth-url = https://kbase.us/authyauth",
		"kbase-auth-admin-roles =    \t     ",
		"dont-trust-x-ip-headers =      \t     ",
	)
	cfg, err := New(filePath)
	t.Nil(err, "unexpected error")
	u, _ := url.Parse("https://kbase.us/authyauth")
	expected := Config{
		Host:                "localhost:12345",
		MongoHost:           "localhost:67890",
		MongoDatabase:       "mydb",
		S3Host:              "localhost:34567",
		S3Bucket:            "mybucket",
		S3AccessKey:         "akey",
		S3AccessSecret:      "sooporsekrit",
		S3Region:            "us-west-1",
		S3DisableSSL:        false,
		AuthURL:             u,
		AuthAdminRoles:      &[]string{},
		DontTrustXIPHeaders: false,
	}
	t.Equal(&expected, cfg, "incorrect config")
}

func (t *TestSuite) TestMaximalConfig() {
	filePath := t.writeFile(
		"host = localhost:12345     ",
		"mongodb-host = localhost:67890 \t  ",
		"mongodb-database = mydb",
		"mongodb-user =     mdbu",
		"mongodb-pwd =     mdbp",
		"s3-host = localhost:34567",
		"s3-bucket =        \t      mybucket",
		"s3-access-key = akey",
		"s3-access-secret = sooporsekrit",
		"s3-region = us-west-1",
		"s3-disable-ssl=     true    ",
		"kbase-auth-url = https://kbase.us/authyauth",
		"kbase-auth-admin-roles =    \t     ,    foo   , \tbar\t , ,  baz ,,",
		"dont-trust-x-ip-headers =     true   \t  ",
	)
	cfg, err := New(filePath)
	t.Nil(err, "unexpected error")
	u, _ := url.Parse("https://kbase.us/authyauth")
	expected := Config{
		Host:                "localhost:12345",
		MongoHost:           "localhost:67890",
		MongoDatabase:       "mydb",
		MongoUser:           "mdbu",
		MongoPwd:            "mdbp",
		S3Host:              "localhost:34567",
		S3Bucket:            "mybucket",
		S3AccessKey:         "akey",
		S3AccessSecret:      "sooporsekrit",
		S3DisableSSL:        true,
		S3Region:            "us-west-1",
		AuthURL:             u,
		AuthAdminRoles:      &[]string{"foo", "bar", "baz"},
		DontTrustXIPHeaders: true,
	}
	t.Equal(&expected, cfg, "incorrect config")
}

func (t *TestSuite) TestConfigImmediateFail() {
	nofile := uuid.New().String()
	badsec := t.writeFileWithSec("Blbstore", "foo=bar")
	badkey := t.writeFile("foo")
	nohost := t.writeFile("foo=bar", "hst=whoops")
	nohostval := t.writeFile("foo=bar", "host=  \t    ")
	tc := map[string]error{
		"": fmt.Errorf("Error opening config file : open : no such file or directory"),
		nofile: fmt.Errorf("Error opening config file %s: open %s: no such file or directory",
			nofile, nofile),
		badsec: fmt.Errorf("Error opening config file %s: section 'BlobStore' does not exist",
			badsec),
		badkey: fmt.Errorf("Error opening config file %s: key-value delimiter not found: foo",
			badkey),
		nohost: fmt.Errorf("Missing key host in section BlobStore of config file " + nohost),
		nohostval: fmt.Errorf("Missing value for key host in section BlobStore of config file " +
			nohostval),
	}

	for filename, expectedErr := range tc {
		cfg, err := New(filename)
		t.Nil(cfg, "expected error")
		t.Equal(expectedErr, err, "incorrect error")
	}
}

func (t *TestSuite) TestConfigFailNoHost() {
	nokey := t.writeFile(
		"mongodb-host = localhost:67890 \t  ",
		"mongodb-database = mydb",
		"s3-host = localhost:34567",
		"s3-bucket =        \t      mybucket",
		"s3-access-key = akey",
		"s3-access-secret = sooporsekrit",
		"s3-region = us-west-1",
		"kbase-auth-url = https://kbase.us/authyauth",
	)
	wskey := t.writeFile(
		"host =      ",
		"mongodb-host = localhost:67890 \t  ",
		"mongodb-database = mydb",
		"s3-host = localhost:34567",
		"s3-bucket =        \t      mybucket",
		"s3-access-key = akey",
		"s3-access-secret = sooporsekrit",
		"s3-region = us-west-1",
		"kbase-auth-url = https://kbase.us/authyauth",
	)
	t.checkFile(nokey, wskey, "host")
}

func (t *TestSuite) TestConfigFailNoMongoHost() {
	nokey := t.writeFile(
		"host = localhost:12345",
		"mongodb-database = mydb",
		"s3-host = localhost:34567",
		"s3-bucket =        \t      mybucket",
		"s3-access-key = akey",
		"s3-access-secret = sooporsekrit",
		"s3-region = us-west-1",
		"kbase-auth-url = https://kbase.us/authyauth",
	)
	wskey := t.writeFile(
		"host = localhost:12345",
		"mongodb-host =  \t  ",
		"mongodb-database = mydb",
		"s3-host = localhost:34567",
		"s3-bucket =        \t      mybucket",
		"s3-access-key = akey",
		"s3-access-secret = sooporsekrit",
		"s3-region = us-west-1",
		"kbase-auth-url = https://kbase.us/authyauth",
	)
	t.checkFile(nokey, wskey, "mongodb-host")
}

func (t *TestSuite) TestConfigFailNoMongoDatabase() {
	nokey := t.writeFile(
		"host = localhost:12345",
		"mongodb-host = localhost:67890 \t  ",
		"s3-host = localhost:34567",
		"s3-bucket =        \t      mybucket",
		"s3-access-key = akey",
		"s3-access-secret = sooporsekrit",
		"s3-region = us-west-1",
		"kbase-auth-url = https://kbase.us/authyauth",
	)
	wskey := t.writeFile(
		"host = localhost:12345",
		"mongodb-host = localhost:67890 \t  ",
		"mongodb-database =    \t   ",
		"s3-host = localhost:34567",
		"s3-bucket =        \t      mybucket",
		"s3-access-key = akey",
		"s3-access-secret = sooporsekrit",
		"s3-region = us-west-1",
		"kbase-auth-url = https://kbase.us/authyauth",
	)
	t.checkFile(nokey, wskey, "mongodb-database")
}

func (t *TestSuite) TestConfigFailMongoUserPwd() {
	nouser := t.writeFile(
		"host = localhost:12345",
		"mongodb-host = localhost:67890 \t  ",
		"mongodb-database = mydb",
		"mongodb-pwd = p",
		"s3-host = localhost:34567",
		"s3-bucket =        \t      mybucket",
		"s3-access-key = akey",
		"s3-access-secret = sooporsekrit",
		"s3-region = us-west-1",
		"kbase-auth-url = https://kbase.us/authyauth",
	)
	wsuser := t.writeFile(
		"host = localhost:12345",
		"mongodb-host = localhost:67890 \t  ",
		"mongodb-database = mydb",
		"mongodb-user = \t   \t  ",
		"mongodb-pwd = p",
		"s3-host = localhost:34567",
		"s3-bucket =        \t      mybucket",
		"s3-access-key = akey",
		"s3-access-secret = sooporsekrit",
		"s3-region = us-west-1",
		"kbase-auth-url = https://kbase.us/authyauth",
	)
	nopwd := t.writeFile(
		"host = localhost:12345",
		"mongodb-host = localhost:67890 \t  ",
		"mongodb-database = mydb",
		"mongodb-user = u",
		"s3-host = localhost:34567",
		"s3-bucket =        \t      mybucket",
		"s3-access-key = akey",
		"s3-access-secret = sooporsekrit",
		"s3-region = us-west-1",
		"kbase-auth-url = https://kbase.us/authyauth",
	)
	wspwd := t.writeFile(
		"host = localhost:12345",
		"mongodb-host = localhost:67890 \t  ",
		"mongodb-database = mydb",
		"mongodb-user = u",
		"mongodb-pwd = \t   \t  ",
		"s3-host = localhost:34567",
		"s3-bucket =        \t      mybucket",
		"s3-access-key = akey",
		"s3-access-secret = sooporsekrit",
		"s3-region = us-west-1",
		"kbase-auth-url = https://kbase.us/authyauth",
	)
	for _, f := range []string{nouser, wsuser, nopwd, wspwd} {
		cfg, err := New(f)
		t.Nil(cfg, "expected error")
		t.Equal(fmt.Errorf("Either both or neither of mongodb-user and mongodb-pwd must be "+
			"supplied in section BlobStore of config file %s", f),
			err, "incorrect error")
	}
}

func (t *TestSuite) TestConfigFailNoS3Host() {
	nokey := t.writeFile(
		"host = localhost:12345",
		"mongodb-host = localhost:67890 \t  ",
		"mongodb-database = mydb",
		"s3-bucket =        \t      mybucket",
		"s3-access-key = akey",
		"s3-access-secret = sooporsekrit",
		"s3-region = us-west-1",
		"kbase-auth-url = https://kbase.us/authyauth",
	)
	wskey := t.writeFile(
		"host = localhost:12345",
		"mongodb-host = localhost:67890 \t  ",
		"mongodb-database = mydb",
		"s3-host = \t  \t ",
		"s3-bucket =        \t      mybucket",
		"s3-access-key = akey",
		"s3-access-secret = sooporsekrit",
		"s3-region = us-west-1",
		"kbase-auth-url = https://kbase.us/authyauth",
	)
	t.checkFile(nokey, wskey, "s3-host")
}

func (t *TestSuite) TestConfigFailNoS3Bucket() {
	nokey := t.writeFile(
		"host = localhost:12345",
		"mongodb-host = localhost:67890 \t  ",
		"mongodb-database = mydb",
		"s3-host = localhost:34567",
		"s3-access-key = akey",
		"s3-access-secret = sooporsekrit",
		"s3-region = us-west-1",
		"kbase-auth-url = https://kbase.us/authyauth",
	)
	wskey := t.writeFile(
		"host = localhost:12345",
		"mongodb-host = localhost:67890 \t  ",
		"mongodb-database = mydb",
		"s3-host = localhost:34567",
		"s3-bucket =        \t      ",
		"s3-access-key = akey",
		"s3-access-secret = sooporsekrit",
		"s3-region = us-west-1",
		"kbase-auth-url = https://kbase.us/authyauth",
	)
	t.checkFile(nokey, wskey, "s3-bucket")
}

func (t *TestSuite) TestConfigFailNoS3AccessKey() {
	nokey := t.writeFile(
		"host = localhost:12345",
		"mongodb-host = localhost:67890 \t  ",
		"mongodb-database = mydb",
		"s3-host = localhost:34567",
		"s3-bucket =        \t      mybucket",
		"s3-access-secret = sooporsekrit",
		"s3-region = us-west-1",
		"kbase-auth-url = https://kbase.us/authyauth",
	)
	wskey := t.writeFile(
		"host = localhost:12345",
		"mongodb-host = localhost:67890 \t  ",
		"mongodb-database = mydb",
		"s3-host = localhost:34567",
		"s3-bucket =        \t      mybucket",
		"s3-access-key =    ",
		"s3-access-secret = sooporsekrit",
		"s3-region = us-west-1",
		"kbase-auth-url = https://kbase.us/authyauth",
	)
	t.checkFile(nokey, wskey, "s3-access-key")
}

func (t *TestSuite) TestConfigFailNoS3AccessSecret() {
	nokey := t.writeFile(
		"host = localhost:12345",
		"mongodb-host = localhost:67890 \t  ",
		"mongodb-database = mydb",
		"s3-host = localhost:34567",
		"s3-bucket =        \t      mybucket",
		"s3-access-key = akey",
		"s3-region = us-west-1",
		"kbase-auth-url = https://kbase.us/authyauth",
	)
	wskey := t.writeFile(
		"host = localhost:12345",
		"mongodb-host = localhost:67890 \t  ",
		"mongodb-database = mydb",
		"s3-host = localhost:34567",
		"s3-bucket =        \t      mybucket",
		"s3-access-key = akey",
		"s3-access-secret = \t",
		"s3-region = us-west-1",
		"kbase-auth-url = https://kbase.us/authyauth",
	)
	t.checkFile(nokey, wskey, "s3-access-secret")
}

func (t *TestSuite) TestConfigFailNoS3Region() {
	nokey := t.writeFile(
		"host = localhost:12345",
		"mongodb-host = localhost:67890 \t  ",
		"mongodb-database = mydb",
		"s3-host = localhost:34567",
		"s3-bucket =        \t      mybucket",
		"s3-access-key = akey",
		"s3-access-secret = sooporsekrit",
		"kbase-auth-url = https://kbase.us/authyauth",
	)
	wskey := t.writeFile(
		"host = localhost:12345",
		"mongodb-host = localhost:67890 \t  ",
		"mongodb-database = mydb",
		"s3-host = localhost:34567",
		"s3-bucket =        \t      mybucket",
		"s3-access-key = akey",
		"s3-access-secret = sooporsekrit",
		"s3-region =    \t     \n     ",
		"kbase-auth-url = https://kbase.us/authyauth",
	)
	t.checkFile(nokey, wskey, "s3-region")
}

func (t *TestSuite) TestConfigFailNoAuthURL() {
	nokey := t.writeFile(
		"host = localhost:12345",
		"mongodb-host = localhost:67890 \t  ",
		"mongodb-database = mydb",
		"s3-host = localhost:34567",
		"s3-bucket =        \t      mybucket",
		"s3-access-key = akey",
		"s3-access-secret = sooporsekrit",
		"s3-region = us-west-1",
	)
	wskey := t.writeFile(
		"host = localhost:12345",
		"mongodb-host = localhost:67890 \t  ",
		"mongodb-database = mydb",
		"s3-host = localhost:34567",
		"s3-bucket =        \t      mybucket",
		"s3-access-key = akey",
		"s3-access-secret = sooporsekrit",
		"s3-region = us-west-1",
		"kbase-auth-url =   \t    ",
	)
	t.checkFile(nokey, wskey, "kbase-auth-url")
}

func (t *TestSuite) TestConfigFailBadAuthURL() {
	f := t.writeFile(
		"host = localhost:12345",
		"mongodb-host = localhost:67890 \t  ",
		"mongodb-database = mydb",
		"s3-host = localhost:34567",
		"s3-bucket =        \t      mybucket",
		"s3-access-key = akey",
		"s3-access-secret = sooporsekrit",
		"s3-region = us-west-1",
		"kbase-auth-url =   ://kbase.us/authyauth",
	)

	cfg, err := New(f)
	t.Nil(cfg, "expected error")
	t.Equal(fmt.Errorf("Value for key kbase-auth-url in section BlobStore of config file %s "+
		"is not a valid url: parse ://kbase.us/authyauth: missing protocol scheme", f),
		err, "incorrect error")
}

func (t *TestSuite) checkFile(nokey string, wskey string, key string) {
	cfg, err := New(nokey)
	t.Nil(cfg, "expected error")
	t.Equal(fmt.Errorf("Missing key %s in section BlobStore of config file %s", key, nokey),
		err, "incorrect error")

	cfg, err = New(wskey)
	t.Nil(cfg, "expected error")
	t.Equal(
		fmt.Errorf("Missing value for key %s in section BlobStore of config file %s", key, wskey),
		err, "incorrect error")
}
