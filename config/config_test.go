package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"github.com/google/uuid"
	"path/filepath"
	"github.com/kbase/blobstore/test/testhelpers"
	"github.com/stretchr/testify/suite"
	"testing"
)

type TestSuite struct {
	suite.Suite
	tempDir string
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
	filePath := t.writeFile("host = localhost:12345")
	cfg, err := New(filePath)
	t.Nil(err, "unexpected error")
	t.Equal(&Config{"localhost:12345"}, cfg, "incorrect config")
}

func (t *TestSuite) TestConfigFail() {
	nofile := uuid.New().String()
	badsec := t.writeFileWithSec("Blbstore", "foo=bar")
	badkey := t.writeFile("foo")
	nohost := t.writeFile("foo=bar", "hst=whoops")
	nohostval := t.writeFile("foo=bar", "host=  \t    \n")
	tc := map[string]error{
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
