package filestore

import (
	"strings"
	"testing"
	"time"

	"github.com/kbase/blobstore/test/miniocontroller"
	"github.com/kbase/blobstore/test/testhelpers"
	"github.com/stretchr/testify/suite"
)

type TestSuite struct {
	suite.Suite
	minio *miniocontroller.Controller
}

func (t *TestSuite) SetupSuite() {
	// TODO get from test files
	miniopath := "minio"
	testdir := "temp_test_dir"

	minio, err := miniocontroller.New(miniocontroller.Params{
		ExecutablePath: miniopath,
		AccessKey:      "ackey",
		SecretKey:      "sooporsecret",
		RootTempDir:    testdir})
	if err != nil {
		t.Fail(err.Error())
	}
	t.minio = minio
}

func (t *TestSuite) TearDownSuite() {
	// TODO get from test files
	deleteTempFiles := true
	if t.minio != nil {
		t.minio.Destroy(deleteTempFiles)
	}
}

// TODO clear minio between tests

func TestRunSuite(t *testing.T) {
	suite.Run(t, new(TestSuite))
}

func ptr(s string) *string {
	return &s
}

//TODO test file store with existing bucket

func (t *TestSuite) TestGetAndPut() {
	mclient := t.minio.CreateS3Client("us-west-1")
	fstore, err := NewS3FileStore(mclient, "mybucket")
	if err != nil {
		t.Fail(err.Error())
	}
	p, err := NewStoreFileParams(
		"myid",
		12,
		strings.NewReader("012345678910"),
		Format("json"),
		FileName("fn"),
	)
	if err != nil {
		t.Fail(err.Error())
	}
	res, err := fstore.StoreFile(p)
	if err != nil {
		t.Fail(err.Error())
	}

	testhelpers.AssertCloseToNow1S(t.T(), res.Stored)
	fakestored := time.Now()
	res.Stored = fakestored
	expected := &StoreFileOutput{
		ID:       "myid",
		Size:     12,
		Stored:   fakestored,
		Filename: "fn",
		Format:   "json",
		MD5:      "5d838d477ddf355fc15df1db90bee0aa",
	}

	t.Equal(expected, res, "unexpected output")

	//TODO get file and check contents
}
