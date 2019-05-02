package filestore

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/kbase/blobstore/test/miniocontroller"
	"github.com/kbase/blobstore/test/testhelpers"
	"github.com/stretchr/testify/suite"
)

type TestSuite struct {
	suite.Suite
	minio         *miniocontroller.Controller
	deleteTempDir bool
}

func (t *TestSuite) SetupSuite() {
	tcfg, err := testhelpers.GetConfig()
	if err != nil {
		t.Fail(err.Error())
	}

	minio, err := miniocontroller.New(miniocontroller.Params{
		ExecutablePath: tcfg.MinioExePath,
		AccessKey:      "ackey",
		SecretKey:      "sooporsecret",
		RootTempDir:    tcfg.TempDir,
		Region:         "us-west-1",
	})
	if err != nil {
		t.Fail(err.Error())
	}
	t.minio = minio
	t.deleteTempDir = tcfg.DeleteTempDir
}

func (t *TestSuite) TearDownSuite() {
	if t.minio != nil {
		t.minio.Destroy(t.deleteTempDir)
	}
}

func (t *TestSuite) SetupTest() {
	t.minio.Clear()
}

func TestRunSuite(t *testing.T) {
	suite.Run(t, new(TestSuite))
}

func ptr(s string) *string {
	return &s
}

func (t *TestSuite) TestConstructFail() {
	constructFail(t, nil, "s", errors.New("client cannot be nil"))
	cli := t.minio.CreateS3Client()
	constructFail(t, cli, "   \t   \n   ", errors.New("bucket cannot be empty or whitespace only"))

}

func constructFail(t *TestSuite, client *s3.S3, bucket string, expected error) {
	fstore, err := NewS3FileStore(client, bucket)
	if err == nil {
		t.Fail("expected error")
	}
	if fstore != nil {
		t.Fail("storage is not nil when error is present")
	}
	t.Equal(expected, err, "incorrect error")
}

func (t *TestSuite) TestConstructWithExistingBucket() {
	mclient := t.minio.CreateS3Client()
	bucket := "somebucket"
	input := &s3.CreateBucketInput{Bucket: aws.String(bucket)}
	_, err := mclient.CreateBucket(input)
	if err != nil {
		t.Fail(err.Error())
	}
	fstore, err := NewS3FileStore(mclient, bucket)
	if err != nil {
		t.Fail(err.Error())
	}
	if fstore == nil {
		t.Fail("expected configured store")
	}
	t.Equal(fstore.GetBucket(), bucket, "incorrect bucket")
}

func (t *TestSuite) TestGetAndPut() {
	mclient := t.minio.CreateS3Client()
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
