package filestore

import (
	"errors"
	"io/ioutil"
	"strings"
	"testing"

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

func (t *TestSuite) TestStoreAndGet() {
	t.storeAndGet("", "")
}
func (t *TestSuite) TestStoreAndGetWithMeta() {
	t.storeAndGet("fn", "json")
}

func (t *TestSuite) storeAndGet(filename string, format string) {
	mclient := t.minio.CreateS3Client()
	fstore, _ := NewS3FileStore(mclient, "mybucket")
	p, _ := NewStoreFileParams(
		"myid",
		12,
		strings.NewReader("012345678910"),
		Format(format),
		FileName(filename),
	)
	res, _ := fstore.StoreFile(p)

	stored := res.Stored
	testhelpers.AssertCloseToNow1S(t.T(), stored)
	expected := &StoreFileOutput{
		ID:       "myid",
		Size:     12,
		Stored:   stored, // fake
		Filename: filename,
		Format:   format,
		MD5:      "5d838d477ddf355fc15df1db90bee0aa",
	}

	t.Equal(expected, res, "unexpected output")

	obj, _ := fstore.GetFile("  myid   ")
	defer obj.Data.Close()
	b, _ := ioutil.ReadAll(obj.Data)
	t.Equal("012345678910", string(b), "incorrect object contents")
	obj.Data = ioutil.NopCloser(strings.NewReader("")) // fake

	expected2 := &GetFileOutput{
		ID:       "myid",
		Size:     12,
		Filename: filename,
		Format:   format,
		MD5:      "5d838d477ddf355fc15df1db90bee0aa",
		Data:     ioutil.NopCloser(strings.NewReader("")), // fake
		Stored:   stored,
	}
	t.Equal(expected2, obj, "incorrect object")
}

func (t *TestSuite) TestStoreWithIncorrectSize() {
	mclient := t.minio.CreateS3Client()
	fstore, _ := NewS3FileStore(mclient, "mybucket")
	p, _ := NewStoreFileParams(
		"myid",
		11,
		strings.NewReader("012345678910"),
		Format("json"),
		FileName("fn"),
	)
	res, err := fstore.StoreFile(p)
	if res != nil {
		t.Fail("returned object is not nil")
	}
	// might want a different error message here
	t.Equal(errors.New("http: ContentLength=11 with Body length 12"), err, "incorrect error")
}

func (t *TestSuite) TestGetWithBlankID() {
	mclient := t.minio.CreateS3Client()
	fstore, _ := NewS3FileStore(mclient, "mybucket")

	res, err := fstore.GetFile("")
	if res != nil {
		t.Fail("returned object is not null")
	}
	t.Equal(errors.New("id cannot be empty or whitespace only"), err, "incorrect err")
}

func (t *TestSuite) TestGetWithNonexistentID() {
	mclient := t.minio.CreateS3Client()
	fstore, _ := NewS3FileStore(mclient, "mybucket")
	p, _ := NewStoreFileParams(
		"myid",
		12,
		strings.NewReader("012345678910"),
	)
	_, err := fstore.StoreFile(p)
	if err != nil {
		t.Fail(err.Error())
	}
	t.assertNoFile(fstore, " no file ")
}

func (t *TestSuite) assertNoFile(fstore FileStore, id string) {
	res, err := fstore.GetFile(id)
	if res != nil {
		t.Fail("returned object is not null")
	}
	t.Equal(errors.New("No such id: "+strings.TrimSpace(id)), err, "incorrect err")
}

func (t *TestSuite) TestDeleteObject() {
	mclient := t.minio.CreateS3Client()
	fstore, _ := NewS3FileStore(mclient, "mybucket")
	p, _ := NewStoreFileParams(
		"myid",
		12,
		strings.NewReader("012345678910"),
	)
	_, err := fstore.StoreFile(p)
	if err != nil {
		t.Fail(err.Error())
	}
	err = fstore.DeleteFile("  myid   ")
	if err != nil {
		t.Fail(err.Error())
	}
	t.assertNoFile(fstore, "   myid   ")
}

func (t *TestSuite) TestDeleteObjectWrongID() {
	mclient := t.minio.CreateS3Client()
	fstore, _ := NewS3FileStore(mclient, "mybucket")
	p, _ := NewStoreFileParams(
		"myid",
		12,
		strings.NewReader("012345678910"),
	)
	_, err := fstore.StoreFile(p)
	if err != nil {
		t.Fail(err.Error())
	}
	err = fstore.DeleteFile("  myid2   ") // S3 returns no error here, which is weird
	if err != nil {
		t.Fail(err.Error())
	}
	obj, err := fstore.GetFile("  myid   ")
	if err != nil {
		t.Fail(err.Error())
	}
	if obj == nil {
		t.Fail("expected object")
	}
}

func (t *TestSuite) TestDeleteWithBlankID() {
	mclient := t.minio.CreateS3Client()
	fstore, _ := NewS3FileStore(mclient, "mybucket")

	err := fstore.DeleteFile("")
	t.Equal(errors.New("id cannot be empty or whitespace only"), err, "incorrect err")
}
