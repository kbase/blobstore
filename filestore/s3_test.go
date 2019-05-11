package filestore

import (
	"fmt"
	"os"
	"bytes"
	"time"
	"github.com/stretchr/testify/assert"
	"errors"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/kbase/blobstore/test/miniocontroller"
	"github.com/kbase/blobstore/test/testhelpers"
	"github.com/stretchr/testify/suite"
	"github.com/minio/minio-go"
	
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
	min, _ := t.minio.CreateMinioClient()
	cli := t.minio.CreateS3Client()
	constructFail(t, nil, min, "s", errors.New("s3client cannot be nil"))
	constructFail(t, cli, nil, "s", errors.New("minioClient cannot be nil"))
	constructFail(t, cli, min, "   \t   \n   ",
		errors.New("bucket cannot be empty or whitespace only"))

}

func constructFail(t *TestSuite, client *s3.S3, min *minio.Client, bucket string, expected error) {
	fstore, err := NewS3FileStore(client, min, bucket)
	if err == nil {
		t.FailNow("expected error")
	}
	if fstore != nil {
		t.FailNow("storage is not nil when error is present")
	}
	t.Equal(expected, err, "incorrect error")
}

func (t *TestSuite) TestConstructWithExistingBucket() {
	s3client := t.minio.CreateS3Client()
	mclient, _ := t.minio.CreateMinioClient()
	bucket := "somebucket"
	input := &s3.CreateBucketInput{Bucket: aws.String(bucket)}
	_, err := s3client.CreateBucket(input)
	if err != nil {
		t.FailNow(err.Error())
	}
	fstore, err := NewS3FileStore(s3client, mclient, bucket)
	if err != nil {
		t.FailNow(err.Error())
	}
	if fstore == nil {
		t.FailNow("expected configured store")
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
	s3client := t.minio.CreateS3Client()
	mclient, _ := t.minio.CreateMinioClient()
	fstore, _ := NewS3FileStore(s3client, mclient, "mybucket")
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

func (t *TestSuite) TestStoreWithNilInput() {
	s3client := t.minio.CreateS3Client()
	mclient, _ := t.minio.CreateMinioClient()
	fstore, _ := NewS3FileStore(s3client, mclient, "mybucket")

	res, err := fstore.StoreFile(nil)
	if res != nil {
		t.Fail("returned object is not nil")
	}
	t.Equal(errors.New("Params cannot be nil"), err, "incorrect error")
}

func (t *TestSuite) TestStoreWithIncorrectSize() {
	s3client := t.minio.CreateS3Client()
	mclient, _ := t.minio.CreateMinioClient()
	fstore, _ := NewS3FileStore(s3client, mclient, "mybucket")
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
	s3client := t.minio.CreateS3Client()
	mclient, _ := t.minio.CreateMinioClient()
	fstore, _ := NewS3FileStore(s3client, mclient, "mybucket")

	res, err := fstore.GetFile("")
	if res != nil {
		t.Fail("returned object is not null")
	}
	t.Equal(errors.New("id cannot be empty or whitespace only"), err, "incorrect err")
}

func (t *TestSuite) TestGetWithNonexistentID() {
	s3client := t.minio.CreateS3Client()
	mclient, _ := t.minio.CreateMinioClient()
	fstore, _ := NewS3FileStore(s3client, mclient, "mybucket")
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

func (t *TestSuite) TestGetWithoutMetaData() {
	// files not saved by this code may not have expected user metadata fields
	// e.g. files transferred from Shock
	bkt := "mybucket"
	id := "myid"
	s3client := t.minio.CreateS3Client()
	mclient, _ := t.minio.CreateMinioClient()
	fstore, _ := NewS3FileStore(s3client, mclient, bkt)

	_, err := s3client.PutObject(&s3.PutObjectInput{
		Bucket: &bkt,
		Body: bytes.NewReader([]byte("012345678910")),
		Key: &id,
	})
	if err != nil {
		t.Fail(err.Error())
	}

	obj, err := fstore.GetFile(id)
	if err != nil {
		t.Fail(err.Error())
	}
	defer obj.Data.Close()
	testhelpers.AssertCloseToNow1S(t.T(), obj.Stored)
	
	b, _ := ioutil.ReadAll(obj.Data)
	t.Equal("012345678910", string(b), "incorrect object contents")
	obj.Data = ioutil.NopCloser(strings.NewReader("")) // fake

	expected := &GetFileOutput{
		ID:       id,
		Size:     12,
		Filename: "",
		Format:   "",
		MD5:      "5d838d477ddf355fc15df1db90bee0aa",
		Data:     ioutil.NopCloser(strings.NewReader("")), // fake
		Stored:   obj.Stored, //fake
	}

	t.Equal(expected, obj, "incorrect return")
}

func (t *TestSuite) TestDeleteObject() {
	s3client := t.minio.CreateS3Client()
	mclient, _ := t.minio.CreateMinioClient()
	fstore, _ := NewS3FileStore(s3client, mclient, "mybucket")
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
	s3client := t.minio.CreateS3Client()
	mclient, _ := t.minio.CreateMinioClient()
	fstore, _ := NewS3FileStore(s3client, mclient, "mybucket")
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
	s3client := t.minio.CreateS3Client()
	mclient, _ := t.minio.CreateMinioClient()
	fstore, _ := NewS3FileStore(s3client, mclient, "mybucket")

	err := fstore.DeleteFile("")
	t.Equal(errors.New("id cannot be empty or whitespace only"), err, "incorrect err")
}

func (t *TestSuite) TestCopy() {
	t.copy("", "")
}
func (t *TestSuite) TestCopyWithMeta() {
	t.copy("fn", "json")
}

func (t *TestSuite) copy(filename string, format string) {
	s3client := t.minio.CreateS3Client()
	mclient, _ := t.minio.CreateMinioClient()
	fstore, _ := NewS3FileStore(s3client, mclient, "mybucket")
	p, _ := NewStoreFileParams(
		"myid",
		12,
		strings.NewReader("012345678910"),
		Format(format),
		FileName(filename),
	)
	res, _ := fstore.StoreFile(p)
	time.Sleep(1 * time.Second) // otherwise the store times are the same
	err := fstore.CopyFile("  myid   ", "   myid3  ")
	if err != nil {
		t.Fail(err.Error())
	}

	obj, _ := fstore.GetFile("  myid3   ")
	testhelpers.AssertCloseToNow1S(t.T(), obj.Stored)
	defer obj.Data.Close()
	b, _ := ioutil.ReadAll(obj.Data)
	t.Equal("012345678910", string(b), "incorrect object contents")
	obj.Data = ioutil.NopCloser(strings.NewReader("")) // fake

	assert.True(t.T(), obj.Stored.After(res.Stored), "expected copy time later than source time")

	expected := &GetFileOutput{
		ID:       "myid3",
		Size:     12,
		Filename: filename,
		Format:   format,
		MD5:      "5d838d477ddf355fc15df1db90bee0aa",
		Data:     ioutil.NopCloser(strings.NewReader("")), // fake
		Stored:   obj.Stored, // fake
	}
	t.Equal(expected, obj, "incorrect object")
}

func (t *TestSuite) TestCopyBadInput() {
	s3client := t.minio.CreateS3Client()
	mclient, _ := t.minio.CreateMinioClient()
	fstore, _ := NewS3FileStore(s3client, mclient, "mybucket")

	t.copyFail(fstore, "  \t  \n  ", "bar",
		errors.New("sourceID cannot be empty or whitespace only"))

	t.copyFail(fstore, "foo", "  \t  \n  ",
		errors.New("targetID cannot be empty or whitespace only"))

}

func (t *TestSuite) copyFail(fstore FileStore, src string, dst string, expected error) {
	err := fstore.CopyFile(src, dst)
	if err == nil {
		t.Fail("expected error")
	}
	t.Equal(err, expected, "incorrect error")
}

func (t *TestSuite) TestCopyNonExistentFile() {
	s3client := t.minio.CreateS3Client()
	mclient, _ := t.minio.CreateMinioClient()
	fstore, _ := NewS3FileStore(s3client, mclient, "mybucket")
	p, _ := NewStoreFileParams(
		"myid",
		12,
		strings.NewReader("012345678910"),
	)
	_, err := fstore.StoreFile(p)
	if err != nil {
		t.Fail(err.Error())
	}
	t.copyFail(fstore, "  myid2   ", "   myid3  ", errors.New("File ID myid2 does not exist"))
}

func (t* TestSuite) testCopyLargeObject() {
	// this takes a long time so should not be part of the regular test suite.
	// run it manually as needed
	largefilepath := os.Getenv("TEST_LARGE_FILE_PATH")
	fmt.Println(largefilepath)
	reader, err := os.Open(largefilepath)
	if err != nil {
		t.Fail(err.Error())
	}
	fi, err := reader.Stat()
	if err != nil {
		t.Fail(err.Error())
	}
	s3client := t.minio.CreateS3Client()
	mclient, _ := t.minio.CreateMinioClient()
	fstore, _ := NewS3FileStore(s3client, mclient, "mybucket")
	p, _ := NewStoreFileParams("myid", fi.Size(), reader)
	start := time.Now()
	obj, err := fstore.StoreFile(p)
	if err != nil {
		t.Fail(err.Error())
	}
	fmt.Printf("Store took %s\n", time.Since(start))
	stored := time.Now()
	fmt.Println(obj)

	err = fstore.CopyFile("myid", "myid2")
	if err != nil {
		t.Fail(err.Error())
	}
	fmt.Printf("Copy took %s\n", time.Since(stored))
	copied := time.Now()
	res, err := fstore.GetFile("myid2")
	if err != nil {
		t.Fail(err.Error())
	}
	fmt.Printf("Get took %s\n", time.Since(copied))
	res.Data.Close()
	fmt.Println(res)
	// test passed

}