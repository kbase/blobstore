package filestore

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"
	"net/http"
	"crypto/tls"

	"github.com/kbase/blobstore/core/values"
	"github.com/sirupsen/logrus"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/kbase/blobstore/test/miniocontroller"
	"github.com/kbase/blobstore/test/testhelpers"
	"github.com/minio/minio-go"
	"github.com/stretchr/testify/suite"

	logrust "github.com/sirupsen/logrus/hooks/test"
)

type TestSuite struct {
	suite.Suite
	minio         *miniocontroller.Controller
	loggerhook    *logrust.Hook
	deleteTempDir bool
	httpClient    *http.Client
}

func httpClient() *http.Client {

	customTransport := &http.Transport{
	    TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
        }
	customHTTPClient := &http.Client{
                Transport:        customTransport,
		Timeout:         24 * time.Hour }
	return customHTTPClient
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
	t.loggerhook = logrust.NewGlobal()

	logrus.SetOutput(ioutil.Discard)
}

func (t *TestSuite) TearDownSuite() {
	if t.minio != nil {
		t.minio.Destroy(t.deleteTempDir)
	}
}

func (t *TestSuite) SetupTest() {
	t.minio.Clear(false)
	t.loggerhook.Reset()
}

func TestRunSuite(t *testing.T) {
	suite.Run(t, new(TestSuite))
}

func ptr(s string) *string {
	return &s
}

func (t *TestSuite) TestConstructWithGoodBucketNames() {
	min, _ := t.minio.CreateMinioClient()
	cli := t.minio.CreateS3Client()

	b := strings.Builder{}
	b.Write([]byte("abcefghijklmnopqrstuvwxyz-0123456789-012456"))
	for i := 0; i < 2; i++ {
		b.Write([]byte("0123456789"))
	}
	ls := b.String()
	t.Equal(63, len(ls), "incorrect string length")
	httpClient := httpClient()
	for _, bucket := range []string{"foo", ls} {
		fstore, err := NewS3FileStore(cli, min, bucket, httpClient)
		t.NotNil(fstore, "expected filestore client")
		t.Nil(err, "unexpected error")
	}
}

func (t *TestSuite) TestConstructFail() {
	min, _ := t.minio.CreateMinioClient()
	cli := t.minio.CreateS3Client()
	constructFail(t, nil, min, "s", errors.New("s3client cannot be nil"))
	constructFail(t, cli, nil, "s", errors.New("minioClient cannot be nil"))
}

func (t *TestSuite) TestConstructFailBadBucketName() {
	min, _ := t.minio.CreateMinioClient()
	cli := t.minio.CreateS3Client()

	b := strings.Builder{}
	for i := 0; i < 6; i++ {
		b.Write([]byte("a123456789"))
	}
	ls := b.String() + "123"
	t.Equal(63, len(ls), "incorrect string length")
	testcases := map[string]string{
		"":            "bucket length must be between 3 and 63 characters",
		"  \t     ":   "bucket length must be between 3 and 63 characters",
		"     fo    ": "bucket length must be between 3 and 63 characters",
		ls + "a":      "bucket length must be between 3 and 63 characters",
		"-ab":         "bucket must start with a letter or number",
		"a𐤈b":         "bucket contains an illegal character: 𐤈",
		"aCb":         "bucket contains an illegal character: C",
		"a#b":         "bucket contains an illegal character: #",
	}

	for bucket, er := range testcases {
		constructFail(t, cli, min, bucket, errors.New(er))
	}
}

func constructFail(t *TestSuite, client *s3.S3, min *minio.Client, bucket string, expected error) {
	httpClient := httpClient()
	fstore, err := NewS3FileStore(client, min, bucket, httpClient)
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
	httpClient := httpClient()
	fstore, err := NewS3FileStore(s3client, mclient, bucket, httpClient)
	if err != nil {
		t.FailNow(err.Error())
	}
	if fstore == nil {
		t.FailNow("expected configured store")
	}
	t.Equal(fstore.GetBucket(), bucket, "incorrect bucket")
}

func (t *TestSuite) TestStoreAndGet() {
	t.storeAndGet("", "", 0, 0, "012345678910")
}
func (t *TestSuite) TestStoreAndGetWithMeta() {
	t.storeAndGet("fn", "json", 0, 0, "012345678910")
}

func (t *TestSuite) TestStoreAndGetWithSeek() {
	t.storeAndGet("", "", 3, 0, "345678910")
}

func (t *TestSuite) TestStoreAndGetWithExactSeek() {
	t.storeAndGet("", "", 11, 0, "0")
}

func (t *TestSuite) TestStoreAndGetWithLength() {
	t.storeAndGet("", "", 0, 8, "01234567")
}

func (t *TestSuite) TestStoreAndGetWithSeekAndLength() {
	t.storeAndGet("", "", 1, 5, "12345")
}

func (t *TestSuite) TestStoreAndGetWithSeekAndExactLength() {
	t.storeAndGet("", "", 1, 11, "12345678910")
}

func (t *TestSuite) TestStoreAndGetWithSeekAndExcessLength() {
	t.storeAndGet("", "", 1, 15, "12345678910")
}

func (t *TestSuite) storeAndGet(
	filename string,
	format string,
	seek uint64,
	length uint64,
	expectedfile string,
) {
	s3client := t.minio.CreateS3Client()
	mclient, _ := t.minio.CreateMinioClient()
	httpClient := httpClient()
	fstore, _ := NewS3FileStore(s3client, mclient, "mybucket", httpClient)
	p, _ := NewStoreFileParams(
		"myid",
		12,
		strings.NewReader("012345678910"),
		Format(format),
		FileName(filename),
	)
	res, _ := fstore.StoreFile(logrus.WithField("a", "b"), p)
	t.Equal(0, len(t.loggerhook.AllEntries()), "unexpected logging")

	stored := res.Stored
	// sometimes a 1 sec delta fails. I'm guessing that S3 returns a time that is rounded
	// down, and so if the time is very close to the next second, at the time the test occurs
	// it's flipped over to the next second and the test fails.
	testhelpers.AssertCloseToNow(t.T(), stored, 2*time.Second)
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	expected := &FileInfo{
		ID:       "myid",
		Size:     12,
		Stored:   stored, // fake
		Filename: filename,
		Format:   format,
		MD5:      md5,
	}

	t.Equal(expected, res, "unexpected output")

	obj, _ := fstore.GetFile("  myid   ", seek, length)
	defer obj.Data.Close()
	b, _ := ioutil.ReadAll(obj.Data)
	t.Equal(expectedfile, string(b), "incorrect object contents")
	obj.Data = ioutil.NopCloser(strings.NewReader("")) // fake

	expected2 := &GetFileOutput{
		ID:       "myid",
		Size:     int64(len(expectedfile)),
		Filename: filename,
		Format:   format,
		MD5:      md5,
		Data:     ioutil.NopCloser(strings.NewReader("")), // fake
		Stored:   stored,
	}
	t.Equal(expected2, obj, "incorrect object")
}

func (t *TestSuite) TestStoreWithNilInput() {
	s3client := t.minio.CreateS3Client()
	mclient, _ := t.minio.CreateMinioClient()
	httpClient := httpClient()
	fstore, _ := NewS3FileStore(s3client, mclient, "mybucket", httpClient)

	res, err := fstore.StoreFile(nil, &StoreFileParams{}) // DO NOT init SFP like this
	t.Nil(res, "expected error")
	t.Equal(errors.New("logger cannot be nil"), err, "incorrect error")

	res, err = fstore.StoreFile(logrus.WithField("a", "b"), nil)
	t.Nil(res, "expected error")
	t.Equal(errors.New("Params cannot be nil"), err, "incorrect error")
	t.Equal(0, len(t.loggerhook.AllEntries()), "unexpected logging")
}

func (t *TestSuite) TestStoreWithIncorrectSize() {
	s3client := t.minio.CreateS3Client()
	mclient, _ := t.minio.CreateMinioClient()
	httpClient := httpClient()
	fstore, _ := NewS3FileStore(s3client, mclient, "mybucket", httpClient)
	p, _ := NewStoreFileParams(
		"myid",
		11,
		strings.NewReader("012345678910"),
		Format("json"),
		FileName("fn"),
	)
	res, err := fstore.StoreFile(logrus.WithField("a", "b"), p)
	if res != nil {
		t.Fail("returned object is not nil")
	}
	// might want a different error message here
	t.Equal(values.NewIllegalInputError(
		"incorrect Content-Length: http: ContentLength=11 with Body length 12"), err,
		"incorrect error")
	t.Equal(0, len(t.loggerhook.AllEntries()), "unexpected logging")
}

func (t *TestSuite) TestStoreFailNoBucket() {
	s3client := t.minio.CreateS3Client()
	mclient, _ := t.minio.CreateMinioClient()
	httpClient := httpClient()
	fstore, _ := NewS3FileStore(s3client, mclient, "mybucket", httpClient)

	t.minio.Clear(false)

	p, _ := NewStoreFileParams(
		"myid",
		10,
		strings.NewReader("0123456789"),
		Format("json"),
		FileName("fn"),
	)

	res, err := fstore.StoreFile(logrus.WithField("a", "b"), p)
	t.Nil(res, "expected error")
	t.Equal(errors.New("s3 store request unexpected status code: 404"), err, "incorrect error")

	t.Equal(1, len(t.loggerhook.AllEntries()), "incorrect log event count")
	le := t.loggerhook.AllEntries()[0]
	t.Equal("s3 store request unexpected status code: 404", le.Message)
	t.Equal(logrus.ErrorLevel, le.Level, "incorrect level")
	t.Equal("b", le.Data["a"], "incorrect field")
	bdy := "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist" +
		"</Message><Key>myid</Key><BucketName>mybucket</BucketName><Resource>/mybucket/myid" +
		"</Resource>"
	t.Contains(le.Data["truncated_response_body"], bdy, "incorrect body")
}

func (t *TestSuite) TestGetWithBlankID() {
	s3client := t.minio.CreateS3Client()
	mclient, _ := t.minio.CreateMinioClient()
	httpClient := httpClient()
	fstore, _ := NewS3FileStore(s3client, mclient, "mybucket", httpClient)

	res, err := fstore.GetFile("", 0, 0)
	if res != nil {
		t.Fail("returned object is not null")
	}
	t.Equal(errors.New("id cannot be empty or whitespace only"), err, "incorrect err")
}

func (t *TestSuite) TestGetWithNonexistentID() {
	s3client := t.minio.CreateS3Client()
	mclient, _ := t.minio.CreateMinioClient()
	httpClient := httpClient()
	fstore, _ := NewS3FileStore(s3client, mclient, "mybucket", httpClient)
	p, _ := NewStoreFileParams(
		"myid",
		12,
		strings.NewReader("012345678910"),
	)
	_, err := fstore.StoreFile(logrus.WithField("a", "b"), p)
	if err != nil {
		t.Fail(err.Error())
	}
	t.assertNoFile(fstore, " no file ")
}

func (t *TestSuite) assertNoFile(fstore FileStore, id string) {
	res, err := fstore.GetFile(id, 0, 0)
	if res != nil {
		t.Fail("returned object is not null")
	}
	t.Equal(NewNoFileError("No such id: "+strings.TrimSpace(id)), err, "incorrect err")
}

func (t *TestSuite) TestGetWithExcessSeek() {
	s3client := t.minio.CreateS3Client()
	mclient, _ := t.minio.CreateMinioClient()
	httpClient := httpClient()
	fstore, _ := NewS3FileStore(s3client, mclient, "mybucket", httpClient)
	p, _ := NewStoreFileParams(
		"myid",
		12,
		strings.NewReader("012345678910"),
	)
	_, err := fstore.StoreFile(logrus.WithField("a", "b"), p)
	if err != nil {
		t.Fail(err.Error())
	}
	res, err := fstore.GetFile("myid", 12, 0)
	if res != nil {
		t.Fail("returned object is not null")
	}
	t.True(strings.HasPrefix(
		err.Error(),
		"s3 store get: InvalidRange: The requested range is not satisfiable\n\tstatus " +
		"code: 416, request id: "),
		"incorrect error: "+err.Error())
}

func (t *TestSuite) TestGetWithoutMetaData() {
	// files not saved by this code may not have expected user metadata fields
	// e.g. files transferred from Shock
	bkt := "mybucket"
	id := "myid"
	s3client := t.minio.CreateS3Client()
	mclient, _ := t.minio.CreateMinioClient()
	httpClient := httpClient()
	fstore, _ := NewS3FileStore(s3client, mclient, bkt, httpClient)

	_, err := s3client.PutObject(&s3.PutObjectInput{
		Bucket: &bkt,
		Body:   bytes.NewReader([]byte("012345678910")),
		Key:    &id,
	})
	if err != nil {
		t.Fail(err.Error())
	}

	obj, err := fstore.GetFile(id, 0 , 0)
	if err != nil {
		t.Fail(err.Error())
	}
	defer obj.Data.Close()
	// sometimes a 1 sec delta fails. I'm guessing that S3 returns a time that is rounded
	// down, and so if the time is very close to the next second, at the time the test occurs
	// it's flipped over to the next second and the test fails.
	testhelpers.AssertCloseToNow(t.T(), obj.Stored, 2*time.Second)

	b, _ := ioutil.ReadAll(obj.Data)
	t.Equal("012345678910", string(b), "incorrect object contents")
	obj.Data = ioutil.NopCloser(strings.NewReader("")) // fake

	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	expected := &GetFileOutput{
		ID:       id,
		Size:     12,
		Filename: "",
		Format:   "",
		MD5:      md5,
		Data:     ioutil.NopCloser(strings.NewReader("")), // fake
		Stored:   obj.Stored,                              //fake
	}

	t.Equal(expected, obj, "incorrect return")
}

func (t *TestSuite) TestDeleteObject() {
	s3client := t.minio.CreateS3Client()
	mclient, _ := t.minio.CreateMinioClient()
	httpClient := httpClient()
	fstore, _ := NewS3FileStore(s3client, mclient, "mybucket", httpClient)
	p, _ := NewStoreFileParams(
		"myid",
		12,
		strings.NewReader("012345678910"),
	)
	_, err := fstore.StoreFile(logrus.WithField("a", "b"), p)
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
	httpClient := httpClient()
	fstore, _ := NewS3FileStore(s3client, mclient, "mybucket", httpClient)
	p, _ := NewStoreFileParams(
		"myid",
		12,
		strings.NewReader("012345678910"),
	)
	_, err := fstore.StoreFile(logrus.WithField("a", "b"), p)
	if err != nil {
		t.Fail(err.Error())
	}
	err = fstore.DeleteFile("  myid2   ") // S3 returns no error here, which is weird
	if err != nil {
		t.Fail(err.Error())
	}
	obj, err := fstore.GetFile("  myid   ", 0, 0)
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
	httpClient := httpClient()
	fstore, _ := NewS3FileStore(s3client, mclient, "mybucket", httpClient)

	err := fstore.DeleteFile("")
	t.Equal(errors.New("id cannot be empty or whitespace only"), err, "incorrect err")
}

func (t *TestSuite) TestDeleteFailNoBucket() {
	s3client := t.minio.CreateS3Client()
	mclient, _ := t.minio.CreateMinioClient()
	httpClient := httpClient()
	fstore, _ := NewS3FileStore(s3client, mclient, "mybucket", httpClient)

	t.minio.Clear(false)

	err := fstore.DeleteFile("myid")
	t.True(strings.HasPrefix(err.Error(), "s3 store delete: NoSuchBucket: "+
		"The specified bucket does not exist\n\tstatus code: 404, request id:"),
		"incorrect error: "+err.Error())
}

func (t *TestSuite) TestCopyWithSlashes() {
	t.copy("  my/myid  ", "   my/myid3     ", "", "")
}
func (t *TestSuite) TestCopyWithMeta() {
	t.copy("  myid", "   myid3   ", "fn", "json")
}

func (t *TestSuite) copy(
	srcobj string,
	dstobj string,
	filename string,
	format string) {
	s3client := t.minio.CreateS3Client()
	mclient, _ := t.minio.CreateMinioClient()
	httpClient := httpClient()
	fstore, _ := NewS3FileStore(s3client, mclient, "mybucket", httpClient)
	p, _ := NewStoreFileParams(
		srcobj,
		12,
		strings.NewReader("012345678910"),
		Format(format),
		FileName(filename),
	)
	res, _ := fstore.StoreFile(logrus.WithField("a", "b"), p)
	time.Sleep(1 * time.Second) // otherwise the store times are the same
	fi, err := fstore.CopyFile(srcobj, dstobj)
	if err != nil {
		t.Fail(err.Error())
	}
	// sometimes a 1 sec delta fails. I'm guessing that S3 returns a time that is rounded
	// down, and so if the time is very close to the next second, at the time the test occurs
	// it's flipped over to the next second and the test fails.
	testhelpers.AssertCloseToNow(t.T(), fi.Stored, 2*time.Second)
	t.True(fi.Stored.After(res.Stored), "expected copy time later than source time")
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	fiexpected := FileInfo{
		ID:       strings.TrimSpace(dstobj),
		Size:     12,
		Format:   format,
		Filename: filename,
		MD5:      md5,
		Stored:   fi.Stored, // fake
	}
	t.Equal(&fiexpected, fi, "incorrect copy result")

	obj, _ := fstore.GetFile(dstobj, 0, 0)
	defer obj.Data.Close()
	b, _ := ioutil.ReadAll(obj.Data)
	t.Equal("012345678910", string(b), "incorrect object contents")
	obj.Data = ioutil.NopCloser(strings.NewReader("")) // fake

	expected := &GetFileOutput{
		ID:       strings.TrimSpace(dstobj),
		Size:     12,
		Filename: filename,
		Format:   format,
		MD5:      md5,
		Data:     ioutil.NopCloser(strings.NewReader("")), // fake
		Stored:   fi.Stored,                               // fake
	}
	t.Equal(expected, obj, "incorrect object")
}

func (t *TestSuite) TestCopyBadInput() {
	s3client := t.minio.CreateS3Client()
	mclient, _ := t.minio.CreateMinioClient()
	httpClient := httpClient()
	fstore, _ := NewS3FileStore(s3client, mclient, "mybucket", httpClient)

	t.copyFail(fstore, "  \t  \n  ", "bar",
		errors.New("sourceID cannot be empty or whitespace only"))

	t.copyFail(fstore, "foo", "  \t  \n  ",
		errors.New("targetID cannot be empty or whitespace only"))

}

func (t *TestSuite) copyFail(fstore FileStore, src string, dst string, expected error) {
	fi, err := fstore.CopyFile(src, dst)
	t.Nil(fi, "expected error")
	if err == nil {
		t.Fail("expected error")
	}
	t.Equal(expected, err, "incorrect error")
}

func (t *TestSuite) TestCopyNonExistentFile() {
	s3client := t.minio.CreateS3Client()
	mclient, _ := t.minio.CreateMinioClient()
	httpClient := httpClient()
	fstore, _ := NewS3FileStore(s3client, mclient, "mybucket", httpClient)
	p, _ := NewStoreFileParams(
		"myid",
		12,
		strings.NewReader("012345678910"),
	)
	_, err := fstore.StoreFile(logrus.WithField("a", "b"), p)
	if err != nil {
		t.Fail(err.Error())
	}
	t.copyFail(fstore, "  myid2   ", "   myid3  ", NewNoFileError("No such ID: myid2"))
}

func (t *TestSuite) testCopyLargeObject() {
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
	httpClient := httpClient()
	fstore, _ := NewS3FileStore(s3client, mclient, "mybucket", httpClient)
	p, _ := NewStoreFileParams("myid", fi.Size(), reader)
	start := time.Now()
	obj, err := fstore.StoreFile(logrus.WithField("a", "b"), p)
	if err != nil {
		t.Fail(err.Error())
	}
	fmt.Printf("Store took %s\n", time.Since(start))
	stored := time.Now()
	fmt.Println(obj)

	finfo, err := fstore.CopyFile("myid", "myid2")
	if err != nil {
		t.Fail(err.Error())
	}
	fmt.Printf("%v\n", finfo)
	fmt.Printf("Copy took %s\n", time.Since(stored))
	copied := time.Now()
	res, err := fstore.GetFile("myid2", 0, 0)
	if err != nil {
		t.Fail(err.Error())
	}
	fmt.Printf("Get took %s\n", time.Since(copied))
	res.Data.Close()
	fmt.Println(res)
	// test passed

}
