package filestore

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/sirupsen/logrus"

	"github.com/kbase/blobstore/core/values"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/minio/minio-go"
)

const (
	minioNoSuchKey = "NoSuchKey"
)

//TODO INPUT check for acceptable object names all over. No leading slashes.

// S3FileStore is a file store that stores files in an S3 API compatible storage system.
// It impelements FileStore.
type S3FileStore struct {
	s3client    *s3.S3
	minioClient *minio.Client
	bucket      string
}

// NewS3FileStore creates a new S3 based file store. Files will be stored in the provided
// bucket, which will be created if it doesn't exist. The provided clients must have write
// privileges for the bucket.
// Two clients are currently required because they are better at different operations.
// This may change in a future version if one client provides all the necessary operations.
func NewS3FileStore(
	s3client *s3.S3,
	minioClient *minio.Client,
	bucket string,
) (*S3FileStore, error) {

	if s3client == nil {
		return nil, errors.New("s3client cannot be nil")
	}
	if minioClient == nil {
		return nil, errors.New("minioClient cannot be nil")
	}
	bucket, err := checkBucketName(bucket)
	if err != nil {
		return nil, err
	}
	err = createBucket(s3client, bucket)
	if err != nil {
		// this case is hard to test without adding minio accounts which is a chunk of work.
		// Ignore for now.
		return nil, err
	}
	return &S3FileStore{s3client: s3client, minioClient: minioClient, bucket: bucket}, nil
}

func checkBucketName(bucket string) (string, error) {
	bucket = strings.TrimSpace(bucket)
	if len(bucket) < 3 || len(bucket) > 63 {
		return "", errors.New("bucket length must be between 3 and 63 characters")
	}
	for i, r := range bucket {
		if r > unicode.MaxASCII {
			return "", errors.New("bucket contains an illegal character: " + string(r))
		}
		if i == 0 && r == '-' {
			return "", errors.New("bucket must start with a letter or number")
		}
		if !unicode.IsLower(r) && !unicode.IsDigit(r) && r != '-' {
			return "", errors.New("bucket contains an illegal character: " + string(r))
		}
	}
	return bucket, nil
}

func createBucket(s3Client *s3.S3, bucket string) error {
	// most of the error cases are hard to test without adding minio accounts which is a
	// chunk of work. Ignore for now.
	input := &s3.CreateBucketInput{Bucket: aws.String(bucket)}
	_, err := s3Client.CreateBucket(input)
	if err != nil {
		switch err.(awserr.Error).Code() {
		case s3.ErrCodeBucketAlreadyOwnedByYou:
			return nil // everything's groovy
		default:
			// do nothing
		}
		return err
	}
	return nil
}

// GetBucket returns the bucket in which files are stored.
func (fs *S3FileStore) GetBucket() string {
	return fs.bucket
}

// StoreFile stores a file.
func (fs *S3FileStore) StoreFile(le *logrus.Entry, p *StoreFileParams) (out *FileInfo, err error) {
	if p == nil {
		return nil, errors.New("Params cannot be nil")
	}
	if le == nil {
		return nil, errors.New("logger cannot be nil")
	}
	putObj, _ := fs.s3client.PutObjectRequest(&s3.PutObjectInput{ // PutObjectOutput is never filled
		Bucket: &fs.bucket,
		Key:    &p.id,
	})

	presignedurl, _, err := putObj.PresignRequest(15 * time.Minute) // headers is nil in this case
	if err != nil {
		return nil, errors.New("s3 store presign: " + err.Error()) //not sure how to test
	}
	// could split the stream here to count the size and confirm content-length
	req, _ := http.NewRequest("PUT", presignedurl, p.data)
	req.ContentLength = p.size
	req.Header.Set("x-amz-meta-Filename", p.filename)
	req.Header.Set("x-amz-meta-Format", p.format)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// don't expose the presigned url in the returned error
		errstr := err.(*url.Error).Err.Error()
		el := strings.ToLower(errstr)
		if strings.Contains(el, "contentlength") &&
			strings.Contains(el, "with body length") {
			// this works for minio, hopefully error messages are stable across S3 impls
			return nil, values.NewIllegalInputError("incorrect Content-Length: " + errstr)
		}
		// dunno how to test this
		return nil, errors.New("s3 store request: " + errstr)
	}
	defer resp.Body.Close()
	if resp.StatusCode > 399 { // don't worry about 100s, shouldn't happen
		buffer := make([]byte, 1000)
		n, err := resp.Body.Read(buffer)
		if err != nil && err != io.EOF {
			return nil, err // dunno how to test this
		}
		er := fmt.Sprintf("s3 store request unexpected status code: %v", resp.StatusCode)
		le.WithField("truncated_response_body", string(buffer[:n])).Error(er)
		return nil, errors.New(er)
	}
	// tried parsing the date from the returned headers, but wasn't always the same as what's
	// returned by head. Head should be cheap compared to a write
	return fs.getFileInfo(p.id, true)
}

func (fs *S3FileStore) getFileInfo(id string, strictMD5 bool) (*FileInfo, error) {
	headObj, err := fs.s3client.HeadObject(&s3.HeadObjectInput{Bucket: &fs.bucket, Key: &id})
	if err != nil {
		return nil, errors.New("s3 store head: " + err.Error()) // not sure how to test this
	}
	md5str := strings.Trim(*headObj.ETag, `"`)
	md5, err := values.NewMD5(md5str)
	if strictMD5 && err != nil {
		// this is a real pain to test
		// tried putting a file with minio PutObject but would need to use at least 5MB parts
		// infuriatingly the mc client does make a non-md5 etag
		// try the AMZ client maybe. For now test manually.
		return nil, errors.New("s3 store returned invalid MD5: " + md5str)
	}
	return &FileInfo{
			ID:       id,
			Filename: getMeta(headObj.Metadata, "Filename"),
			Format:   getMeta(headObj.Metadata, "Format"),
			// theoretically, the Etag is opaque. In practice, it's the md5
			// If that changes, MultiWrite the file to an md5 writer.
			// That means that we can't return the md5 in get file though.
			MD5:    md5,
			Size:   *headObj.ContentLength,
			Stored: headObj.LastModified.UTC(),
		},
		nil
}

// GetFile Get a file by the ID of the file.
// The user is responsible for closing the reader.
// ** Add S3 Range Header **
func (fs *S3FileStore) GetFile(id string) (out *GetFileOutput, err error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, errors.New("id cannot be empty or whitespace only")
	}
	res, err := fs.s3client.GetObject(&s3.GetObjectInput{Bucket: &fs.bucket, Key: &id})
	if err != nil {
		switch err.(awserr.Error).Code() {
		case s3.ErrCodeNoSuchKey:
			return nil, NewNoFileError("No such id: " + id)
		default:
			// do nothing - not sure how to test this
		}
		return nil, errors.New("s3 store get: " + err.Error())
	}
	md5str := strings.Trim(*res.ETag, `"`)
	// ignore errors. Can occur if the file was uploaded in parts, etc.
	// should never happen for files uploaded via StoreFile, but if data is transferred in it
	// may not have a true MD5.
	md5, _ := values.NewMD5(md5str)
	return &GetFileOutput{
			ID:       id,
			Size:     *res.ContentLength,
			Filename: getMeta(res.Metadata, "Filename"),
			Format:   getMeta(res.Metadata, "Format"),
			MD5:      md5,
			Data:     res.Body,
			Stored:   res.LastModified.UTC(),
		},
		nil
}

func getMeta(meta map[string]*string, key string) string {
	val := meta[key]
	if val == nil {
		return ""
	}
	return *val
}

// DeleteFile deletes the file with the given ID. Deleting an ID that does not exist is not an
// error
func (fs *S3FileStore) DeleteFile(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("id cannot be empty or whitespace only")
	}
	_, err := fs.s3client.DeleteObject(&s3.DeleteObjectInput{
		Bucket: &fs.bucket,
		Key:    &id,
	})
	if err != nil {
		return errors.New("s3 store delete: " + err.Error())
	}
	return nil
}

// CopyFile copies the file with the source ID to the target ID.
func (fs *S3FileStore) CopyFile(sourceID string, targetID string) (*FileInfo, error) {
	sourceID = strings.TrimSpace(sourceID)
	targetID = strings.TrimSpace(targetID)
	if sourceID == "" {
		return nil, errors.New("sourceID cannot be empty or whitespace only")
	}
	if targetID == "" {
		return nil, errors.New("targetID cannot be empty or whitespace only")
	}
	// TODO INPUT check valid source and target IDs
	src := minio.NewSourceInfo(fs.bucket, sourceID, nil)
	// err is returned on invalid bucket & object names.
	dst, _ := minio.NewDestinationInfo(fs.bucket, targetID, nil, nil)
	// tested this manually with 12G object. Locally takes about the same amount of time
	// as StoreFile. Disk limited, presumably
	err := fs.minioClient.CopyObject(dst, src)
	if err != nil {
		err2 := err.(minio.ErrorResponse)
		if err2.Code == minioNoSuchKey {
			return nil, NewNoFileError("No such ID: " + sourceID)
		}
		// not sure how to test this.
		return nil, errors.New("s3 store copy: " + err.Error())

	}
	// ignore MD5 errors. Can occur if the file was uploaded in parts, etc.
	// should never happen for files uploaded via StoreFile, but if data is transferred in it
	// may not have a true MD5.
	return fs.getFileInfo(targetID, false)
}
