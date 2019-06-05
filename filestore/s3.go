package filestore

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

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
	bucket string) (*S3FileStore, error) {

	if s3client == nil {
		return nil, errors.New("s3client cannot be nil")
	}
	if minioClient == nil {
		return nil, errors.New("minioClient cannot be nil")
	}
	bucket = strings.TrimSpace(bucket)
	if bucket == "" {
		return nil, errors.New("bucket cannot be empty or whitespace only")
	}
	err := createBucket(s3client, bucket)
	if err != nil {
		// this case is hard to test without adding minio accounts which is a chunk of work.
		// Ignore for now.
		return nil, err
	}
	//TODO * INPUT check bucket name for illegal chars and max length

	return &S3FileStore{s3client: s3client, minioClient: minioClient, bucket: bucket}, nil
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
func (fs *S3FileStore) StoreFile(p *StoreFileParams) (out *FileInfo, err error) {
	if p == nil {
		return nil, errors.New("Params cannot be nil")
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
		// The wrapped error has weird behavior that I don't understand, so rewrap in a std err
		return nil, errors.New("s3 store request: " + err.(*url.Error).Err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode > 399 { // don't worry about 100s, shouldn't happen
		// TODO * LOG body
		return nil, fmt.Errorf("s3 store request unexpected status code: %v", resp.StatusCode)
	}
	// tried parsing the date from the returned headers, but wasn't always the same as what's
	// returned by head. Head should be cheap compared to a write
	return fs.getFileInfo(p.id)
}

func (fs *S3FileStore) getFileInfo(id string) (*FileInfo, error) {
	headObj, err := fs.s3client.HeadObject(&s3.HeadObjectInput{Bucket: &fs.bucket, Key: &id})
	if err != nil {
		return nil, errors.New("s3 store head: " + err.Error()) // not sure how to test this
	}
	md5str := strings.Trim(*headObj.ETag, `"`)
	md5, err := values.NewMD5(md5str)
	if err != nil {
		// this is a real pain to test, need to start minio in s3 incompatibility mode
		return nil, errors.New("s3 store returned invalid MD5: " + md5str)
	}
	return &FileInfo{
			ID:       id,
			Filename: getMeta(headObj.Metadata, "Filename"),
			Format:   getMeta(headObj.Metadata, "Format"),
			// theoretically, the Etag is opaque. In practice, it's the md5
			// If that changes, MultiWrite the file to an md5 writer.
			// That means that we can't return the md5 in get file though.
			MD5:    *md5,
			Size:   *headObj.ContentLength,
			Stored: headObj.LastModified.UTC(),
		},
		nil
}

// GetFile Get a file by the ID of the file.
// The user is responsible for closing the reader.
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
	md5, err := values.NewMD5(md5str)
	if err != nil {
		// this is a real pain to test, need to start minio in s3 incompatibility mode
		return nil, errors.New("s3 store returned invalid MD5: " + md5str)
	}
	return &GetFileOutput{
			ID:       id,
			Size:     *res.ContentLength,
			Filename: getMeta(res.Metadata, "Filename"),
			Format:   getMeta(res.Metadata, "Format"),
			MD5:      *md5,
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
	return fs.getFileInfo(targetID)
}
