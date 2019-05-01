package filestore

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/s3"
)

// S3FileStore is a file store that stores files in an S3 API compatible storage system.
// It impelements FileStore.
type S3FileStore struct {
	client *s3.S3
	bucket string
}

// NewS3FileStore creates a new S3 based file store. Files will be stored in the provided
// bucket, which will be created if it doesn't exist. The provided client must have write
// privileges for the bucket.
func NewS3FileStore(client *s3.S3, bucket string) (*S3FileStore, error) {
	if client == nil {
		return nil, errors.New("client cannot be nil")
	}
	bucket = strings.TrimSpace(bucket)
	if bucket == "" {
		return nil, errors.New("bucket cannot be empty or whitespace only")
	}
	err := createBucket(client, bucket)
	if err != nil {
		// this case is hard to test without adding minio accounts which is a chunk of work.
		// Ignore for now.
		return nil, err
	}
	//TODO check bucket for illegal chars and max length

	return &S3FileStore{client: client, bucket: bucket}, nil
}

func createBucket(s3Client *s3.S3, bucket string) error {
	// most of the error cases are hard to test without adding minio accounts which is a
	// chunk of work. Ignore for now.
	input := &s3.CreateBucketInput{Bucket: aws.String(bucket)}
	_, err := s3Client.CreateBucket(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case s3.ErrCodeBucketAlreadyOwnedByYou:
				// TODO log here, need to pass in logger
				// log.Println("Bucket already exists")
				return nil // everything's groovy
			default:
				// do nothing
			}
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
func (fs *S3FileStore) StoreFile(p *StoreFileParams) (out *StoreFileOutput, err error) {
	//TODO check for valid object names https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingMetadata.html
	putObj, _ := fs.client.PutObjectRequest(&s3.PutObjectInput{ // PutObjectOutput is never filled
		Bucket: &fs.bucket,
		Key:    &p.id,
	})

	url, _, err := putObj.PresignRequest(15 * time.Minute) // headers is nil in this case
	if err != nil {
		return nil, err // may want to wrap error here, not sure how to test
	}
	req, err := http.NewRequest("PUT", url, p.data)
	if err != nil {
		return nil, err // may want to wrap error here, not sure now to test
	}
	req.ContentLength = p.size
	req.Header.Set("x-amz-meta-filename", p.filename)
	req.Header.Set("x-amz-meta-format", p.format)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err // may want to wrap error here, not sure how to test
	}
	// TODO check for non-200 response and handle
	return &StoreFileOutput{
			ID:       p.id,
			Filename: p.filename,
			Format:   p.format,
			// theoretically, the Etag is opaque. In practice, it's the md5
			// If that changes, MultiWrite the file to an md5 writer.
			// That means that we can't return the md5 in get file though.
			MD5:    strings.Trim(resp.Header.Get("Etag"), `"`),
			Size:   p.size,
			Stored: time.Now(), // TODO get time from header
		},
		nil
}

// GetFile Get a file by the ID of the file.
func (fs *S3FileStore) GetFile(id string) (out *GetFileOutput, err error) {
	// TODO
	return nil, nil

}
