package filestore

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/minio/minio-go"
)

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
	//TODO INPUT check bucket name for illegal chars and max length

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
			// TODO LOG here, need to pass in logger
			// log.Println("Bucket already exists")
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
func (fs *S3FileStore) StoreFile(p *StoreFileParams) (out *StoreFileOutput, err error) {
	putObj, _ := fs.s3client.PutObjectRequest(&s3.PutObjectInput{ // PutObjectOutput is never filled
		Bucket: &fs.bucket,
		Key:    &p.id,
	})

	presignedurl, _, err := putObj.PresignRequest(15 * time.Minute) // headers is nil in this case
	if err != nil {
		return nil, err // may want to wrap error here, not sure how to test
	}
	req, err := http.NewRequest("PUT", presignedurl, p.data)
	if err != nil {
		return nil, err // may want to wrap error here, not sure now to test
	}
	req.ContentLength = p.size
	req.Header.Set("x-amz-meta-Filename", p.filename)
	req.Header.Set("x-amz-meta-Format", p.format)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// don't expose the presigned url in the returned error
		// The wrapped error has weird behavior that I don't understand, so rewrap in a std err
		return nil, errors.New(err.(*url.Error).Err.Error())
	}
	if resp.StatusCode > 399 { // don't worry about 100s, shouldn't happen
		// not sure how to test this either, other than shutting down Minio
		// TODO LOG body
		return nil, fmt.Errorf("Unexpected status code uploading to S3: %v", resp.StatusCode)
	}
	stored, err := time.Parse(time.RFC1123, resp.Header.Get("Date"))
	if err != nil {
		// should delete file if this occurs, but it should never happen
		return nil, err
	}
	return &StoreFileOutput{
			ID:       p.id,
			Filename: p.filename,
			Format:   p.format,
			// theoretically, the Etag is opaque. In practice, it's the md5
			// If that changes, MultiWrite the file to an md5 writer.
			// That means that we can't return the md5 in get file though.
			MD5:    strings.Trim(resp.Header.Get("Etag"), `"`),
			Size:   p.size,
			Stored: stored.UTC(),
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
			// TODO ERRORS change to own error code system so can be converted to HTTP codes (404 here)
			return nil, fmt.Errorf("No such id: " + id)
		default:
			// do nothing - not sure how to test this
		}
		return nil, err
	}
	return &GetFileOutput{
			ID:       id,
			Size:     *res.ContentLength,
			Filename: getMeta(res.Metadata, "Filename"),
			Format:   getMeta(res.Metadata, "Format"),
			MD5:      strings.Trim(*res.ETag, `"`),
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
		return err // no idea how to test this - could delete bucket? But that shouldn't happen
	}
	return nil
}

// CopyFile copies the file with the source ID to the target ID.
func (fs *S3FileStore) CopyFile(sourceID string, targetID string) error {
	sourceID = strings.TrimSpace(sourceID)
	targetID = strings.TrimSpace(targetID)
	if sourceID == "" {
		return errors.New("sourceID cannot be empty or whitespace only")
	}
	if targetID == "" {
		return errors.New("targetID cannot be empty or whitespace only")
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
		if err2.Code == "NoSuchKey" { //TODO CONSTANT
			// TODO ERRORS change to own error code system so can be converted to HTTP codes (404 here)
			return fmt.Errorf("File ID %s does not exist", sourceID)
		}
	}
	return err // don't know how to test this easily if it's an error
}
