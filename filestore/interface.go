package filestore

import (
	"errors"
	"io"
	"strings"
	"time"

	"github.com/kbase/blobstore/core/values"
	"github.com/sirupsen/logrus"
)

// TODO INPUT may need limits for strings.

// StoreFileParams input parameters for storing a file.
type StoreFileParams struct {
	id       string
	size     int64
	data     io.Reader
	format   string
	filename string
}

// Format provides an arbitrary file format (e.g. json, txt) to the NewStoreFileParams() method.
func Format(format string) func(*StoreFileParams) error {
	return func(s *StoreFileParams) error {
		s.format = strings.TrimSpace(format)
		return nil
	}
}

// FileName provides an arbitrary file name to the NewStoreFileParams() method.
func FileName(filename string) func(*StoreFileParams) error {
	return func(s *StoreFileParams) error {
		s.filename = strings.TrimSpace(filename)
		return nil
	}
}

// NewStoreFileParams creates parameters for storing a file.
// The ID must be unique - providing the same ID twice will cause the file to be overwritten.
// To set the file format and name (both optional and arbitrary) use the Format() and
// FileName() functions in the options argument.
// The ID, format, and name will be whitespace-trimmed.
// The user is responsible for closing the reader, if closable.
func NewStoreFileParams(
	id string,
	size int64,
	data io.Reader,
	options ...func(*StoreFileParams) error) (*StoreFileParams, error) {

	//TODO INPUT check for valid object names https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingMetadata.html. Also minio objects can't have a leading slash
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, errors.New("id cannot be empty or whitespace only")
	}
	if size < 1 {
		return nil, errors.New("size must be > 0")
	}

	p := &StoreFileParams{id: id, size: size, data: data}

	for _, option := range options {
		option(p) // currently no option funcs return nil
		// add this back in if that changes
		// err := option(p)
		// if err != nil {
		// 	return nil, err
		// }
	}
	return p, nil
}

// FileInfo contains information about a file.
type FileInfo struct {
	// The id by which the file can be accessed.
	ID string
	// The size of the file.
	Size int64
	// The file format (e.g. json, txt)
	Format string
	// The filename.
	Filename string
	// The MD5 of the file. May be nil if the backend service does not provide an MD5 - for
	// example many S3 upload methods. Always provided for a store file operation.
	MD5 *values.MD5
	// The time the file was stored.
	Stored time.Time
}

// may want to make specific structs for save and copy, but that complicates the code
// quite a bit. YAGNI for now.

// GetFileOutput the output when getting a file. The user is responsible for closing the reader.
type GetFileOutput struct {
	// The id by which the file can be accessed.
	ID string
	// The size of the file.
	Size int64
	// The file format (e.g. json, txt)
	Format string
	// The filename.
	Filename string
	// The MD5 of the file. May be nil if the backend service does not provide an MD5 - for
	// example many S3 upload methods.
	MD5 *values.MD5
	// The time the file was stored.
	Stored time.Time
	// The file's contents.
	Data io.ReadCloser
}

// NoFileError is returned when a file that doesn't exist is requested.
type NoFileError string

// NewNoFileError creates a new NoFileError.
func NewNoFileError(err string) *NoFileError {
	e := NoFileError(err)
	return &e
}

func (e *NoFileError) Error() string {
	return string(*e)
}

// FileStore an interface to a file storage system that allows storing and retrieving files
// by ID.
type FileStore interface {
	// Store a file. In this case the MD5 is always provided.
	StoreFile(le *logrus.Entry, p *StoreFileParams) (*FileInfo, error)
	// Get a file by the ID of the file.
	// Returns NoFileError if there is no file by the given ID.
	GetFile(id string) (*GetFileOutput, error)
	// DeleteFile deletes a file. Deleting a file that does not exist is not an error.
	DeleteFile(id string) error
	// CopyFile copies a file from one ID to another.
	// Returns NoFileError if there is no file by the source ID.
	CopyFile(sourceID string, targetID string) (*FileInfo, error)
}
