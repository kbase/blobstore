package filestore

import (
	"errors"
	"io"
	"strings"
	"time"
)

// TODO may need limits for strings.
//TODO in implementation, check for valid object names https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingMetadata.html

// StoreFileParams input parameters for storing a file.
type StoreFileParams struct {
	id       string
	size     int64
	data     io.Reader
	format   string
	filename string
}

// Format provide an arbitrary file format (e.g. json, txt) to the NewStoreFileParams() method.
func Format(format string) func(*StoreFileParams) error {
	return func(s *StoreFileParams) error {
		s.format = strings.TrimSpace(format)
		return nil
	}
}

// FileName provide an arbitrary file name to the NewStoreFileParams() method.
func FileName(filename string) func(*StoreFileParams) error {
	return func(s *StoreFileParams) error {
		s.filename = strings.TrimSpace(filename)
		return nil
	}
}

// NewStoreFileParams create parameters for storing a file.
// The ID must be unique - providing the same ID twice will cause the file to be overwritten.
// To set the file format and name (both optional and arbitrary) use the Format() and
// FileName() functions in the options argument.
// The ID, format, and name will be whitespace-trimmed.
// The reader will be closed when empty.
func NewStoreFileParams(
	id string,
	size int64,
	data io.Reader,
	options ...func(*StoreFileParams) error) (*StoreFileParams, error) {

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

// StoreFileOutput the output of the file storage operation.
type StoreFileOutput struct {
	// The id by which the file can be accessed.
	ID string
	// The size of the file.
	Size int64
	// The file format (e.g. json, txt)
	Format string
	// The filename.
	Filename string
	// The MD5 of the file.
	MD5 string
	// The time the file was stored.
	Stored time.Time
}

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
	// The MD5 of the file.
	MD5 string
	// The time the file was stored.
	Stored time.Time
	// The file's contents.
	Data io.Reader
}

// FileStore an interface to a file storage system that allows storing and retrieving files
// by ID.
type FileStore interface {
	// Store a file.
	StoreFile(p *StoreFileParams) (out *StoreFileOutput, err error)
	// Get a file by the ID of the file.
	GetFile(id string) (out *GetFileOutput, err error)
}
