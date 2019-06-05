// Package values contains simple wrapper classes for value types, such as MD5 strings.
package values

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

const (
	maxFileNameSize = 256
	maxFormatSize   = 100
)

var md5regex = regexp.MustCompile("^[a-fA-F0-9]{32}$")

// MD5 contains a valid MD5 string.
type MD5 struct {
	md5 string
}

// NewMD5 creates a new MD5.
func NewMD5(md5 string) (*MD5, error) {
	if !md5regex.MatchString(md5) {
		return nil, fmt.Errorf("%v is not an MD5 string", md5)
	}
	return &MD5{md5}, nil
}

// GetMD5 returns the MD5 string.
func (md5 *MD5) GetMD5() string {
	return md5.md5
}

// IllegalInputError denotes that some input was illegal
type IllegalInputError string

// NewIllegalInputError creates a new IllegalInputError.
func NewIllegalInputError(err string) *IllegalInputError {
	e := IllegalInputError(err)
	return &e
}

func (e *IllegalInputError) Error() string {
	return string(*e)
}

// FileName is the name of a file, limited to 256 bytes.
type FileName struct {
	fileName string
}

// NewFileName creates a new filename.
func NewFileName(name string) (*FileName, error) {
	name, err := checkString(name, "File name", maxFileNameSize)
	if err != nil {
		return nil, err
	}
	return &FileName{name}, nil
}

// GetFileName returns the file name.
func (fn *FileName) GetFileName() string {
	return fn.fileName
}

// FileFormat is the format of a file, limited to 100 bytes.
type FileFormat struct {
	fileFormat string
}

// NewFileFormat creates a new filename.
func NewFileFormat(name string) (*FileFormat, error) {
	name, err := checkString(name, "File format", maxFormatSize)
	if err != nil {
		return nil, err
	}
	return &FileFormat{name}, nil
}

// GetFileFormat returns the file name.
func (fn *FileFormat) GetFileFormat() string {
	return fn.fileFormat
}

func checkString(s string, name string, maxSize int) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) > maxSize {
		return "", NewIllegalInputError(fmt.Sprintf("%s is > %d bytes", name, maxSize))
	}
	if containsControlChar(s) {
		return "", NewIllegalInputError(fmt.Sprintf("%s contains control characters", name))
	}
	return s, nil
}

func containsControlChar(s string) bool {
	for _, c := range s {
		if unicode.IsControl(c) {
			return true
		}
	}
	return false
}
