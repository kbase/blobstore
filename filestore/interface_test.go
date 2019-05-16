package filestore

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStoreFileParamsBuildMinimal(t *testing.T) {
	p, err := NewStoreFileParams("my id", 78, strings.NewReader("contents"))

	assert.Nil(t, err, "unexpected error")

	expected := &StoreFileParams{
		id:       "my id",
		size:     78,
		data:     strings.NewReader("contents"),
		format:   "",
		filename: "",
	}

	assert.Equal(t, expected, p, "incorrect params")
}

func TestStoreFileParamsBuildMaximul(t *testing.T) {
	p, err := NewStoreFileParams("   my id   \t ", 78, strings.NewReader("contents"),
		Format("  \n   json"), FileName("myfile.txt   \t "))

	assert.Nil(t, err, "unexpected error")

	expected := &StoreFileParams{
		id:       "my id",
		size:     78,
		data:     strings.NewReader("contents"),
		format:   "json",
		filename: "myfile.txt",
	}

	assert.Equal(t, expected, p, "incorrect params")
}

func TestStoreFileParamsBuildBadID(t *testing.T) {
	p, err := NewStoreFileParams("  \t   \n   ", 78, strings.NewReader("contents"))

	assert.Nil(t, p, "expected failure")

	assert.Equal(t, errors.New("id cannot be empty or whitespace only"), err, "incorrect err")
}

func TestStoreFileParamsBuildBadSize(t *testing.T) {
	p, err := NewStoreFileParams("bad id", 0, strings.NewReader("contents"))

	assert.Nil(t, p, "expected failure")

	assert.Equal(t, errors.New("size must be > 0"), err, "incorrect err")
}

func TestNoFileError(t *testing.T) {
	e := NewNoFileError("err")
	assert.Equal(t, "err", e.Error(), "incorrect error")
}
