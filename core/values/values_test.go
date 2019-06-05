package values

import (
	"strings"
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewMD5(t *testing.T) {
	for _, m := range []string{
		"5d838d477ddf355fc15df1db90bee0aa",
		"1B9554867D35F0D59E4705F6B2712CD1",
		"0123456789abcdefABCDEF0123456789",
	} {
		md5, err := NewMD5(m)
		assert.Nil(t, err, "unexpected error")
		assert.Equal(t, m, md5.GetMD5(), "incorrect md5")
	}
}

func TestNewMD5Fail(t *testing.T) {
	for _, m := range []string{
		"a",
		"1b9554867d35f0d59e4705f6b2712cd",
		"1b9554867d35f0d59e4705f6b2712cd1c",
		"1b9554867d35X0d59e4705f6b2712cd1",
		"1b9554867d35x0d59e4705f6b2712cd1",
		"1b9554867d35f0d%9e4705f6b2712cd1",
		"1b9554867d35f0d-9e4705f6b2712cd1",
		"1b9554867d35f0d_9e4705f6b2712cd1",
	} {
		md5, err := NewMD5(m)
		assert.Nil(t, md5, "expected error")
		assert.Equal(t, errors.New(m + " is not an MD5 string"), err, "incorrect error")
	}
}

func TestIllegalInputError(t *testing.T) {
	i := NewIllegalInputError("bad input")
	assert.Equal(t, "bad input", i.Error(), "incorrect error")
}

func TestFileName(t *testing.T) {
	fns := fileNameString()
	assert.Equal(t, 256, len(fns), "incorrect length")
	fn, err := NewFileName("    \t       " + fns + "    \t       ")
	assert.Nil(t, err, "unexpected error")
	assert.Equal(t, fns, fn.GetFileName())
}

func fileNameString() string {
	s := "ab9 8&#']K[1*(&)ꢇ]" // 20 bytes

	b := strings.Builder{}
	for i := 0; i < 12; i++ {
		b.Write([]byte(s))
	}
	b.Write([]byte("KJIPG1234567.txt"))
	return b.String()
}

func TestFileNameFail(t *testing.T) {
	fns := fileNameString()
	assert.Equal(t, 256, len(fns), "incorrect length")
	fn, err := NewFileName(fns + "a")
	assert.Nil(t, fn, "expected error")
	assert.Equal(t, NewIllegalInputError("File name is > 256 bytes"), err, "incorrect error")

	fn, err = NewFileName("abc\tneg")
	assert.Nil(t, fn, "expected error")
	assert.Equal(t, NewIllegalInputError("File name contains control characters"), err,
		"incorrect error")
}

func TestFileFormat(t *testing.T) {
	fns := fileNameString()[:100]
	assert.Equal(t, 100, len(fns), "incorrect length")
	fn, err := NewFileFormat("    \t       " + fns + "    \t       ")
	assert.Nil(t, err, "unexpected error")
	assert.Equal(t, fns, fn.GetFileFormat())
}

func TestFileFormatFail(t *testing.T) {
	fns := fileNameString()[:100]
	assert.Equal(t, 100, len(fns), "incorrect length")
	fn, err := NewFileFormat(fns + "a")
	assert.Nil(t, fn, "expected error")
	assert.Equal(t, NewIllegalInputError("File format is > 100 bytes"), err, "incorrect error")

	fn, err = NewFileFormat("abc\tneg")
	assert.Nil(t, fn, "expected error")
	assert.Equal(t, NewIllegalInputError("File format contains control characters"), err,
		"incorrect error")
}
