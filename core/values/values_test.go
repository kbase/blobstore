package values

import (
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
