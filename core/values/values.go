// Package values contains simple wrapper classes for value types, such as MD5 strings.
package values

import (
	"fmt"
	"regexp"
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
