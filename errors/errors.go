package errors

import "errors"

// WhiteSpaceError returns an error noting that the key cannot be empty or whitespace only.
func WhiteSpaceError(key string) error {
	return errors.New(key + " cannot be empty or whitespace only")
}
