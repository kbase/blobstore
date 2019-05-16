package service

import (
	"net/http"

	"github.com/kbase/blobstore/auth"
)

func translateError(err error) (code int, errstr string) {
	// not sure about this approach. Alternative is to add some state to every error that
	// can be mapped to a code, and I'm not super thrilled about that either.
	switch t := err.(type) {
	case *auth.InvalidTokenError:
		// Shock compatibility, should be 401
		return http.StatusBadRequest, "Invalid authorization header or content"
	// add more error types here
	default:
		return 500, t.Error()
	}
}
