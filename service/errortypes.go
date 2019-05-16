package service

import (
	"net/http"

	"github.com/kbase/blobstore/core"

	"github.com/kbase/blobstore/auth"
)

func translateError(err error) (code int, errstr string) {
	// not sure about this approach. Alternative is to add some state to every error that
	// can be mapped to a code, and I'm not super thrilled about that either.
	switch t := err.(type) {
	case *auth.InvalidTokenError:
		// Shock compatibility, should be 401
		return http.StatusBadRequest, "Invalid authorization header or content"
	case *core.NoBlobError:
		return http.StatusNotFound, "Node not found"
	case *core.UnauthorizedError:
		// Shock compatibility, really should be 403 forbidden
		return http.StatusUnauthorized, "User Unauthorized"
	default:
		return 500, t.Error()
	}
}
