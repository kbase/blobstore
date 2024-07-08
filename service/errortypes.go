package service

import (
	"net/http"

	"github.com/kbase/blobstore/core/values"

	"github.com/kbase/blobstore/core"

	"github.com/kbase/blobstore/auth"
)

const (
	invalidAuthHeader = "Invalid authorization header or content"
)

// UnauthorizedCustomError denotes that an unauthorized operation was requested that needs
// special explanation in the error string.
type UnauthorizedCustomError string

// NewUnauthorizedCustomError creates a new UnauthorizedCustomError.
func NewUnauthorizedCustomError(err string) *UnauthorizedCustomError {
	e := UnauthorizedCustomError(err)
	return &e
}

func (e *UnauthorizedCustomError) Error() string {
	return string(*e)
}

// InvalidTokenCustomError denotes that an invalid token was submitted and special explanation
// is needed in the error string.
type InvalidTokenCustomError string

// NewInvalidTokenCustomError creates a new InvalidTokenCustomError.
func NewInvalidTokenCustomError(err string) *InvalidTokenCustomError {
	e := InvalidTokenCustomError(err)
	return &e
}

func (e *InvalidTokenCustomError) Error() string {
	return string(*e)
}

func translateError(err error) (code int, errstr string) {
	// not sure about this approach. Alternative is to add some state to every error that
	// can be mapped to a code, and I'm not super thrilled about that either.
	switch t := err.(type) {
	case *auth.InvalidTokenError:
		// Shock compatibility, should be 401
		return http.StatusBadRequest, invalidAuthHeader
	case *InvalidTokenCustomError:
		return http.StatusUnauthorized, t.Error()
	case *core.NoBlobError:
		return http.StatusNotFound, "Node not found"
	case *core.UnauthorizedError:
		// Shock compatibility, really should be 403 forbidden
		return http.StatusUnauthorized, "User Unauthorized"
	case *core.UnauthorizedACLError:
		// Shock compatibility, really should be 403 forbidden
		return http.StatusBadRequest, "Users that are not node owners can only delete " +
			"themselves from ACLs."
	case *UnauthorizedCustomError:
		return http.StatusForbidden, t.Error()
	case *auth.InvalidUserError:
		// no equivalent shock error, it accepts any string as a username
		return http.StatusBadRequest, t.Error()
	case *values.IllegalInputError:
		return http.StatusBadRequest, t.Error()
	default:
		return 500, t.Error()
	}
}
