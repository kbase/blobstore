package auth

import (
	"fmt"
	"strings"

	"github.com/kbase/blobstore/errors"
)

// User is a user of an authentication system. The user account name (which is expected to
// be a unique, permanent identifier for the user) and whether the user is an administrator
// of the blob store is provided.
type User struct {
	userName string
	isAdmin  bool
}

// NewUser creates a new user.
func NewUser(userName string, isAdmin bool) (*User, error) {
	userName = strings.TrimSpace(userName)
	if userName == "" {
		return nil, errors.WhiteSpaceError("userName")
	}
	return &User{userName, isAdmin}, nil
}

// GetUserName returns the user's user name.
func (u *User) GetUserName() string {
	return u.userName
}

// IsAdmin returns whether the user is a blob store administrator.
func (u *User) IsAdmin() bool {
	return u.isAdmin
}

// InvalidUserError occurs when invalid user names are submitted to ValidateUserNames.
type InvalidUserError struct {
	InvalidUsers *[]string
}

func (iue *InvalidUserError) Error() string {
	if iue.InvalidUsers == nil {
		return fmt.Sprintf("Please do not initialize %T with a nil", iue)
	}
	return "Invalid users: " + strings.Join(*iue.InvalidUsers, ", ")
}

// InvalidTokenError occurs when the user's token is invalid.
type InvalidTokenError string

// NewInvalidTokenError creates a new invalid token error.
func NewInvalidTokenError(err string) *InvalidTokenError {
	e := InvalidTokenError(err)
	return &e
}

func (e *InvalidTokenError) Error() string {
	return string(*e)
}

// Provider provides authentication for a user given the user's token.
type Provider interface {
	// GetUser gets a user given a token.
	GetUser(token string) (*User, error)
	// ValidateUserName validates that user names exist in the auth system.
	// token can be any valid token - it's used only to look up the userName.
	ValidateUserNames(userNames *[]string, token string) (bool, error)
}
