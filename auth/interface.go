package auth

import (
	"fmt"
	"strings"
)

// User is a user of an authentication system. The user account name (which is expected to
// be a unique, permanent identifier for the user) and whether the user is an administrator
// of the blob store is provided.
type User struct {
	UserName string
	IsAdmin  bool
}

// InvalidUserError occurs when invalid user names are submitted to ValidateUserNames.
type InvalidUserError struct {
	InvalidUsers *[]string
}

func (iue InvalidUserError) Error() string {
	if iue.InvalidUsers == nil {
		return fmt.Sprintf("Please do not initialize %T with a nil", iue)
	}
	return "Invalid users: " + strings.Join(*iue.InvalidUsers, ", ")
}

// Provider provides authentication for a user given the user's token.
type Provider interface {
	// GetUser gets a user given a token.
	GetUser(token string) (*User, error)
	// ValidateUserName validates that user names exist in the auth system.
	// token can be any valid token - it's used only to look up the userName.
	ValidateUserNames(userNames *[]string, token string) (bool, error)
}
