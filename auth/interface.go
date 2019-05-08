package auth

// User is a user of an authentication system. The user account name (which is expected to
// be a unique, permanent identifier for the user) and whether the user is an administrator
// of the blob store is provided.
type User struct {
	UserName string
	IsAdmin  bool
}

// Provider provides authentication for a user given the user's token.
type Provider interface {
	// GetUser gets a user given a token.
	GetUser(token string) (*User, error)
	// TODO ValidateUser // validate user name
}
