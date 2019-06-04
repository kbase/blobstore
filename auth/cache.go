package auth

import (
	gcache "github.com/patrickmn/go-cache"
)

//TODO CACHE implement
//TODO CACHE TEST

// Cache caches auth service data from a provider.
type Cache struct {
	cache *gcache.Cache
	prov  Provider
}

// NewCache creates a new auth cache.
func NewCache(prov Provider) *Cache {
	return &Cache{nil, prov}
}

// GetUser gets a user given a token.
// Returns InvalidToken error.
func (c *Cache) GetUser(token string) (*User, error) {
	return c.prov.GetUser(token)
}

// ValidateUserNames validates that user names exist in the auth system.
// token can be any valid token - it's used only to look up the userName.
// Returns InvalidToken error and InvalidUserError.
func (c *Cache) ValidateUserNames(userNames *[]string, token string) error {
	return c.prov.ValidateUserNames(userNames, token)
}
