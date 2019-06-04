package cache

import (
	"time"

	"github.com/kbase/blobstore/auth"

	gcache "github.com/patrickmn/go-cache"
)

// TimeProvider provides the current time.
type TimeProvider interface {
	// Now returns the current time.
	Now() time.Time
}

type defaultTimeProvider struct{}

func (tp *defaultTimeProvider) Now() time.Time {
	return time.Now()
}

// Cache caches auth service data from a provider.
type Cache struct {
	cache *gcache.Cache
	prov  auth.Provider
	time  TimeProvider
}

// NewCache creates a new auth cache.
func NewCache(prov auth.Provider) *Cache {
	return NewCacheWithTimeProvider(prov, &defaultTimeProvider{})
}

// NewCacheWithTimeProvider creates a new auth cache with the given time provider.
// This is primarily useful for testing.
func NewCacheWithTimeProvider(prov auth.Provider, tp TimeProvider) *Cache {
	// don't use the default expire time anyway
	return &Cache{gcache.New(5*time.Minute, 10*time.Minute), prov, tp}
}

// GetUser gets a user given a token.
// Returns InvalidToken error.
func (c *Cache) GetUser(token string) (*auth.User, error) {
	// could cache bad tokens, but that's just incompetent client programming if they keep trying
	// to use a bad token.
	if u, ok := c.cache.Get(token); ok {
		return u.(*auth.User), nil
	}
	u, expires, cachefor, err := c.prov.GetUser(token)
	if err != nil {
		return nil, err
	}
	c.cache.Set(token, u, c.getCacheTime(expires, cachefor))
	return u, nil
}

func (c *Cache) getCacheTime(expires int64, cachefor int) time.Duration {
	now := c.time.Now().UnixNano() / 1000000
	if now+int64(cachefor) < expires { // assume cachefor > 0
		return time.Duration(cachefor) * time.Millisecond
	}
	return time.Duration(expires-now) * time.Millisecond
}

// ValidateUserNames validates that user names exist in the auth system.
// token can be any valid token - it's used only to look up the userName.
// Returns InvalidToken error and InvalidUserError.
func (c *Cache) ValidateUserNames(userNames *[]string, token string) error {
	cachemiss := []string{}
	for _, name := range *userNames {
		if _, found := c.cache.Get(name); !found {
			cachemiss = append(cachemiss, name)
		}
	}
	if len(cachemiss) > 0 {
		cachefor, err := c.prov.ValidateUserNames(&cachemiss, token)
		if err != nil {
			// could cache the good usernames here. Not worth the added complexity.
			// could also cache bad usernames. That should be rare unless programmers are
			// incompetent
			return err
		}
		for _, name := range cachemiss {
			c.cache.Set(name, struct{}{}, time.Duration(cachefor)*time.Millisecond)
		}
	}
	return nil
}
