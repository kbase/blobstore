package cache

import (
	"github.com/sirupsen/logrus"
	"errors"
	"time"
	"github.com/stretchr/testify/assert"
	"github.com/kbase/blobstore/auth"
	"testing"

	authmocks "github.com/kbase/blobstore/auth/mocks"
	cachemocks "github.com/kbase/blobstore/auth/cache/mocks"
)

func TestGetUserCacheFor(t *testing.T) {
	provmock := new(authmocks.Provider)
	timemock := new(cachemocks.TimeProvider)

	c := NewCacheWithTimeProvider(provmock, timemock)

	// first attempt is cache miss

	u, _ := auth.NewUser("username", false)

	le := logrus.WithField("a", "b")
	// expect cachefor to take precedence
	provmock.On("GetUser", le, "sometoken").Return(u, int64(1200), 100, nil).Once()
	timemock.On("Now").Return(time.Unix(1, 0)).Once()

	got, err := c.GetUser(le, "sometoken")
	assert.Equal(t, u, got, "incorrect user")
	assert.Nil(t, err, "unexpected error")

	time.Sleep(50 * time.Millisecond)

	// now should hit cache
	got, err = c.GetUser(le, "sometoken")
	assert.Equal(t, u, got, "incorrect user")
	assert.Nil(t, err, "unexpected error")

	time.Sleep(60 * time.Millisecond)

	// cache miss again
	provmock.On("GetUser", le, "sometoken").Return(u, int64(1310), 100, nil).Once()
	timemock.On("Now").Return(time.Unix(1, 110 * 1000000)).Once()
	got, err = c.GetUser(le, "sometoken")
	assert.Equal(t, u, got, "incorrect user")
	assert.Nil(t, err, "unexpected error")

	// now should hit cache
	got, err = c.GetUser(le, "sometoken")
	assert.Equal(t, u, got, "incorrect user")
	assert.Nil(t, err, "unexpected error")

	provmock.AssertNumberOfCalls(t, "GetUser", 2)
	timemock.AssertNumberOfCalls(t, "Now", 2)
}

// could maybe combine w/ test above but I think it'd get too annoying to follow

func TestGetUserExpires(t *testing.T) {
	// last test had cachefor set the expiry, now we'll check with expires
	provmock := new(authmocks.Provider)
	timemock := new(cachemocks.TimeProvider)

	c := NewCacheWithTimeProvider(provmock, timemock)

	// first attempt is cache miss

	u, _ := auth.NewUser("username", false)

	le := logrus.WithField("a", "b")
	// expect cachefor to take precedence
	provmock.On("GetUser", le, "sometoken").Return(u, int64(4100), 200, nil).Once()
	timemock.On("Now").Return(time.Unix(4, 0)).Once()

	got, err := c.GetUser(le, "sometoken")
	assert.Equal(t, u, got, "incorrect user")
	assert.Nil(t, err, "unexpected error")

	time.Sleep(50 * time.Millisecond)

	// now should hit cache
	got, err = c.GetUser(le, "sometoken")
	assert.Equal(t, u, got, "incorrect user")
	assert.Nil(t, err, "unexpected error")

	time.Sleep(60 * time.Millisecond)

	// cache miss again
	provmock.On("GetUser", le, "sometoken").Return(u, int64(4210), 200, nil).Once()
	timemock.On("Now").Return(time.Unix(4, 110 * 1000000)).Once()
	got, err = c.GetUser(le, "sometoken")
	assert.Equal(t, u, got, "incorrect user")
	assert.Nil(t, err, "unexpected error")

	// now should hit cache
	got, err = c.GetUser(le, "sometoken")
	assert.Equal(t, u, got, "incorrect user")
	assert.Nil(t, err, "unexpected error")

	provmock.AssertNumberOfCalls(t, "GetUser", 2)
	timemock.AssertNumberOfCalls(t, "Now", 2)
}

func TestGetUserError(t *testing.T) {
	provmock := new(authmocks.Provider)
	timemock := new(cachemocks.TimeProvider)

	c := NewCacheWithTimeProvider(provmock, timemock)
	le := logrus.WithField("a", "b")
	provmock.On("GetUser", le, "sometoken").Return(nil, int64(4210), 5000, errors.New("foo")).
		Once()

	got, err := c.GetUser(le, "sometoken")
	assert.Nil(t, got, "expected error")
	assert.Equal(t, errors.New("foo"), err, "incorrect error")

	//check that user is not in cache
	u, _ := auth.NewUser("username", false)

	provmock.On("GetUser", le, "sometoken").Return(u, int64(4100), 200, nil).Once()
	timemock.On("Now").Return(time.Unix(4, 0)).Once()
	got, err = c.GetUser(le, "sometoken")
	assert.Equal(t, u, got, "incorrect user")
	assert.Nil(t, err, "unexpected error")

	provmock.AssertNumberOfCalls(t, "GetUser", 2)
	timemock.AssertNumberOfCalls(t, "Now", 1)
}

func TestGetUserFailNilLogger(t *testing.T) {
	provmock := new(authmocks.Provider)
	timemock := new(cachemocks.TimeProvider)

	c := NewCacheWithTimeProvider(provmock, timemock)
	got, err := c.GetUser(nil, "sometoken")
	assert.Nil(t, got, "expected error")
	assert.Equal(t, errors.New("logger cannot be nil"), err, "incorrect error")
}

func TestValidateUserNames(t *testing.T) {
	provmock := new(authmocks.Provider)
	c := NewCache(provmock)

	le := logrus.WithField("a", "b")
	provmock.On("ValidateUserNames", le, &[]string{"u1", "u2", "u3"}, "othertoken").
		Return(100, nil)

	// expect no cache
	err := c.ValidateUserNames(le, &[]string{"u1", "u2", "u3"}, "othertoken")
	assert.Nil(t, err, "unexpected error")

	time.Sleep(50 * time.Millisecond)

	// now should hit cache
	err = c.ValidateUserNames(le, &[]string{"u1", "u2", "u3"}, "othertoken")
	assert.Nil(t, err, "unexpected error")

	time.Sleep(60 * time.Millisecond)

	// cache miss again
	err = c.ValidateUserNames(le, &[]string{"u1", "u2", "u3"}, "othertoken")
	assert.Nil(t, err, "unexpected error")

	// cache hit
	err = c.ValidateUserNames(le, &[]string{"u1", "u2", "u3"}, "othertoken")
	assert.Nil(t, err, "unexpected error")

	provmock.AssertNumberOfCalls(t, "ValidateUserNames", 2)
}

func TestValidateUserNamesPartialCacheHit(t *testing.T) {
	provmock := new(authmocks.Provider)
	c := NewCache(provmock)

	le := logrus.WithField("a", "b")
	provmock.On("ValidateUserNames", le, &[]string{"u1", "u2"}, "othertoken").Return(100, nil)
	provmock.On("ValidateUserNames", le, &[]string{"u3"}, "othertoken").Return(100, nil)

	err := c.ValidateUserNames(le, &[]string{"u1", "u2"}, "othertoken")
	assert.Nil(t, err, "unexpected error")
	err = c.ValidateUserNames(le, &[]string{"u1", "u2", "u3"}, "othertoken")
	assert.Nil(t, err, "unexpected error")

	provmock.AssertNumberOfCalls(t, "ValidateUserNames", 2)
}

func TestValidateUserNamesError(t *testing.T) {
	provmock := new(authmocks.Provider)
	c := NewCache(provmock)

	le := logrus.WithField("a", "b")
	provmock.On("ValidateUserNames", le, &[]string{"u1"}, "othertoken").
		Return(100, errors.New("boo")).Once()

	err := c.ValidateUserNames(le, &[]string{"u1"}, "othertoken")

	assert.Equal(t, errors.New("boo"), err, "incorrect error")

	//check user isn't in cache
	provmock.On("ValidateUserNames", le, &[]string{"u1"}, "othertoken").Return(100, nil)

	err = c.ValidateUserNames(le, &[]string{"u1"}, "othertoken")
	assert.Nil(t, err, "unexpected error")

	provmock.AssertNumberOfCalls(t, "ValidateUserNames", 2)
}

func TestValidateUserNamesFailNilLogger(t *testing.T) {
	provmock := new(authmocks.Provider)
	timemock := new(cachemocks.TimeProvider)

	c := NewCacheWithTimeProvider(provmock, timemock)
	err := c.ValidateUserNames(nil, &[]string{"u1"}, "othertoken")
	assert.Equal(t, errors.New("logger cannot be nil"), err, "incorrect error")
}
