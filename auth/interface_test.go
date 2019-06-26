package auth

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUser(t *testing.T) {
	u, err := NewUser("    un    \t  \n  ", false)
	assert.Nil(t, err, "unexpected error")
	assert.Equal(t, "un", u.GetUserName(), "incorrect username")
	assert.Equal(t, false, u.IsAdmin(), "incorrect isAdmin")

	u, err = NewUser("un2", true)
	assert.Nil(t, err, "unexpected error")
	assert.Equal(t, "un2", u.GetUserName(), "incorrect username")
	assert.Equal(t, true, u.IsAdmin(), "incorrect isAdmin")
}

func TestUserFailInput(t *testing.T) {
	u, err := NewUser("  \t\t     ", false)
	assert.Nil(t, u, "expected error")
	assert.Equal(t, err, errors.New("userName cannot be empty or whitespace only"),
		"incorrect error")
}

func TestInvalidUserError(t *testing.T) {
	type tiue struct {
		users  *[]string
		errstr string
	}

	tc := []tiue{
		tiue{nil, "Please do not initialize *auth.InvalidUserError with a nil"},
		tiue{&[]string{}, "Invalid users: "},
		tiue{&[]string{"foo", "bar"}, "Invalid users: foo, bar"},
	}

	for _, tcase := range tc {
		e := InvalidUserError{tcase.users}
		assert.Equal(t, tcase.errstr, e.Error(), "incorrect error")
	}
}

func TestInvalidTokenError(t *testing.T) {
	e := NewInvalidTokenError("some error")
	assert.Equal(t, "some error", e.Error(), "incorrect error")
}
