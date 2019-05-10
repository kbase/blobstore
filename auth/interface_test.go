package auth

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestInvalidUserError(t *testing.T) {
	type tiue struct {
		users *[]string
		errstr 	string
	}

	tc := []tiue{
		tiue{nil, "Please do not initialize auth.InvalidUserError with a nil"},
		tiue{&[]string{}, "Invalid users: "},
		tiue{&[]string{"foo", "bar"}, "Invalid users: foo, bar"},
	}

	for _, tcase := range tc {
		e := InvalidUserError{tcase.users}
		assert.Equal(t, tcase.errstr, e.Error(), "incorrect error")
	}
}