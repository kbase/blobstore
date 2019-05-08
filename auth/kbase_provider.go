package auth

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	bserr "github.com/kbase/blobstore/errors"
)

//TODO NOW test

// KBaseProvider provides authentication based on the KBase auth server
// (https://github.com/kbase/auth2)
type KBaseProvider struct {
	url           url.URL
	kbToken       string
	adminRoles    *[]string
	endpointToken url.URL
	endpointMe    url.URL
}

// AdminRole is an option for NewKBaseProvider that designates that users with the specified
// KBase auth service role are blobstore admins.
func AdminRole(role string) func(*KBaseProvider) error {
	return func(kb *KBaseProvider) error {
		role = strings.TrimSpace(role)
		if role == "" {
			return bserr.WhiteSpaceError("role")
		}
		r := append(*kb.adminRoles, role)
		kb.adminRoles = &r
		return nil
	}
}

// NewKBaseProvider creates a new auth provider targeting the KBase auth server.
// kbToken must be a valid KBase token and is used to validate KBase user names.
func NewKBaseProvider(url url.URL, kbToken string, options ...func(*KBaseProvider) error,
) (*KBaseProvider, error) {
	// tokens could possibly have surrounding whitespace (although that'd be weird), so we
	// just check it's not *all* whitespace
	if strings.TrimSpace(kbToken) == "" {
		return nil, bserr.WhiteSpaceError("kbToken")
	}
	r := []string(nil)
	kb := &KBaseProvider{url: url, kbToken: kbToken, adminRoles: &r}
	for _, option := range options {
		err := option(kb)
		if err != nil {
			return nil, err
		}
	}
	token, _ := url.Parse("api/V2/token")
	kb.endpointToken = *token
	me, _ := url.Parse("api/V2/me")
	kb.endpointMe = *me
	// TODO LATER check url is valid when auth testmode root returns correct info
	// could also check custom roles are valid & clock skew, probably not worth it
	return kb, nil
}

// GetURL returns the url of the KBase auth server.
func (kb *KBaseProvider) GetURL() url.URL {
	return kb.url
}

// GetRoles returns the KBase auth server roles that designate blobstore admins.
func (kb *KBaseProvider) GetRoles() *[]string {
	r := append([]string(nil), *kb.adminRoles...)
	return &r
}

// GetUser gets a user given a token.
func (kb *KBaseProvider) GetUser(token string) (*User, error) {
	if strings.TrimSpace(token) == "" {
		return nil, bserr.WhiteSpaceError("token")
	}
	// TODO CACHE
	req, err := http.NewRequest(http.MethodGet, kb.endpointToken.String(), nil)
	if err != nil {
		return nil, err // dunno how to test this
	}
	authenticate(&req.Header, token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	fmt.Printf("res: %v\nbody\n:", res)
	io.Copy(os.Stdout, res.Body)
	fmt.Println()

	// TODO NOW implement
	// https://github.com/jgi-kbase/IDMappingService/blob/master/src/jgikbase/idmapping/userlookup/kbase_user_lookup.py

	return nil, nil
}

// modifies header in place
func authenticate(h *http.Header, token string) {
	h.Add("authorization", token)
}
