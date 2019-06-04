package auth

import (
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	bserr "github.com/kbase/blobstore/errors"
)

//TODO CACHE token -> user & name -> valid

const (
	//https://github.com/kbase/auth2/blob/01a4d2c6e9bf8aff7d7f6eda78af47522ca158d8/src/us/kbase/auth2/lib/UserName.java#L39
	nameInvalidChars = "[^a-z\\d_]+"
	userExpireTimeMS = 30 * 60 * 1000
)

var nameRegex = regexp.MustCompile(nameInvalidChars)

// KBaseProvider provides authentication based on the KBase auth server. Implements auth.Provider.
// (https://github.com/kbase/auth2)
type KBaseProvider struct {
	url           url.URL
	adminRoles    *[]string
	endpointToken url.URL
	endpointMe    url.URL
	endpointUser  string
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
func NewKBaseProvider(kbaseurl url.URL, options ...func(*KBaseProvider) error,
) (*KBaseProvider, error) {
	if !kbaseurl.IsAbs() {
		return nil, errors.New("url must be absolute")
	}
	if !strings.HasSuffix(kbaseurl.String(), "/") {
		kburl, _ := url.Parse(kbaseurl.String() + "/")
		kbaseurl = *kburl
	}
	r := []string(nil)
	kb := &KBaseProvider{url: kbaseurl, adminRoles: &r}
	for _, option := range options {
		err := option(kb)
		if err != nil {
			return nil, err
		}
	}
	token, _ := kbaseurl.Parse("api/V2/token")
	kb.endpointToken = *token
	me, _ := kbaseurl.Parse("api/V2/me")
	kb.endpointMe = *me
	u, _ := kbaseurl.Parse("api/V2/users")
	kb.endpointUser = u.String() + "?list="
	// TODO LATER check url is valid when auth testmode root returns correct info
	// could also check custom roles are valid & clock skew, probably not worth it
	return kb, nil
}

// GetURL returns the url used to contact the auth server.
func (kb *KBaseProvider) GetURL() url.URL {
	return kb.url
}

// GetUser gets a user given a token.
// Returns InvalidToken error.
func (kb *KBaseProvider) GetUser(token string) (*User, int64, int, error) {
	if strings.TrimSpace(token) == "" {
		return nil, -1, -1, bserr.WhiteSpaceError("token")
	}
	tokenjson, err := get(kb.endpointToken, token)
	if err != nil {
		return nil, -1, -1, err
	}
	mejson, err := get(kb.endpointMe, token)
	if err != nil {
		return nil, -1, -1, err // not sure how to test this given the previous passed
	}
	roles := mejson["customroles"].([]interface{})
	isadmin := kb.isAdmin(&roles)
	expires := int64(tokenjson["expires"].(float64))
	cachetime := int(tokenjson["cachefor"].(float64))
	u := &User{userName: tokenjson["user"].(string), isAdmin: isadmin}
	return u, expires, cachetime, nil
}

// expects roles to be strings
func (kb *KBaseProvider) isAdmin(roles *[]interface{}) bool {
	if len(*roles) < 1 || len(*kb.adminRoles) < 1 {
		return false
	}
	rolemap := map[string]struct{}{}
	for _, r := range *kb.adminRoles {
		rolemap[r] = struct{}{}
	}
	for _, r := range *roles {
		delete(rolemap, r.(string))
	}
	return len(rolemap) < len(*kb.adminRoles)
}

func get(u url.URL, token string) (map[string]interface{}, error) {
	req, _ := http.NewRequest(http.MethodGet, u.String(), nil)
	authenticate(&req.Header, token)
	req.Header.Add("accept", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.New("kbase auth get: " + err.Error()) // dunno how to test this
	}
	return toJSON(res)
}

// modifies header in place
func authenticate(h *http.Header, token string) {
	h.Add("authorization", token)
}

// will close body
func toJSON(resp *http.Response) (map[string]interface{}, error) {
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(io.LimitReader(resp.Body, 10000))
	if err != nil {
		return nil, errors.New("kbase auth read: " + err.Error()) // dunno how to test this easily
	}
	if _, err = resp.Body.Read(make([]byte, 1, 1)); err != io.EOF {
		// TODO LOG b
		return nil, errors.New("kbase auth: Unexpectedly long body from auth service")
	}
	var authresp map[string]interface{}
	err = json.Unmarshal(b, &authresp)
	if err != nil {
		// TODO LOG b.
		return nil, errors.New("kbase auth: Non-JSON response from KBase auth server, " +
			"status code: " + strconv.Itoa(resp.StatusCode))
	}
	if resp.StatusCode > 399 { // should never see 100s or 300s
		// assume that we have a valid error response from the auth server at this point
		aerr := authresp["error"].(map[string]interface{})
		if aerr["apperror"] == "Invalid token" {
			return nil, NewInvalidTokenError("KBase auth server reported token was invalid")
		}
		// add more errors responses here
		// not sure how to easily test this
		return nil, errors.New("kbase auth server error: " + aerr["message"].(string))
	}
	return authresp, nil
}

// ValidateUserNames validates that user names exist in the auth system.
// token can be any valid token - it's used only to look up the userNames.
// Returns InvalidToken error and InvalidUserError.
func (kb *KBaseProvider) ValidateUserNames(userNames *[]string, token string) (int, error) {
	if strings.TrimSpace(token) == "" {
		return -1, bserr.WhiteSpaceError("token")
	}
	if userNames == nil || len(*userNames) < 1 {
		return -1, errors.New("userNames cannot be nil or empty")
	}
	names := []string{}
	invalid := []string{}
	for _, n := range *userNames {
		n = strings.TrimSpace(n)
		if n == "" {
			return -1, bserr.WhiteSpaceError("names in userNames array")
		}
		if nameRegex.Match([]byte(n)) || !startsWithLetter(n) {
			invalid = append(invalid, n)
		} else {
			names = append(names, n) // don't modify input
		}
	}
	if len(invalid) > 0 {
		// maybe a different error type here? Not actually checking all the names
		return -1, &InvalidUserError{&invalid}
	}
	u, _ := url.Parse(kb.endpointUser + strings.Join(names, ","))
	userjson, err := get(*u, token)
	if err != nil {
		return -1, err
	}
	for _, n := range names {
		if _, ok := userjson[n]; !ok {
			invalid = append(invalid, n)
		}
	}
	if len(invalid) > 0 {
		return -1, &InvalidUserError{&invalid}
	}
	return userExpireTimeMS, nil
}

func startsWithLetter(s string) bool {
	r, _ := utf8.DecodeRuneInString(s)
	return unicode.IsLetter(r)
}
