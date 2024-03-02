package auth

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/kbase/blobstore/test/kbaseauthcontroller"
	"github.com/kbase/blobstore/test/mongocontroller"
	"github.com/sirupsen/logrus"

	"github.com/kbase/blobstore/test/testhelpers"
	"github.com/stretchr/testify/suite"

	logrust "github.com/sirupsen/logrus/hooks/test"
)

const (
	blobstoreRole = "BLOBSTORE_ADMIN"
	adminRole     = "KBASE_ADMIN"
)

type TestSuite struct {
	suite.Suite
	mongo           *mongocontroller.Controller
	auth            *kbaseauthcontroller.Controller
	authURL         *url.URL
	loggerhook      *logrust.Hook
	deleteTempDir   bool
	tokenNoRole     string
	tokenStdRole    string
	tokenKBaseAdmin string
}

func (t *TestSuite) SetupSuite() {
	tcfg, err := testhelpers.GetConfig()
	if err != nil {
		t.FailNow(err.Error())
	}

	mongoctl, err := mongocontroller.New(mongocontroller.Params{
		ExecutablePath: tcfg.MongoExePath,
		UseWiredTiger:  tcfg.UseWiredTiger,
		RootTempDir:    tcfg.TempDir,
	})
	if err != nil {
		t.FailNow(err.Error())
	}
	t.mongo = mongoctl

	auth, err := kbaseauthcontroller.New(kbaseauthcontroller.Params{
		JarsDir:       tcfg.JarsDir,
		MongoHost:     "localhost:" + strconv.Itoa(mongoctl.GetPort()),
		MongoDatabase: "test_kb_auth_provider_authdb",
		RootTempDir:   tcfg.TempDir,
	})
	if err != nil {
		t.FailNow(err.Error())
	}
	t.authURL, err = url.Parse("http://localhost:" + strconv.Itoa(auth.GetPort()) + "/testmode/")
	if err != nil {
		t.FailNow(err.Error())
	}
	t.auth = auth
	t.deleteTempDir = tcfg.DeleteTempDir

	t.setUpUsersAndRoles()
	t.loggerhook = logrust.NewGlobal()
	logrus.SetOutput(ioutil.Discard)
}

func (t *TestSuite) setUpUsersAndRoles() {
	t.createTestUser("noroles")
	t.createTestUser("admin_std_role")
	t.createTestUser("admin_kbase")
	t.createTestUser("abc_123")

	t.tokenNoRole = t.createTestToken("noroles")
	t.tokenStdRole = t.createTestToken("admin_std_role")
	t.tokenKBaseAdmin = t.createTestToken("admin_kbase")

	t.createTestRole(blobstoreRole)
	t.createTestRole(adminRole)

	t.addTestRole("admin_std_role", blobstoreRole)
	t.addTestRole("admin_kbase", adminRole)
}

func (t *TestSuite) createTestUser(username string) {
	if err := t.auth.CreateTestUser(username, "displayname"); err != nil {
		t.FailNow(err.Error())
	}
}

func (t *TestSuite) createTestToken(username string) string {
	token, err := t.auth.CreateTestToken(username)
	if err != nil {
		t.FailNow(err.Error())
	}
	return token
}

func (t *TestSuite) createTestRole(role string) {
	if err := t.auth.CreateTestRole(role, "description"); err != nil {
		t.FailNow(err.Error())
	}
}

func (t *TestSuite) addTestRole(username string, role string) {
	r := []string{role}
	if err := t.auth.SetTestUserRoles(username, &r); err != nil {
		t.FailNow(err.Error())
	}
}

func (t *TestSuite) SetupTest() {
	t.loggerhook.Reset()
}

func (t *TestSuite) TearDownSuite() {
	if t.auth != nil {
		t.auth.Destroy(t.deleteTempDir)
	}
	if t.mongo != nil {
		t.mongo.Destroy(t.deleteTempDir)
	}
}

func TestRunSuite(t *testing.T) {
	suite.Run(t, new(TestSuite))
}

func (t *TestSuite) TestConstruct() {
	u, _ := url.Parse("http://foo.bar/baz/")
	kb, err := NewKBaseProvider(*u)
	t.Nil(err, "unexpected error")
	expected, _ := url.Parse("http://foo.bar/baz/")
	t.Equal(*expected, kb.GetURL(), "incorrect url")

	u2, _ := url.Parse("http://foo.bar/baz")
	kb2, err := NewKBaseProvider(*u2)
	t.Nil(err, "unexpected error")
	expected2, _ := url.Parse("http://foo.bar/baz/")
	t.Equal(*expected2, kb2.GetURL(), "incorrect url")
}

func (t *TestSuite) TestConstructFailBadArgs() {
	u, _ := url.Parse("foo.bar")
	kb, err := NewKBaseProvider(*u)
	t.Nil(kb, "expected error")
	t.Equal(errors.New("url must be absolute"), err, "incorrect error")

	u, _ = url.Parse("http://foo.bar")
	kb, err = NewKBaseProvider(*u, AdminRole("   \t   \n  "))
	t.Nil(kb, "expected error")
	t.Equal(errors.New("role cannot be empty or whitespace only"), err, "incorrect error")
}

type tgu struct {
	Token      string
	AdminRoles *[]string
	UserName   string
	IsAdmin    bool
}

func (t *TestSuite) TestGetUser() {

	testcases := []tgu{
		tgu{t.tokenNoRole, &[]string{}, "noroles", false},
		tgu{t.tokenNoRole, &[]string{blobstoreRole, adminRole}, "noroles", false},

		tgu{t.tokenStdRole, &[]string{}, "admin_std_role", false},
		tgu{t.tokenStdRole, &[]string{"foo"}, "admin_std_role", false},
		tgu{t.tokenStdRole, &[]string{adminRole}, "admin_std_role", false},
		tgu{t.tokenStdRole, &[]string{blobstoreRole, adminRole}, "admin_std_role", true},

		tgu{t.tokenKBaseAdmin, &[]string{blobstoreRole}, "admin_kbase", false},
		tgu{t.tokenKBaseAdmin, &[]string{blobstoreRole, adminRole}, "admin_kbase", true},
	}

	for _, tc := range testcases {
		t.checkUser(&tc)
	}
}

func (t *TestSuite) checkUser(tc *tgu) {
	opts := []func(*KBaseProvider) error{}
	for _, r := range *tc.AdminRoles {
		opts = append(opts, AdminRole(r))
	}

	kb, err := NewKBaseProvider(*t.authURL, opts...)
	t.Nil(err, "unexpected error")
	u, expires, cachefor, err := kb.GetUser(logrus.WithField("a", "b"), tc.Token)
	t.Nil(err, "unexpected error")
	expected := User{tc.UserName, tc.IsAdmin}
	t.Equal(&expected, u, "incorrect user")
	// testing against a local authserver, so checking more or less exact values is ok
	t.Equal(5*60*1000, cachefor, "incorrect cachefor")
	// test tokens expire in 1 hour
	expectedtime := (time.Now().UnixNano() / 1000000) + 60*60*1000
	t.True(expectedtime+1000 > expires, fmt.Sprintf(
		"expire time (%v) too large vs. expected (%v)", expires, expectedtime))
	t.True(expectedtime-1000 < expires, fmt.Sprintf(
		"expire time (%v) too small vs. expected (%v)", expires, expectedtime))
	t.Equal(0, len(t.loggerhook.AllEntries()), "unexpected logging")
}

func (t *TestSuite) TestGetUserFailBadInput() {
	tc := map[string]error{
		"   \t    \n   ": errors.New("token cannot be empty or whitespace only"),
		"no such token":  NewInvalidTokenError("KBase auth server reported token was invalid"),
	}
	kb, err := NewKBaseProvider(*t.authURL)
	t.Nil(err, "unexpected error")

	u, expires, cachefor, err := kb.GetUser(nil, "t")
	t.Nil(u, "expected error")
	t.Equal(errors.New("logger cannot be nil"), err, "incorrect error")
	t.Equal(int64(-1), expires, "incorrect expires")
	t.Equal(-1, cachefor, "incorrect cachefore")

	for token, expectederr := range tc {
		u, expires, cachefor, err := kb.GetUser(logrus.WithField("a", "b"), token)
		t.Nil(u, "expected error")
		t.Equal(expectederr, err, "incorrect error")
		t.Equal(int64(-1), expires, "incorrect expires")
		t.Equal(-1, cachefor, "incorrect cachefore")
	}
	t.Equal(0, len(t.loggerhook.AllEntries()), "unexpected logging")
}

func (t *TestSuite) TestGetUserFailBadURL() {
	// this test goes against outside resources and so is delicate
	type testcase struct {
		url      string
		errstr   string
		contents []string
		bodylen  int
	}
	testcases := []testcase{
		testcase{
			"https://httpbin.org/status/404",
			"kbase auth: Non-JSON response from KBase auth server, status code: 404",
			[]string{
				"<!DOCTYPE HTML",
				"<title>404 Not Found</title>",
				"<p>The requested URL was not found on the server.",
			},
			233,
		},
		testcase{
			"https://en.wikipedia.org/wiki/1944_Birthday_Honours",
			"kbase auth: Unexpectedly long body from auth service",
			[]string{
				"<!DOCTYPE html>",
				"<head>",
				"<title>1944 Birthday Honours/api/V2/token - Wikipedia</title>",
				"February",
			},
			1000,
		},
	}
	for _, tc := range testcases {
		urp, _ := url.Parse(tc.url)
		kb, err := NewKBaseProvider(*urp)
		t.Nil(err, "unexpected error")
		u, expires, cachefor, err := kb.GetUser(logrus.WithField("a", "b"), "fake")
		t.Nil(u, "expected error")
		t.Equal(errors.New(tc.errstr), err, "incorrect error")
		t.Equal(int64(-1), expires, "incorrect expires")
		t.Equal(-1, cachefor, "incorrect cachefore")

		t.Equal(1, len(t.loggerhook.AllEntries()), "incorrect log event count")
		le := t.loggerhook.AllEntries()[0]
		t.Equal(tc.errstr, le.Message)
		t.Equal(logrus.ErrorLevel, le.Level, "incorrect level")
		t.Equal("b", le.Data["a"], "incorrect field")
		t.Equal(tc.bodylen, len(le.Data["truncated_response_body"].(string)),
			"incorrect body length")
		
		fmt.Println("------")
		fmt.Println(le.Data["truncated_response_body"])
		fmt.Println("------")
		for _, c := range tc.contents {
			fmt.Println(le.Data["truncated_response_body"])
			t.Contains(le.Data["truncated_response_body"], c, "incorrect body")
		}
		t.loggerhook.Reset()
	}
}

func (t *TestSuite) TestValidateUserName() {
	tc := [][]string{
		[]string{"   noroles  "},
		[]string{"   noroles  ", "  \t   admin_std_role  \n", "  abc_123   \n"},
	}
	kb, err := NewKBaseProvider(*t.authURL)
	t.Nil(err, "unexpected error")

	for _, names := range tc {
		cachefor, err := kb.ValidateUserNames(logrus.WithField("a", "b"), &names, t.tokenNoRole)
		t.Nil(err, "unexpected error")
		t.Equal(30*60*1000, cachefor, "incorrect cachefor")
	}
	t.Equal(0, len(t.loggerhook.AllEntries()), "unexpected logging")
}

func (t *TestSuite) TestValidateUserNamesBadNameInput() {
	type tvun struct {
		names *[]string
		err   error
	}

	tc := []tvun{
		tvun{nil, errors.New("userNames cannot be nil or empty")},
		tvun{&[]string{}, errors.New("userNames cannot be nil or empty")},
		tvun{&[]string{"user", "  \t \n  "},
			errors.New("names in userNames array cannot be empty or whitespace only")},
		tvun{&[]string{"noroles", "   foo   ", "admin_std_role", "   bar   "},
			&InvalidUserError{&[]string{"foo", "bar"}}},
		tvun{&[]string{"noroles", "   bad*user   ", "admin_std_role", "   bar   ", "0bad"},
			&InvalidUserError{&[]string{"bad*user", "0bad"}}},
	}

	kb, err := NewKBaseProvider(*t.authURL)
	t.Nil(err, "unexpected error")

	cachefor, err := kb.ValidateUserNames(nil, &[]string{"foo"}, "t")
	t.Equal(errors.New("logger cannot be nil"), err, "incorrect error")
	t.Equal(-1, cachefor, "incorrect cachefore")

	for _, tcase := range tc {
		cachefor, err := kb.ValidateUserNames(
			logrus.WithField("a", "b"), tcase.names, t.tokenNoRole)
		t.Equal(tcase.err, err, "incorrect error")
		t.Equal(-1, cachefor, "incorrect cachefor")
	}
	t.Equal(0, len(t.loggerhook.AllEntries()), "unexpected logging")
}

func (t *TestSuite) TestValidateUserNameFailBadToken() {
	tc := map[string]error{
		"   \t    \n   ": errors.New("token cannot be empty or whitespace only"),
		"no such token":  NewInvalidTokenError("KBase auth server reported token was invalid"),
	}

	kb, err := NewKBaseProvider(*t.authURL)
	t.Nil(err, "unexpected error")

	for token, expectederr := range tc {
		cachefor, err := kb.ValidateUserNames(
			logrus.WithField("a", "b"), &[]string{"noroles"}, token)
		t.Equal(expectederr, err, "incorrect error")
		t.Equal(-1, cachefor, "incorrect cachefor")
	}
	t.Equal(0, len(t.loggerhook.AllEntries()), "unexpected logging")
}

func (t *TestSuite) TestValidateUserNameFailBadURL() {
	// this test goes against outside resources and so is delicate
	type testcase struct {
		url      string
		errstr   string
		contents []string
		bodylen  int
	}
	testcases := []testcase{
		testcase{
			"https://httpbin.org/status/404",
			"kbase auth: Non-JSON response from KBase auth server, status code: 404",
			[]string{
				"<!DOCTYPE HTML",
				"<title>404 Not Found</title>",
				"<p>The requested URL was not found on the server.",
			},
			233,
		},
		testcase{
			"https://en.wikipedia.org/wiki/1944_Birthday_Honours",
			"kbase auth: Unexpectedly long body from auth service",
			[]string{
				"<!DOCTYPE html>",
				"<head>",
				"<title>1944 Birthday Honours/api/V2/users - Wikipedia</title>",
				"February",
			},
			1000,
		},
	}
	for _, tc := range testcases {
		urp, _ := url.Parse(tc.url)
		kb, err := NewKBaseProvider(*urp)
		t.Nil(err, "unexpected error")
		cachefor, err := kb.ValidateUserNames(
			logrus.WithField("a", "b"), &[]string{"noroles"}, "fake")
		t.Equal(errors.New(tc.errstr), err, "incorrect error")
		t.Equal(-1, cachefor, "incorrect cachefor")

		t.Equal(1, len(t.loggerhook.AllEntries()), "incorrect log event count")
		le := t.loggerhook.AllEntries()[0]
		t.Equal(tc.errstr, le.Message)
		t.Equal(logrus.ErrorLevel, le.Level, "incorrect level")
		t.Equal("b", le.Data["a"], "incorrect field")
		t.Equal(tc.bodylen, len(le.Data["truncated_response_body"].(string)),
			"incorrect body length")
		for _, c := range tc.contents {
			t.Contains(le.Data["truncated_response_body"], c, "incorrect body")
		}
		t.loggerhook.Reset()
	}
}
