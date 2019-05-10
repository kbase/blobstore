package auth

import (
	"errors"
	"net/url"
	"strconv"
	"github.com/kbase/blobstore/test/mongocontroller"
	"github.com/kbase/blobstore/test/kbaseauthcontroller"
	"testing"

	"github.com/kbase/blobstore/test/testhelpers"
	"github.com/stretchr/testify/suite"
)

const (
	blobstoreRole = "BLOBSTORE_ADMIN"
	adminRole = "KBASE_ADMIN"
)

type TestSuite struct {
	suite.Suite
	mongo         *mongocontroller.Controller
	auth          *kbaseauthcontroller.Controller
	authURL *url.URL
	deleteTempDir bool
	tokenNoRole string
	tokenStdRole string
	tokenKBaseAdmin string
}

func (t *TestSuite) SetupSuite() {
	tcfg, err := testhelpers.GetConfig()
	if err != nil {
		t.FailNow(err.Error())
	}

	mongoctl, err := mongocontroller.New(mongocontroller.Params{
		ExecutablePath: tcfg.MongoExePath,
		UseWiredTiger: tcfg.UseWiredTiger,
		RootTempDir: tcfg.TempDir,
	})
	if err != nil {
		t.FailNow(err.Error())
	}
	t.mongo = mongoctl
	
	auth, err := kbaseauthcontroller.New(kbaseauthcontroller.Params{
		JarsDir: tcfg.JarsDir,
		MongoHost: "localhost:" + strconv.Itoa(mongoctl.GetPort()),
		MongoDatabase: "test_kb_auth_provider_authdb",
		RootTempDir: tcfg.TempDir,
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
}

func (t *TestSuite) setUpUsersAndRoles() {
	t.createTestUser("noroles")
	t.createTestUser("admin_std_role")
	t.createTestUser("admin_kbase")

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
	Token string
	AdminRoles *[]string
	UserName string
	IsAdmin bool
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
	u, err := kb.GetUser(tc.Token)
	t.Nil(err, "unexpected error")
	expected := User{tc.UserName, tc.IsAdmin}
	t.Equal(&expected, u, "incorrect user")
}

func (t *TestSuite) TestGetUserFailBadInput() {
	tc := map[string]string{
		"   \t    \n   ": "token cannot be empty or whitespace only",
		"no such token":  "KBase auth server reported token was invalid",
	}
	kb, err := NewKBaseProvider(*t.authURL)
	t.Nil(err, "unexpected error")

	for token, errstr := range tc {
		u, err := kb.GetUser(token)
		t.Nil(u, "expected error")
		t.Equal(errors.New(errstr), err, "incorrect error")
	}
}

func (t *TestSuite) TestGetUserFailBadURL() {
	tc := map[string]string{
		"https://ci.kbase.us/services":
			"Non-JSON response from KBase auth server, status code: 404",
		"https://en.wikipedia.org/wiki/1944_Birthday_Honours":
			"Unexpectedly long body from auth service",
	}
	
	for ur, errstr := range tc {
		urp, _ := url.Parse(ur)
		kb, err := NewKBaseProvider(*urp)
		t.Nil(err, "unexpected error")
		u, err := kb.GetUser("fake")
		t.Nil(u, "expected error")
		t.Equal(errors.New(errstr), err, "incorrect error")
	}
}