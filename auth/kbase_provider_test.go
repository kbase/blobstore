package auth

import (
	"fmt"
	"net/url"
	"strconv"
	"github.com/kbase/blobstore/test/mongocontroller"
	"github.com/kbase/blobstore/test/kbaseauthcontroller"
	"testing"

	"github.com/kbase/blobstore/test/testhelpers"
	"github.com/stretchr/testify/suite"
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
	t.createTestUser("notadmin")
	t.createTestUser("admin_std_role")
	t.createTestUser("admin_kbase")

	t.tokenNoRole = t.createTestToken("notadmin")
	t.tokenStdRole = t.createTestToken("admin_std_role")
	t.tokenKBaseAdmin = t.createTestToken("admin_kbase")

	t.createTestRole("SOME_MEANINGLESS_ROLE")
	t.createTestRole("BLOBSTORE_ADMIN")
	t.createTestRole("KBASE_ADMIN")

	t.addTestRole("notadmin", "SOME_MEANINGLESS_ROLE")
	t.addTestRole("admin_std_role", "BLOBSTORE_ADMIN")
	t.addTestRole("admin_kbase", "KBASE_ADMIN")
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

func (t *TestSuite) TestGetUserNoRoles() {
	kb, err := NewKBaseProvider(*t.authURL, "faketoken")
	t.Nil(err, "unexpected error")
	u, err := kb.GetUser("sometoken")
	t.Nil(err, "unexpected error")
	//TODO NOW complete test
	fmt.Printf("%v\n", u)
}