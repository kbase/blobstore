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
	err := t.auth.CreateTestUser("notadmin", "display1")
	if err != nil {
		t.FailNow(err.Error())
	}
	err = t.auth.CreateTestUser("admin_std_role", "display2")
	if err != nil {
		t.FailNow(err.Error())
	}
	err = t.auth.CreateTestUser("admin_kbase", "display3")
	if err != nil {
		t.FailNow(err.Error())
	}

	t.tokenNoRole, err = t.auth.CreateTestToken("notadmin")
	if err != nil {
		t.FailNow(err.Error())
	}
	t.tokenStdRole, err = t.auth.CreateTestToken("admin_std_role")
	if err != nil {
		t.FailNow(err.Error())
	}
	t.tokenKBaseAdmin, err = t.auth.CreateTestToken("admin_kbase")
	if err != nil {
		t.FailNow(err.Error())
	}
	//TODO NOW add roles
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