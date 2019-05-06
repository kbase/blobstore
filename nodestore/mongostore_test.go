package nodestore

import (
	"testing"
	"context"
	"strconv"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo"
	"github.com/kbase/blobstore/test/testhelpers"
	"github.com/kbase/blobstore/test/mongocontroller"
	"github.com/stretchr/testify/suite"
)

const (
	testDB = "test_mongostore"
)

type TestSuite struct {
	suite.Suite
	mongo         *mongocontroller.Controller
	deleteTempDir bool
	client *mongo.Client
}

func (t *TestSuite) SetupSuite() {
	tcfg, err := testhelpers.GetConfig()
	if err != nil {
		t.Fail(err.Error())
	}

	mongoctl, err := mongocontroller.New(mongocontroller.Params{
		ExecutablePath: tcfg.MongoExePath,
		UseWiredTiger: tcfg.UseWiredTiger,
		RootTempDir: tcfg.TempDir,
	})
	if err != nil {
		t.Fail(err.Error())
	}
	t.mongo = mongoctl
	t.deleteTempDir = tcfg.DeleteTempDir
	copts := options.ClientOptions{Hosts: []string{
		"localhost:" + strconv.Itoa(mongoctl.GetPort())}}
	err = copts.Validate()
	if err != nil {
		t.Fail(err.Error())
	}
	client, err := mongo.NewClient(&copts)	
	if err != nil {
		t.Fail(err.Error())
	}
	err = client.Connect(context.Background())
	if err != nil {
		t.Fail(err.Error())
	}
	t.client = client
}

func (t *TestSuite) TearDownSuite() {
	if t.mongo != nil {
		t.mongo.Destroy(t.deleteTempDir)
	}
}

func (t *TestSuite) SetupTest() {
	t.client.Database(testDB).Drop(context.Background())
}

func TestRunSuite(t *testing.T) {
	suite.Run(t, new(TestSuite))
}

func ptr(s string) *string {
	return &s
}

func (t *TestSuite) TestGetUser() {
	ns, err := NewMongoNodeStore(t.client.Database(testDB))
	if err != nil {
		t.Fail(err.Error())
	}
	u, err := ns.GetUser("   myusername   ")
	if err != nil {
		t.Fail(err.Error())
	}
	t.Equal("myusername", u.GetAccountName(), "incorrect account name")
}

//TODO test indexes are correct