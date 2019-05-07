package nodestore

import (
	"go.mongodb.org/mongo-driver/bson"
	"errors"
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

func (t *TestSuite) TestConstructFail() {
	t.failConstruct(nil, errors.New("db cannot be nil"))

	// construct a broken client so the create indexes calls fail. Can only test the 1st call
	// though.
	copts := options.ClientOptions{Hosts: []string{
		"localhost:" + strconv.Itoa(t.mongo.GetPort())}}
	client, _ := mongo.NewClient(&copts)
	t.failConstruct(client.Database(testDB), errors.New("topology is closed"))
}

func (t *TestSuite) failConstruct(client *mongo.Database, expected error) {
	cli, err := NewMongoNodeStore(client)
	t.Nil(cli, "expected nil result")
	t.Equal(expected, err, "incorrect error")
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
	uid := u.GetID()
	t.Equal("myusername", u.GetAccountName(), "incorrect account name")
	u, err = ns.GetUser("   myusername   ")
	if err != nil {
		t.Fail(err.Error())
	}
	// now we can check the UUID is the same
	expected, _ := NewUser(uid, "myusername")
	t.Equal(expected, u, "incorrect user")
}

func (t *TestSuite) TestGetUserFailBadInput() {
	ns, err := NewMongoNodeStore(t.client.Database(testDB))
	if err != nil {
		t.Fail(err.Error())
	}
	u, err := ns.GetUser("  \t \n   ")
	t.Nil(u, "expected nil user")
	t.Equal(errors.New("accountName cannot be empty or whitespace only"), err, "incorrect error")
}

func (t *TestSuite) TestCollectionsAndIndexes() {
	// for some reason that's beyond me the mongo go client returns the collection names and
	// the index names in the same list...
	_, err := NewMongoNodeStore(t.client.Database(testDB))
	if (err != nil) {
		t.Fail(err.Error())
	}
	ctx := context.Background()
	cur, err := t.client.Database(testDB).ListCollections(nil, bson.D{})
	if err != nil {
		t.Fail(err.Error())
	}
	defer cur.Close(ctx)

	names := map[string]struct{}{}
	for cur.Next(ctx) {
		elem := &bson.D{}
		if err := cur.Decode(elem); err != nil {
			t.Fail(err.Error())
		}
		m := elem.Map()
		names[m["name"].(string)] = struct{}{}
	}
	if (cur.Err() != nil) {
		t.Fail(err.Error())
	}
	var expected map[string]struct{}
	if t.mongo.GetIncludesIndexes() {
		e := map[string]struct{}{
			"users": struct{}{},
			"system.indexes": struct{}{},
			"users.$_id_": struct{}{},
			"users.$user_1": struct{}{},
			"users.$id_1": struct{}{},
		}
		expected = e
	} else {
		e := map[string]struct{}{
			"users": struct{}{},
		}
		expected = e
	}
	t.Equal(expected, names, "incorrect collection and index names")
}