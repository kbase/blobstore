package nodestore

import (
	"fmt"
	"time"
	"github.com/google/uuid"
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

type mDup struct {
	err error
	isDup bool
}

func (t *TestSuite) TestInternalsCreateUser() {
	// testing internals is often considered naughty
	
	// tests the case where two different concurrent processes are trying to create the same user.
	// P1 reads the user, finds nothing.
	// P2 reads the user, finds nothing.
	// P1 writes the user and returns.
	// P2 writes the user and fails because the user already exists.
	// P2 reads the user and returns.

	ns, err := NewMongoNodeStore(t.client.Database(testDB))
	t.Nil(err, "unexpected error")
	u, err := ns.GetUser("  foo  ")
	t.Equal("foo", u.GetAccountName(), "incorrect account name")
	// normally the next process to call GetUser would just read the foo record.
	// calling createUser() simulates the race condition
	u2, err := ns.createUser("foo")
	t.Equal(u2, u, "incorrect user")
}

func (t *TestSuite) TestInternalsIsMongoDuplicateKey() {
	// testing internals is often considered naughty
	tests := []mDup{
		mDup{
			err: errors.New("some error"),
			isDup: false},
		mDup{
			err: mongo.WriteException{
				WriteConcernError: &mongo.WriteConcernError{Code: 1},
				WriteErrors: []mongo.WriteError{mongo.WriteError{Code: 11000}},
			},
			isDup: false},
		mDup{
			err: mongo.WriteException{WriteErrors: []mongo.WriteError{
				mongo.WriteError{Code: 11000},
				mongo.WriteError{Code: 11000},
				},
			},
			isDup: false},
		mDup{
			err: mongo.WriteException{WriteErrors: []mongo.WriteError{
				mongo.WriteError{Code: 10000},
				},
			},
			isDup: false},
		mDup{
			err: mongo.WriteException{WriteErrors: []mongo.WriteError{
				mongo.WriteError{Code: 11000},
				},
			},
			isDup: true},
	
	}
	for _, d := range tests {
		t.Equal(d.isDup, isMongoDuplicateKey(d.err), "incorrect duplicate detection")
	}
}

func (t *TestSuite) TestCollections() {
	// for some reason that's beyond me the mongo go client returns the collection names and
	// the index names in the same list for mongo 2.X...
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
			"system.indexes": struct{}{},
			"users": struct{}{},
			"users.$_id_": struct{}{},
			"users.$user_1": struct{}{},
			"users.$id_1": struct{}{},
			"nodes": struct{}{},
			"nodes.$_id_": struct{}{},
			"nodes.$id_1": struct{}{},
		}
		expected = e
	} else {
		e := map[string]struct{}{
			"users": struct{}{},
			"nodes": struct{}{},
		}
		expected = e
	}
	t.Equal(expected, names, "incorrect collection and index names")
}

func (t *TestSuite) TestStoreAndGetNodeMinimal() {
	mns, err := NewMongoNodeStore(t.client.Database(testDB))
	if (err != nil) {
		t.Fail(err.Error())
	}
	nid := uuid.New()
	oid := uuid.New()
	own, _ := NewUser(oid, "owner")
	tme := time.Now()
	n, _ := NewNode(nid, *own, 78, "1b9554867d35f0d59e4705f6b2712cd1", tme)
	err = mns.StoreNode(n)
	if err != nil {
		t.Fail(err.Error())
	}
	ngot, err := mns.GetNode(nid)
	if err != nil {
		t.Fail(err.Error())
	}
	// time loses precision when stored in mongo
	testhelpers.AssertWithin1MS(t.T(), tme, ngot.GetStoredTime())
	nexpected, _ := NewNode(nid, *own, 78, "1b9554867d35f0d59e4705f6b2712cd1", ngot.GetStoredTime())
	t.Equal(nexpected, ngot, "incorrect node")
}


func (t *TestSuite) TestStoreAndGetNodeMaximal() {
	mns, err := NewMongoNodeStore(t.client.Database(testDB))
	if (err != nil) {
		t.Fail(err.Error())
	}
	nid := uuid.New()
	oid := uuid.New()
	rid1 := uuid.New()
	rid2 := uuid.New()
	own, _ := NewUser(oid, "owner")
	r1, _ := NewUser(rid1, "reader1")
	r2, _ := NewUser(rid2, "reader2")
	tme := time.Now()
	n, _ := NewNode(
		nid,
		*own,
		78,
		"1b9554867d35f0d59e4705f6b2712cd1",
		tme,
		Format("json"),
		FileName("fn.txt"),
		Public(true),
		Reader(*r1),
		Reader(*r2),
		)
	err = mns.StoreNode(n)
	if err != nil {
		t.Fail(err.Error())
	}
	ngot, err := mns.GetNode(nid)
	if err != nil {
		t.Fail(err.Error())
	}
	// time loses precision when stored in mongo
	testhelpers.AssertWithin1MS(t.T(), tme, ngot.GetStoredTime())
	nexpected, _ := NewNode(
		nid,
		*own,
		78,
		"1b9554867d35f0d59e4705f6b2712cd1",
		ngot.GetStoredTime(),
		Format("json"),
		FileName("fn.txt"),
		Public(true),
		Reader(*r1),
		Reader(*r2),
		)
	t.Equal(nexpected, ngot, "incorrect node")
}

func (t *TestSuite) TestFailStoreNodeFailBadInput() {
	mns, err := NewMongoNodeStore(t.client.Database(testDB))
	if (err != nil) {
		t.Fail(err.Error())
	}
	err = mns.StoreNode(nil)
	t.Equal(errors.New("Node cannot be nil"), err, "incorrect err")
}


func (t *TestSuite) TestStoreNodeFailWithSameID() {
	mns, err := NewMongoNodeStore(t.client.Database(testDB))
	if (err != nil) {
		t.Fail(err.Error())
	}
	nid := uuid.New()
	oid := uuid.New()
	own, _ := NewUser(oid, "owner")
	tme := time.Now()
	n1, _ := NewNode(nid, *own, 78, "1b9554867d35f0d59e4705f6b2712cd1", tme)
	err = mns.StoreNode(n1)
	if err != nil {
		t.Fail(err.Error())
	}
	n2, _ := NewNode(nid, *own, 82, "189e725f4587b679740f0f7783745056", time.Now())
	err = mns.StoreNode(n2)
	t.Equal(fmt.Errorf("Node %v already exists", nid.String()), err, "incorrect error")
}

func (t *TestSuite) TestGetNodeFailNoNode() {
	mns, err := NewMongoNodeStore(t.client.Database(testDB))
	t.Nil(err, "expected no error")
	nid := uuid.New()
	oid := uuid.New()
	own, _ := NewUser(oid, "owner")
	tme := time.Now()
	n1, _ := NewNode(nid, *own, 78, "1b9554867d35f0d59e4705f6b2712cd1", tme)
	err = mns.StoreNode(n1)
	t.Nil(err, "expected no error")

	nid2 := uuid.New()
	n2, err := mns.GetNode(nid2)
	t.Nil(n2, "expected nil node")
	t.Equal(fmt.Errorf("No such node %v", nid2.String()), err, "incorrect error")
}

func (t *TestSuite) TestUserIndexes() {
	expected := map[string]bool{
		"_id_": false,
		"user_1": true,
		"id_1": true,
	}
	t.checkIndexes("users", testDB + ".users", expected)
}

func (t *TestSuite) TestNodeIndexes() {
	expected := map[string]bool{
		"_id_": false,
		"id_1": true,
	}
	t.checkIndexes("nodes", testDB + ".nodes", expected)
}

func (t *TestSuite) checkIndexes(
		collection string,
	 	expectedNamespace string,
	  	expectedIndexes map[string]bool) {
	_, err := NewMongoNodeStore(t.client.Database(testDB))
	if (err != nil) {
		t.Fail(err.Error())
	}
	ctx := context.Background()
	idx := t.client.Database(testDB).Collection(collection).Indexes()
	cur, err := idx.List(ctx)
	if err != nil {
		t.Fail(err.Error())
	}
	defer cur.Close(ctx)
	names := map[string]bool{}
	for cur.Next(ctx) {
		elem := &bson.D{}
		if err := cur.Decode(elem); err != nil {
			t.Fail(err.Error())
		}
		m := elem.Map()
		t.Equal(expectedNamespace, m["ns"], "incorrect name space")
		if un, ok := m["unique"]; ok {
			names[m["name"].(string)] = un.(bool)
		} else {
			names[m["name"].(string)] = false
		}
	}
	if (cur.Err() != nil) {
		t.Fail(err.Error())
	}
	t.Equal(expectedIndexes, names, "incorrect indexes")
}