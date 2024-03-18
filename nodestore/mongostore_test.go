package nodestore

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kbase/blobstore/core/values"
	"github.com/kbase/blobstore/test/mongocontroller"
	"github.com/kbase/blobstore/test/testhelpers"
	"github.com/stretchr/testify/suite"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	testDB = "test_mongostore"
)

type TestSuite struct {
	suite.Suite
	mongo         *mongocontroller.Controller
	deleteTempDir bool
	client        *mongo.Client
}

func (t *TestSuite) SetupSuite() {
	tcfg, err := testhelpers.GetConfig()
	if err != nil {
		t.Fail(err.Error())
	}

	mongoctl, err := mongocontroller.New(mongocontroller.Params{
		ExecutablePath: tcfg.MongoExePath,
		UseWiredTiger:  tcfg.UseWiredTiger,
		RootTempDir:    tcfg.TempDir,
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
	t.failConstruct(client.Database(testDB), errors.New("mongo create index: topology is closed"))
}

func (t *TestSuite) TestConstructFailAddConfigIndex() {
	col := t.client.Database(testDB).Collection("config")
	_, err := col.InsertOne(nil, map[string]interface{}{"schema": "schema"})
	t.Nil(err, "unexpected error")
	_, err = col.InsertOne(nil, map[string]interface{}{"schema": "schema"})
	t.Nil(err, "unexpected error")

	cli, err := NewMongoNodeStore(t.client.Database(testDB))
	t.Nil(cli, "expected nil result")
	// error strings are different for different versions, but have common sub strings
	t.Contains(err.Error(), "mongo create index", "incorrect error")
	t.Contains(err.Error(), "E11000 duplicate key error", "incorrect error")
	t.Contains(err.Error(), testDB+".config", "incorrect error")
	t.Contains(err.Error(), "schema_1", "incorrect error")
	t.Contains(err.Error(), "dup key: { ", "incorrect error")
	t.Contains(err.Error(), ": \"schema\" }", "incorrect error")
}

func (t *TestSuite) TestConstructFailTwoConfigDocs() {
	col := t.client.Database(testDB).Collection("config")
	_, err := col.InsertOne(nil, map[string]interface{}{"schema": "schema"})
	t.Nil(err, "unexpected error")
	_, err = col.InsertOne(nil, map[string]interface{}{"schema": "schema1"})
	t.Nil(err, "unexpected error")

	e := "Multiple config documents found in the mongo database. Something is very wrong"
	t.failConstruct(t.client.Database(testDB), errors.New(e))
}

func (t *TestSuite) TestConstructFailBadSchemaVer() {
	col := t.client.Database(testDB).Collection("config")
	_, err := col.InsertOne(nil, map[string]interface{}{
		"schema":    "schema",
		"inupdate":  false,
		"schemaver": 82})
	t.Nil(err, "unexpected error")

	e := "Incompatible mongo database schema. Server is 1, DB is 82"
	t.failConstruct(t.client.Database(testDB), errors.New(e))
}

func (t *TestSuite) TestConstructFailInUpdate() {
	col := t.client.Database(testDB).Collection("config")
	_, err := col.InsertOne(nil, map[string]interface{}{
		"schema":    "schema",
		"inupdate":  true,
		"schemaver": 1})
	t.Nil(err, "unexpected error")

	e := "The database is in the middle of an update from v1 of the schema. Aborting startup."
	t.failConstruct(t.client.Database(testDB), errors.New(e))
}
func (t *TestSuite) failConstruct(db *mongo.Database, expected error) {
	cli, err := NewMongoNodeStore(db)
	t.Nil(cli, "expected nil result")
	t.Equal(expected, err, "incorrect error")
}

func (t *TestSuite) TestConstructWithPreexistingSchemaDoc() {
	col := t.client.Database(testDB).Collection("config")
	_, err := col.InsertOne(nil, map[string]interface{}{
		"schema":    "schema",
		"inupdate":  false,
		"schemaver": 1})
	t.Nil(err, "unexpected error")
	cli, err := NewMongoNodeStore(t.client.Database(testDB))
	t.Nil(err, "unexpected error")
	t.NotNil(cli, "expected non-nil client") // going to test using the client later
}

func (t *TestSuite) TestConstructStartTwice() {
	// check that the created schema doc is ok
	cli, err := NewMongoNodeStore(t.client.Database(testDB))
	t.Nil(err, "unexpected error")
	t.NotNil(cli, "expected non-nil client")

	cli, err = NewMongoNodeStore(t.client.Database(testDB))
	t.Nil(err, "unexpected error")
	t.NotNil(cli, "expected non-nil client") // going to test using the client later
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
	err   error
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
			err:   errors.New("some error"),
			isDup: false},
		mDup{
			err: mongo.WriteException{
				WriteConcernError: &mongo.WriteConcernError{Code: 1},
				WriteErrors:       []mongo.WriteError{mongo.WriteError{Code: 11000}},
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

func (t *TestSuite) TestStoreAndGetNodeMinimal() {
	mns, err := NewMongoNodeStore(t.client.Database(testDB))
	if err != nil {
		t.Fail(err.Error())
	}
	nid := uuid.New()
	oid := uuid.New()
	own, _ := NewUser(oid, "owner")
	tme := time.Now()
	md5, _ := values.NewMD5("1b9554867d35f0d59e4705f6b2712cd1")
	n, _ := NewNode(nid, *own, 78, *md5, tme)
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
	nexpected, _ := NewNode(nid, *own, 78, *md5, ngot.GetStoredTime())
	t.Equal(nexpected, ngot, "incorrect node")
}

func (t *TestSuite) TestStoreAndGetNodeMaximal() {
	mns, err := NewMongoNodeStore(t.client.Database(testDB))
	if err != nil {
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
	md5, _ := values.NewMD5("1b9554867d35f0d59e4705f6b2712cd1")
	n, _ := NewNode(
		nid,
		*own,
		78,
		*md5,
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
		*md5,
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
	if err != nil {
		t.Fail(err.Error())
	}
	err = mns.StoreNode(nil)
	t.Equal(errors.New("Node cannot be nil"), err, "incorrect err")
}

func (t *TestSuite) TestStoreNodeFailWithSameID() {
	mns, err := NewMongoNodeStore(t.client.Database(testDB))
	if err != nil {
		t.Fail(err.Error())
	}
	nid := uuid.New()
	oid := uuid.New()
	own, _ := NewUser(oid, "owner")
	tme := time.Now()
	md5, _ := values.NewMD5("1b9554867d35f0d59e4705f6b2712cd1")
	n1, _ := NewNode(nid, *own, 78, *md5, tme)
	err = mns.StoreNode(n1)
	if err != nil {
		t.Fail(err.Error())
	}
	n2, _ := NewNode(nid, *own, 82, *md5, time.Now())
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
	md5, _ := values.NewMD5("1b9554867d35f0d59e4705f6b2712cd1")
	n1, _ := NewNode(nid, *own, 78, *md5, tme)
	err = mns.StoreNode(n1)
	t.Nil(err, "expected no error")

	nid2 := uuid.New()
	n2, err := mns.GetNode(nid2)
	t.Nil(n2, "expected nil node")
	t.Equal(NewNoNodeError("No such node "+nid2.String()), err, "incorrect error")
}

func (t *TestSuite) TestDeleteNode() {
	mns, err := NewMongoNodeStore(t.client.Database(testDB))
	t.Nil(err, "expected no error")
	nid := uuid.New()
	own, _ := NewUser(uuid.New(), "owner")
	md5, _ := values.NewMD5("1b9554867d35f0d59e4705f6b2712cd1")
	n, _ := NewNode(nid, *own, 78, *md5, time.Now())
	err = mns.StoreNode(n)
	t.Nil(err, "expected no error")

	err = mns.DeleteNode(nid)
	t.Nil(err, "expected no error")

	n2, err := mns.GetNode(nid)
	t.Nil(n2, "expected nil node")
	t.Equal(NewNoNodeError("No such node "+nid.String()), err, "incorrect error")
}

func (t *TestSuite) TestDeleteNodeFailNoNode() {
	mns, err := NewMongoNodeStore(t.client.Database(testDB))
	t.Nil(err, "expected no error")
	own, _ := NewUser(uuid.New(), "owner")
	md5, _ := values.NewMD5("1b9554867d35f0d59e4705f6b2712cd1")
	n, _ := NewNode(uuid.New(), *own, 78, *md5, time.Now())
	err = mns.StoreNode(n)
	t.Nil(err, "expected no error")

	nid2 := uuid.New()
	err = mns.DeleteNode(nid2)
	t.Equal(NewNoNodeError("No such node "+nid2.String()), err, "incorrect error")
}

func (t *TestSuite) TestSetNodePublic() {
	mns, err := NewMongoNodeStore(t.client.Database(testDB))
	t.Nil(err, "expected no error")
	own, _ := NewUser(uuid.New(), "owner")
	nid := uuid.New()
	md5, _ := values.NewMD5("1b9554867d35f0d59e4705f6b2712cd1")
	n, _ := NewNode(nid, *own, 78, *md5, time.Now())
	err = mns.StoreNode(n)
	t.Nil(err, "expected no error")

	err = mns.SetNodePublic(nid, true)
	t.Nil(err, "expected no error")

	ngot, err := mns.GetNode(nid)
	t.Nil(err, "expected no error")

	nexpected, _ := NewNode(
		nid,
		*own,
		78,
		*md5,
		ngot.GetStoredTime(),
		Public(true),
	)
	t.Equal(nexpected, ngot, "incorrect node")

	err = mns.SetNodePublic(nid, false)
	t.Nil(err, "expected no error")

	ngot, err = mns.GetNode(nid)
	t.Nil(err, "expected no error")

	nexpected, _ = NewNode(
		nid,
		*own,
		78,
		*md5,
		ngot.GetStoredTime(),
		Public(false),
	)
	t.Equal(nexpected, ngot, "incorrect node")
}

func (t *TestSuite) TestSetNodePublicFailNoNode() {
	mns, err := NewMongoNodeStore(t.client.Database(testDB))
	t.Nil(err, "expected no error")
	own, _ := NewUser(uuid.New(), "owner")
	md5, _ := values.NewMD5("1b9554867d35f0d59e4705f6b2712cd1")
	n, _ := NewNode(uuid.New(), *own, 78, *md5, time.Now())
	err = mns.StoreNode(n)
	t.Nil(err, "expected no error")

	nid := uuid.New()
	err = mns.SetNodePublic(nid, true)
	t.Equal(NewNoNodeError("No such node "+nid.String()), err, "incorrect error")
}

func (t *TestSuite) TestAddAndRemoveReader() {
	mns, err := NewMongoNodeStore(t.client.Database(testDB))
	t.Nil(err, "expected no error")
	own, _ := NewUser(uuid.New(), "owner")
	nid := uuid.New()
	md5, _ := values.NewMD5("1b9554867d35f0d59e4705f6b2712cd1")
	n, _ := NewNode(nid, *own, 78, *md5, time.Now())

	err = mns.StoreNode(n)
	t.Nil(err, "expected no error")

	r1, _ := NewUser(uuid.New(), "r1")
	r2, _ := NewUser(uuid.New(), "r2")

	err = mns.AddReader(nid, *r1)
	t.Nil(err, "expected no error")
	node, err := mns.GetNode(nid)
	t.Nil(err, "expected no error")

	tme := node.GetStoredTime()

	expected, _ := NewNode(nid, *own, 78, *md5, tme, Reader(*r1))
	t.Equal(expected, node, "incorrect node")

	err = mns.AddReader(nid, *r2)
	t.Nil(err, "expected no error")
	node, err = mns.GetNode(nid)
	t.Nil(err, "expected no error")

	expected, _ = NewNode(nid, *own, 78, *md5, tme,
		Reader(*r1), Reader(*r2))
	t.Equal(expected, node, "incorrect node")

	err = mns.RemoveReader(nid, *r1)
	t.Nil(err, "expected no error")
	node, err = mns.GetNode(nid)
	t.Nil(err, "expected no error")

	expected, _ = NewNode(nid, *own, 78, *md5, tme, Reader(*r2))
	t.Equal(expected, node, "incorrect node")

	err = mns.RemoveReader(nid, *r2)
	t.Nil(err, "expected no error")
	node, err = mns.GetNode(nid)
	t.Nil(err, "expected no error")

	expected, _ = NewNode(nid, *own, 78, *md5, tme)
	t.Equal(expected, node, "incorrect node")
}

func (t *TestSuite) TestAddOwnerAsReader() {
	// expect no change to the node and no error
	mns, err := NewMongoNodeStore(t.client.Database(testDB))
	t.Nil(err, "expected no error")
	own, _ := NewUser(uuid.New(), "owner")
	nid := uuid.New()
	md5, _ := values.NewMD5("1b9554867d35f0d59e4705f6b2712cd1")
	n, _ := NewNode(nid, *own, 78, *md5, time.Now())

	err = mns.StoreNode(n)
	t.Nil(err, "expected no error")

	err = mns.AddReader(nid, *own)
	t.Nil(err, "expected no error")

	node, err := mns.GetNode(nid)
	t.Nil(err, "expected no error")

	expected, _ := NewNode(nid, *own, 78, *md5, node.GetStoredTime())
	t.Equal(expected, node, "incorrect node")
}

func (t *TestSuite) TestRemoveOwnerAsReader() {
	// expect no change to the node and no error
	mns, err := NewMongoNodeStore(t.client.Database(testDB))
	t.Nil(err, "expected no error")
	own, _ := NewUser(uuid.New(), "owner")
	nid := uuid.New()
	md5, _ := values.NewMD5("1b9554867d35f0d59e4705f6b2712cd1")
	n, _ := NewNode(nid, *own, 78, *md5, time.Now())

	err = mns.StoreNode(n)
	t.Nil(err, "expected no error")

	err = mns.RemoveReader(nid, *own)
	t.Nil(err, "expected no error")

	node, err := mns.GetNode(nid)
	t.Nil(err, "expected no error")

	expected, _ := NewNode(nid, *own, 78, *md5, node.GetStoredTime())
	t.Equal(expected, node, "incorrect node")
}

func (t *TestSuite) TestAddReaderTwice() {
	// expect no change to the node and no error
	mns, err := NewMongoNodeStore(t.client.Database(testDB))
	t.Nil(err, "expected no error")
	own, _ := NewUser(uuid.New(), "owner")
	nid := uuid.New()
	md5, _ := values.NewMD5("1b9554867d35f0d59e4705f6b2712cd1")
	n, _ := NewNode(nid, *own, 78, *md5, time.Now())

	err = mns.StoreNode(n)
	t.Nil(err, "expected no error")

	r, _ := NewUser(uuid.New(), "r")

	err = mns.AddReader(nid, *r)
	t.Nil(err, "expected no error")

	node, err := mns.GetNode(nid)
	expected, _ := NewNode(nid, *own, 78, *md5, node.GetStoredTime(),
		Reader(*r))
	t.Nil(err, "expected no error")
	t.Equal(expected, node, "incorrect node")

	err = mns.AddReader(nid, *r)
	t.Nil(err, "expected no error")

	node, err = mns.GetNode(nid)
	t.Nil(err, "expected no error")
	t.Equal(expected, node, "incorrect node")
}

func (t *TestSuite) TestRemoveNonReader() {
	// expect no change and no error.
	mns, err := NewMongoNodeStore(t.client.Database(testDB))
	t.Nil(err, "expected no error")
	own, _ := NewUser(uuid.New(), "owner")
	r1, _ := NewUser(uuid.New(), "r1")
	nid := uuid.New()
	md5, _ := values.NewMD5("1b9554867d35f0d59e4705f6b2712cd1")
	n, _ := NewNode(nid, *own, 78, *md5, time.Now(), Reader(*r1))

	err = mns.StoreNode(n)
	t.Nil(err, "expected no error")

	r2, _ := NewUser(uuid.New(), "r2")
	r3, _ := NewUser(r1.GetID(), "r3")
	r4, _ := NewUser(uuid.New(), r1.GetAccountName())

	node, err := mns.GetNode(nid)
	t.Nil(err, "expected no error")
	expected, _ := NewNode(nid, *own, 78, *md5, node.GetStoredTime(),
		Reader(*r1))
	t.Equal(expected, node, "incorrect node")

	for _, r := range []User{*r2, *r3, *r4} {
		err = mns.RemoveReader(nid, r)
		t.Nil(err, "expected no error")
		node, err := mns.GetNode(nid)
		t.Nil(err, "expected no error")
		t.Equal(expected, node, "incorrect node")
	}
}

func (t *TestSuite) TestAddReaderFailNoNode() {
	mns, err := NewMongoNodeStore(t.client.Database(testDB))
	t.Nil(err, "expected no error")
	own, _ := NewUser(uuid.New(), "owner")
	md5, _ := values.NewMD5("1b9554867d35f0d59e4705f6b2712cd1")
	n, _ := NewNode(uuid.New(), *own, 78, *md5, time.Now())

	err = mns.StoreNode(n)
	t.Nil(err, "expected no error")

	nid := uuid.New()
	err = mns.AddReader(nid, *own)
	t.Equal(NewNoNodeError("No such node "+nid.String()), err, "incorrect error")
}

func (t *TestSuite) TestRemoveReaderFailNoNode() {
	mns, err := NewMongoNodeStore(t.client.Database(testDB))
	t.Nil(err, "expected no error")
	own, _ := NewUser(uuid.New(), "owner")
	md5, _ := values.NewMD5("1b9554867d35f0d59e4705f6b2712cd1")
	n, _ := NewNode(uuid.New(), *own, 78, *md5, time.Now())

	err = mns.StoreNode(n)
	t.Nil(err, "expected no error")

	nid := uuid.New()
	err = mns.RemoveReader(nid, *own)
	t.Equal(NewNoNodeError("No such node "+nid.String()), err, "incorrect error")
}

func (t *TestSuite) TestChangeOwner() {
	// tests that user is added to the read acl if made owner
	mns, err := NewMongoNodeStore(t.client.Database(testDB))
	t.Nil(err, "expected no error")
	own, _ := NewUser(uuid.New(), "owner")
	newown, _ := NewUser(uuid.New(), "newowner")
	nid := uuid.New()
	md5, _ := values.NewMD5("1b9554867d35f0d59e4705f6b2712cd1")
	n, _ := NewNode(nid, *own, 78, *md5, time.Now())

	err = mns.StoreNode(n)
	t.Nil(err, "expected no error")

	node, err := mns.GetNode(nid)
	t.Nil(err, "expected no error")

	tme := node.GetStoredTime()

	expected, _ := NewNode(nid, *own, 78, *md5, tme)
	t.Equal(expected, node, "incorrect node")

	// test that changing to the current owner has no effect
	err = mns.ChangeOwner(nid, *own)
	node, err = mns.GetNode(nid)
	t.Nil(err, "expected no error")
	t.Equal(expected, node, "incorrect node")

	// actually change the owner
	err = mns.ChangeOwner(nid, *newown)
	t.Nil(err, "expected no error")
	node, err = mns.GetNode(nid)
	t.Nil(err, "expected no error")

	expected, _ = NewNode(nid, *newown, 78, *md5, tme, Reader(*own))
	t.Equal(expected, node, "incorrect node")
}

func (t *TestSuite) TestChangeOwnerFailNoNode() {
	mns, err := NewMongoNodeStore(t.client.Database(testDB))
	t.Nil(err, "expected no error")
	own, _ := NewUser(uuid.New(), "owner")
	md5, _ := values.NewMD5("1b9554867d35f0d59e4705f6b2712cd1")
	n, _ := NewNode(uuid.New(), *own, 78, *md5, time.Now())

	err = mns.StoreNode(n)
	t.Nil(err, "expected no error")

	nid := uuid.New()
	newown, _ := NewUser(uuid.New(), "newowner")
	err = mns.ChangeOwner(nid, *newown)
	t.Equal(NewNoNodeError("No such node "+nid.String()), err, "incorrect error")
}

func (t *TestSuite) TestCollections() {
	// for some reason that's beyond me the mongo go client returns the collection names and
	// the index names in the same list for mongo 2.X...
	_, err := NewMongoNodeStore(t.client.Database(testDB))
	if err != nil {
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
	if cur.Err() != nil {
		t.Fail(err.Error())
	}
	var expected map[string]struct{}
	if t.mongo.GetIncludesIndexes() {
		e := map[string]struct{}{
			"system.indexes":   struct{}{},
			"users":            struct{}{},
			"users.$_id_":      struct{}{},
			"users.$user_1":    struct{}{},
			"users.$id_1":      struct{}{},
			"nodes":            struct{}{},
			"nodes.$_id_":      struct{}{},
			"nodes.$id_1":      struct{}{},
			"config":           struct{}{},
			"config.$_id_":     struct{}{},
			"config.$schema_1": struct{}{},
		}
		expected = e
	} else {
		e := map[string]struct{}{
			"users":  struct{}{},
			"nodes":  struct{}{},
			"config": struct{}{},
		}
		expected = e
	}
	t.Equal(expected, names, "incorrect collection and index names")
}

func (t *TestSuite) TestConfigIndexes() {
	expected := map[string]bool{
		"_id_":     false,
		"schema_1": true,
	}
	t.checkIndexes("config", expected)
}

func (t *TestSuite) TestUserIndexes() {
	expected := map[string]bool{
		"_id_":   false,
		"user_1": true,
		"id_1":   true,
	}
	t.checkIndexes("users", expected)
}

func (t *TestSuite) TestNodeIndexes() {
	expected := map[string]bool{
		"_id_": false,
		"id_1": true,
	}
	t.checkIndexes("nodes", expected)
}

func (t *TestSuite) checkIndexes(
	collection string,
	expectedIndexes map[string]bool) {
	_, err := NewMongoNodeStore(t.client.Database(testDB))
	if err != nil {
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
		if un, ok := m["unique"]; ok {
			names[m["name"].(string)] = un.(bool)
		} else {
			names[m["name"].(string)] = false
		}
	}
	if cur.Err() != nil {
		t.Fail(err.Error())
	}
	t.Equal(expectedIndexes, names, "incorrect indexes")
}
