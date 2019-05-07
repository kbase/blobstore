package nodestore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/google/uuid"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

//TODO SCHEMA schema version doc

const (
	colUsers              = "users"
	keyUsersUser          = "user"
	keyUsersUUID          = "id"
	colNodes              = "nodes"
	keyNodesID            = "id"
	keyNodesOwner         = "own"
	keyNodesUserID        = "id"
	keyNodesUserName      = "user"
	keyNodesReaders       = "read"
	keyNodesFileName      = "fname"
	keyNodesFormat        = "fmt"
	keyNodesSize          = "size"
	keyNodesMD5           = "md5"
	keyNodesStored        = "time"
	keyNodesPublic        = "pub"
	mongoDuplicateKeyCode = 11000
)

// MongoNodeStore is a storage system for blobstore nodes using Mongo as the underlying database.
type MongoNodeStore struct {
	db *mongo.Database
}

// NewMongoNodeStore creates a new node store given a MongoDB database for storing node data.
func NewMongoNodeStore(db *mongo.Database) (*MongoNodeStore, error) {
	if db == nil {
		return nil, errors.New("db cannot be nil")
	}
	err := createIndexes(db)
	if err != nil {
		return nil, err
	}
	return &MongoNodeStore{db: db}, nil
}

func createIndexes(db *mongo.Database) error {
	err := addIndex(db.Collection(colUsers), keyUsersUser, 1, true)
	if err != nil {
		return err
	}
	err = addIndex(db.Collection(colUsers), keyUsersUUID, 1, true)
	if err != nil {
		return err // hard to test
	}
	err = addIndex(db.Collection(colNodes), keyNodesID, 1, true)
	if err != nil {
		return err // hard to test
	}
	// add more indexes here
	return nil
}

func addIndex(col *mongo.Collection, key string, asc int, unique bool) error {
	idx := col.Indexes()
	mdl := mongo.IndexModel{
		Keys:    map[string]int{key: asc},
		Options: &options.IndexOptions{Unique: &unique}}
	_, err := idx.CreateOne(context.Background(), mdl, nil) // first ret arg is undocumented
	return err
}

// GetUser gets a user. If the user does not exist in the system, a new ID will be assigned to
// the user.
func (s *MongoNodeStore) GetUser(accountName string) (*User, error) {
	accountName = strings.TrimSpace(accountName)
	if accountName == "" {
		return nil, errors.New("accountName cannot be empty or whitespace only")
	}
	// try reading first, since users are only written once and reading is a lot faster
	col := s.db.Collection(colUsers)
	res := col.FindOne(context.Background(), map[string]string{keyUsersUser: accountName})
	if res.Err() != nil {
		return nil, res.Err() // don't know how to test this
	}
	u, err := toUser(res)
	if err != nil {
		return nil, err // don't know how to test this
	}
	if u != nil {
		return u, nil
	}
	return s.createUser(accountName)
}

// we split this method out for readability and so we can test a race condition where
// between the read in GetUser and the InsertOne call here the same user is already inserted
// Consider this method part of GetUser though
func (s *MongoNodeStore) createUser(accountName string) (*User, error) {
	// try creating a new user
	col := s.db.Collection(colUsers)
	uid := uuid.New()
	_, err := col.InsertOne(context.Background(), map[string]string{
		keyUsersUser: accountName,
		keyUsersUUID: uid.String()})
	if err == nil {
		return &User{accountName: accountName, id: uid}, nil
	}
	if isMongoDuplicateKey(err) {
		// we assume that a duplicate key error is from the user, not the uuid, since
		// we just created a new uuid. If that's the case we're all good and
		// can just pull the user.
		// Assumes users are never deleted, which they shouldn't be.
		res := col.FindOne(nil, map[string]string{keyUsersUser: accountName})
		if res.Err() != nil {
			// ok, give up. Dunno how to test this either.
			return nil, res.Err()
		}
		return toUser(res)
	}
	return nil, err // dunno how to test
}

// returns true if the error has one WriteError, has no WriteConcernError, and the
// WriteError is a Duplicate Key error.
func isMongoDuplicateKey(err error) bool {
	wex, ok := err.(mongo.WriteException)
	if !ok {
		return false // not sure how to test this
	}
	if wex.WriteConcernError != nil {
		return false // or this
	}
	if len(wex.WriteErrors) > 1 {
		return false //or this
	}
	if wex.WriteErrors[0].Code != mongoDuplicateKeyCode {
		return false // or this
	}
	return true
}

func toUser(sr *mongo.SingleResult) (*User, error) {
	var udoc map[string]interface{}
	err := sr.Decode(&udoc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, err // dunno how to test this either
	}
	// err should always be nil unless db is corrupt
	uid, _ := uuid.Parse(udoc[keyUsersUUID].(string))
	return &User{accountName: udoc[keyUsersUser].(string), id: uid}, nil
}

// StoreNode stores a node.
// Attempting to store Nodes with the same ID is an error.
func (s *MongoNodeStore) StoreNode(node *Node) error {
	if node == nil {
		return errors.New("Node cannot be nil")
	}
	readers := []map[string]string{}
	nodemap := map[string]interface{}{
		keyNodesID: node.id.String(),
		keyNodesOwner: map[string]interface{}{
			keyNodesUserID:   node.owner.id.String(),
			keyNodesUserName: node.owner.accountName},
		keyNodesFileName: node.filename,
		keyNodesFormat:   node.format,
		keyNodesMD5:      node.md5,
		keyNodesPublic:   node.public,
		keyNodesSize:     node.size,
		keyNodesStored:   node.stored,
	}
	for _, u := range *node.readers {
		readers = append(readers, map[string]string{
			keyNodesUserID:   u.id.String(),
			keyNodesUserName: u.accountName})
	}
	nodemap[keyNodesReaders] = readers
	_, err := s.db.Collection(colNodes).InsertOne(nil, nodemap)
	if err != nil {
		if isMongoDuplicateKey(err) {
			return fmt.Errorf("Node %v already exists", node.id.String())
		}
		return err // not sure how to test
	}
	return nil
}

// GetNode gets a node.
func (s *MongoNodeStore) GetNode(id uuid.UUID) (*Node, error) {
	res := s.db.Collection(colNodes).FindOne(nil, map[string]string{keyNodesID: id.String()})
	if res.Err() != nil {
		return nil, res.Err() // don't know how to test this
	}
	var ndoc map[string]interface{}
	err := res.Decode(&ndoc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			// TODO ERROR match shock error and add error code
			return nil, fmt.Errorf("No such node %v", id.String())
		}
		return nil, err // dunno how to test this either
	}
	opts := []func(*Node) error{}
	opts = append(opts, Format(ndoc[keyNodesFormat].(string)))
	opts = append(opts, FileName(ndoc[keyNodesFileName].(string)))
	opts = append(opts, Public(ndoc[keyNodesPublic].(bool)))
	// I feel like I'm doing something wrong here, this seems nuts
	for _, uinter := range []interface{}(ndoc[keyNodesReaders].(primitive.A)) {
		u := uinter.(map[string]interface{})
		uid, _ := uuid.Parse(u[keyNodesUserID].(string))    // err must be nil unless db is corrupt
		nu, _ := NewUser(uid, u[keyNodesUserName].(string)) // same
		opts = append(opts, Reader(*nu))
	}
	nid, _ := uuid.Parse(ndoc[keyNodesID].(string)) // err should always be nil unles db is corrupt
	odoc := ndoc[keyNodesOwner].(map[string]interface{})
	oid, _ := uuid.Parse(odoc[keyNodesUserID].(string)) // err must be nil unles db is corrupt
	owner, _ := NewUser(oid, odoc[keyNodesUserName].(string))
	return NewNode(
		nid,
		*owner,
		ndoc[keyNodesSize].(int64),
		ndoc[keyNodesMD5].(string),
		toTime(ndoc[keyNodesStored].(primitive.DateTime)),
		opts...,
	)
}

// go driver 1.1.0 will have a DateTime.Time() method, this is copied from the prerelease code
// https://github.com/mongodb/mongo-go-driver/blob/229a9c94a4735eccfc431ea183e0942de7569f58/bson/primitive/primitive.go#L45
func toTime(d primitive.DateTime) time.Time {
	return time.Unix(int64(d)/1000, int64(d)%1000*1000000)
}
