package nodestore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"

	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/google/uuid"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

//TODO SCHEMA schema version doc

const (
	colUsers              = "users"
	keyUserUser           = "user"
	keyUserUUID           = "id"
	colNodes              = "nodes"
	keyNodesID            = "id"
	keyNodesOwner         = "own"
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
	err := addIndex(db.Collection(colUsers), keyUserUser, 1, true)
	if err != nil {
		return err
	}
	err = addIndex(db.Collection(colUsers), keyUserUUID, 1, true)
	if err != nil {
		return err // hard to test
	}
	err = addIndex(db.Collection(colNodes), keyNodesID, 1, true)
	if err != nil {
		return err // hard to test
	}
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
	res := col.FindOne(context.Background(), map[string]string{keyUserUser: accountName})
	if res.Err() != nil {
		// don't know how to test this
		return nil, errors.New("mongostore find user: " + res.Err().Error())
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
	_, err := col.InsertOne(context.Background(), toUserDocCreate(uid, accountName))
	if err == nil {
		return &User{accountName: accountName, id: uid}, nil
	}
	if isMongoDuplicateKey(err) {
		// we assume that a duplicate key error is from the user, not the uuid, since
		// we just created a new uuid. If that's the case we're all good and
		// can just pull the user.
		// Assumes users are never deleted, which they shouldn't be.
		res := col.FindOne(nil, map[string]string{keyUserUser: accountName})
		if res.Err() != nil {
			// ok, give up. Dunno how to test this either.
			return nil, errors.New("mongostore find user attempt 2: " + res.Err().Error())
		}
		// assume we found a user here, so returning nil, nil is imposible.
		return toUser(res)
	}
	return nil, errors.New("mongostore create user: " + err.Error()) // dunno how to test
}

// returns true if the error has one WriteError, has no WriteConcernError, and the
// WriteError is a Duplicate Key error.
func isMongoDuplicateKey(err error) bool {
	wex, ok := err.(mongo.WriteException)
	if !ok {
		return false
	}
	if wex.WriteConcernError != nil {
		return false
	}
	if len(wex.WriteErrors) > 1 {
		return false
	}
	if wex.WriteErrors[0].Code != mongoDuplicateKeyCode {
		return false
	}
	return true
}

// returns nil, nil if no result was found
func toUser(sr *mongo.SingleResult) (*User, error) {
	var udoc map[string]interface{}
	err := sr.Decode(&udoc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		// dunno how to test this either
		return nil, errors.New("mongostore user decode: " + err.Error())
	}
	// err should always be nil unless db is corrupt
	uid, _ := uuid.Parse(udoc[keyUserUUID].(string))
	return &User{accountName: udoc[keyUserUser].(string), id: uid}, nil
}

// MUST use these functions to make users, since bson.D is ordered and
// maps are not
// unordered maps make document matching unreliable, since MongoDB take key order into account
// structures would be nicer, but all their fields have to be exported to work
func toUserDoc(user User) bson.D {
	return toUserDocCreate(user.GetID(), user.GetAccountName())
}

func toUserDocCreate(id uuid.UUID, accountName string) bson.D {
	return bson.D{
		{Key: keyUserUUID, Value: id.String()},
		{Key: keyUserUser, Value: accountName},
	}
}

// StoreNode stores a node.
// Attempting to store Nodes with the same ID is an error.
func (s *MongoNodeStore) StoreNode(node *Node) error {
	if node == nil {
		return errors.New("Node cannot be nil")
	}
	readers := []bson.D{}
	nodemap := map[string]interface{}{
		keyNodesID:       node.id.String(),
		keyNodesOwner:    toUserDoc(node.owner),
		keyNodesFileName: node.filename,
		keyNodesFormat:   node.format,
		keyNodesMD5:      node.md5,
		keyNodesPublic:   node.public,
		keyNodesSize:     node.size,
		keyNodesStored:   node.stored,
	}
	for _, u := range *node.readers {
		readers = append(readers, toUserDoc(u))
	}
	nodemap[keyNodesReaders] = readers
	_, err := s.db.Collection(colNodes).InsertOne(nil, nodemap)
	if err != nil {
		if isMongoDuplicateKey(err) {
			return fmt.Errorf("Node %v already exists", node.id.String())
		}
		return errors.New("mongostore store node: " + err.Error()) // not sure how to test
	}
	return nil
}

// GetNode gets a node.
func (s *MongoNodeStore) GetNode(id uuid.UUID) (*Node, error) {
	res := s.db.Collection(colNodes).FindOne(nil, nodeFilter(id))
	if res.Err() != nil {
		// don't know how to test this
		return nil, errors.New("mongostore get node: " + res.Err().Error())
	}
	var ndoc map[string]interface{}
	err := res.Decode(&ndoc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, NewNoNodeError("No such node " + id.String())
		}
		// dunno how to test this either
		return nil, errors.New("mongostore decode node: " + err.Error())
	}
	opts := []func(*Node) error{}
	opts = append(opts, Format(ndoc[keyNodesFormat].(string)))
	opts = append(opts, FileName(ndoc[keyNodesFileName].(string)))
	opts = append(opts, Public(ndoc[keyNodesPublic].(bool)))
	// I feel like I'm doing something wrong here, this seems nuts
	for _, uinter := range []interface{}(ndoc[keyNodesReaders].(primitive.A)) {
		u := uinter.(map[string]interface{})
		uid, _ := uuid.Parse(u[keyUserUUID].(string))  // err must be nil unless db is corrupt
		nu, _ := NewUser(uid, u[keyUserUser].(string)) // same
		opts = append(opts, Reader(*nu))
	}
	nid, _ := uuid.Parse(ndoc[keyNodesID].(string)) // err should always be nil unles db is corrupt
	odoc := ndoc[keyNodesOwner].(map[string]interface{})
	oid, _ := uuid.Parse(odoc[keyUserUUID].(string)) // err must be nil unles db is corrupt
	owner, _ := NewUser(oid, odoc[keyUserUser].(string))
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
	return time.Unix(int64(d)/1000, int64(d)%1000*1000000).UTC()
}

func nodeFilter(id uuid.UUID) map[string]string {
	return map[string]string{keyNodesID: id.String()}
}

// DeleteNode deletes a node.
func (s *MongoNodeStore) DeleteNode(id uuid.UUID) error {
	res, err := s.db.Collection(colNodes).DeleteOne(nil, nodeFilter(id))
	if err != nil {
		return errors.New("mongostore delete node: " + err.Error()) // dunno how to test this
	}
	if res.DeletedCount < 1 {
		return NewNoNodeError("No such node " + id.String())
	}
	return nil
}

// SetNodePublic sets whether a node can be read by anyone, including anonymous users.
// Returns NoNodeError if the node does not exist.
func (s *MongoNodeStore) SetNodePublic(id uuid.UUID, public bool) error {
	update := map[string]interface{}{"$set": map[string]interface{}{keyNodesPublic: public}}
	return s.updateNode(id, update, "set node public")
}

func (s *MongoNodeStore) updateNode(id uuid.UUID, update map[string]interface{}, op string) error {
	res, err := s.db.Collection(colNodes).UpdateOne(nil, nodeFilter(id), update)
	if err != nil {
		return errors.New("mongostore " + op + ": " + err.Error()) // dunno how to test this
	}
	if res.MatchedCount < 1 {
		return NewNoNodeError("No such node " + id.String())
	}
	return nil
}

// AddReader adds a user to a node's read ACL.
// The caller is responsible for ensuring the user is valid - retrieving the user via
// GetUser() is the proper way to do so.
// Has no effect if the user is the node's owner or the user is already in the read ACL.
// Returns NoNodeError if the node does not exist.
func (s *MongoNodeStore) AddReader(id uuid.UUID, user User) error {
	userdoc := toUserDoc(user)
	updatedoc := map[string]interface{}{
		"$addToSet": map[string]interface{}{keyNodesReaders: userdoc},
	}
	filterdoc := map[string]interface{}{
		keyNodesID:    id.String(),
		keyNodesOwner: map[string]interface{}{"$ne": userdoc},
	}

	res, err := s.db.Collection(colNodes).UpdateOne(nil, filterdoc, updatedoc)
	if err != nil {
		return errors.New("mongostore add reader: " + err.Error()) // dunno how to test this
	}
	if res.MatchedCount < 1 {
		c, err := s.db.Collection(colNodes).CountDocuments(nil, nodeFilter(id))
		if err != nil {
			// dunno how to test this
			return errors.New("mongostore set node public count: " + err.Error())
		}
		if c < 1 {
			return NewNoNodeError("No such node " + id.String())
		}
		// otherwise we didn't match becauser the reader is the owner, so shit's cool
	}
	return nil
}

// RemoveReader removes a user from the node's read ACL.
// Has no effect if the user is not in the read ACL.
// Returns NoNodeError if the node does not exist.
func (s *MongoNodeStore) RemoveReader(id uuid.UUID, user User) error {
	updatedoc := map[string]interface{}{
		"$pull": map[string]interface{}{keyNodesReaders: toUserDoc(user)},
	}
	return s.updateNode(id, updatedoc, "remove reader")
}

// ChangeOwner changes the owner of a node.
// The caller is responsible for ensuring the user is valid - retrieving the user via
// GetUser() is the proper way to do so.
// If the new owner is in the read ACL, the new owner will be removed.
// Setting the new owner to the current owner has no effect.
// Returns NoNodeError if the node does not exist.
func (s *MongoNodeStore) ChangeOwner(id uuid.UUID, user User) error {
	userdoc := toUserDoc(user)
	updatedoc := map[string]interface{}{
		"$set":  map[string]interface{}{keyNodesOwner: userdoc},
		"$pull": map[string]interface{}{keyNodesReaders: userdoc},
	}
	return s.updateNode(id, updatedoc, "change owner")

}
