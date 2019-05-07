package nodestore

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

//TODO SCHEMA schema version doc

const (
	colUsers              = "users"
	keyUsersUser          = "user"
	keyUsersUUID          = "id"
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
		return toUser(res)
	}
	// try creating a new user
	uid := uuid.New()
	_, err := col.InsertOne(context.Background(), map[string]string{
		keyUsersUser: accountName,
		keyUsersUUID: uid.String()})
	if err == nil {
		return &User{accountName: accountName, id: uid}, nil
	}
	// this whole block of code is tricky to test. It can only occur if a user with
	// the same user name is inserted by another routine between the read and the write above.
	// Tested manually by commenting out the read.
	if wex, ok := err.(mongo.WriteException); ok {
		if wex.WriteConcernError != nil {
			return nil, err // not sure how to test this
		}
		if len(wex.WriteErrors) > 1 {
			return nil, err // not sure how to test this either
		}
		// we assume that a duplicate key error is from the user, not the uuid, since
		// we just created a new uuid. If that's the case we're all good and
		// can just pull the user.
		if wex.WriteErrors[0].Code == mongoDuplicateKeyCode {
			// this was tested manually
			res := col.FindOne(
				context.Background(),
				map[string]string{keyUsersUser: accountName})
			if res.Err() != nil {
				// ok, give up. Dunno how to test this either.
				return nil, res.Err()
			}
			return toUser(res)
		}
		// otherwise return the error
	}
	return nil, err // dunno how to test
}

func toUser(sr *mongo.SingleResult) (*User, error) {
	var udoc map[string]interface{}
	err := sr.Decode(&udoc)
	if err != nil {
		return nil, err // dunno how to test this either
	}
	// err should always be nil unless db is corrupt
	uid, _ := uuid.Parse(udoc[keyUsersUUID].(string))
	return &User{accountName: udoc[keyUsersUser].(string), id: uid}, nil
}
