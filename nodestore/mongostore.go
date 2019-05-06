package nodestore

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	colUsers     = "users"
	keyUsersUser = "user"
	keyUsersUUID = "id"
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
		return nil, err // hard to test
	}
	return &MongoNodeStore{db: db}, nil
}

func createIndexes(db *mongo.Database) error {
	err := addIndex(db.Collection(colUsers), keyUsersUser, 1, true)
	if err != nil {
		return err // hard to test
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
	fmt.Println(err)
	// TODO check for conflict on account name, if so get normally. If error give up.

	return &User{accountName: accountName, id: uid}, nil
}

func toUser(sr *mongo.SingleResult) (*User, error) {
	var udoc map[string]interface{}
	err := sr.Decode(udoc)
	if err != nil {
		return nil, err
	}
	// err should always be nil unless db is corrupt
	uid, _ := uuid.FromBytes(udoc[keyUsersUUID].([]byte))
	return &User{accountName: udoc[keyUsersUser].(string), id: uid}, nil
}
