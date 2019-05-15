// Package core contains the central code for creating and reading blobs.
package core

import (
	"errors"
	"io"
	"time"

	"github.com/google/uuid"

	"github.com/kbase/blobstore/auth"

	"github.com/kbase/blobstore/filestore"
	"github.com/kbase/blobstore/nodestore"
)

// BlobNode contains basic information about a blob stored in the blobstore.
type BlobNode struct {
	ID       uuid.UUID
	Size     int64
	MD5      string
	Stored   time.Time
	Filename string
	Format   string
}

// might want to move this somewhere else

// UUIDGen is an interface for a type that generates random UUIDs.
type UUIDGen interface {
	// GetUUID generates a random UUID.
	GetUUID() uuid.UUID
}

// UUIDGenDefault generates uuids via the uuid.New() method.
type UUIDGenDefault struct{}

// GetUUID generates a random UUID.
func (u *UUIDGenDefault) GetUUID() uuid.UUID {
	return uuid.New()
}

// BlobStore is the storage system for blobs.
type BlobStore struct {
	fileStore filestore.FileStore
	nodeStore nodestore.NodeStore
	uuidGen   UUIDGen
}

// New creates a new blob store.
func New(filestore filestore.FileStore, nodestore nodestore.NodeStore) *BlobStore {
	return NewWithUUIDGen(filestore, nodestore, &UUIDGenDefault{})
}

// NewWithUUIDGen creates a new blob store with a provided UUID generator, which allows for
// easier testing.
func NewWithUUIDGen(filestore filestore.FileStore, nodestore nodestore.NodeStore, uuidGen UUIDGen,
) *BlobStore {
	return &BlobStore{fileStore: filestore, nodeStore: nodestore, uuidGen: uuidGen}
}

// Store stores a blob. The caller is responsible for closing the reader.
func (bs *BlobStore) Store(
	user auth.User,
	data io.Reader,
	size int64,
	filename string, // TODO OPS make filename and format optional
	format string,
) (*BlobNode, error) {
	if size < 1 {
		return nil, errors.New("size must be > 0")
	}
	uid := bs.uuidGen.GetUUID()

	nodeuser, err := bs.nodeStore.GetUser(user.GetUserName())
	if err != nil {
		return nil, err //TODO ERROR look into error handling here
	}
	p, _ := filestore.NewStoreFileParams(
		uuidToFilePath(uid), size, data, filestore.FileName(filename), filestore.Format(format))
	f, err := bs.fileStore.StoreFile(p)
	if err != nil {
		return nil, err //TODO ERROR look into error handling here
	}
	node, _ := nodestore.NewNode(uid, *nodeuser, size, f.MD5, f.Stored,
		nodestore.FileName(filename), nodestore.Format(format))
	err = bs.nodeStore.StoreNode(node)
	if err != nil {
		return nil, err
		// consider deleting the file here, although errors should be extremely rare
		// since we recently contacted mongo
	}
	return toBlobNode(node), nil
}

func toBlobNode(node *nodestore.Node) *BlobNode {
	return &BlobNode{
		ID:       node.GetID(),
		Size:     node.GetSize(),
		MD5:      node.GetMD5(),
		Stored:   node.GetStoredTime(),
		Filename: node.GetFileName(),
		Format:   node.GetFormat(),
	}
}

func uuidToFilePath(uid uuid.UUID) string {
	uidstr := uid.String()
	return "/" + uidstr[0:2] + "/" + uidstr[2:4] + "/" + uidstr[4:6] + "/" + uidstr
}

// Get gets details about a node.
func (bs *BlobStore) Get(user auth.User, id uuid.UUID) (*BlobNode, error) {
	nodeuser, err := bs.nodeStore.GetUser(user.GetUserName())
	if err != nil {
		return nil, err // TODO ERROR error handling
	}
	node, err := bs.nodeStore.GetNode(id)
	if err != nil {
		return nil, err // TODO ERROR error handling
	}
	if !authok(user, nodeuser, node) {
		return nil, errors.New("Unauthorized") // TODO ERROR error handling
	}
	return toBlobNode(node), nil

}

func authok(user auth.User, nodeuser *nodestore.User, node *nodestore.Node) bool {
	if user.IsAdmin() {
		return true
	}
	if node.GetOwner() == *nodeuser {
		return true
	}
	for _, u := range *node.GetReaders() {
		if u == *nodeuser {
			return true
		}
	}
	return false
}

// GetFile gets the file from a node.
func (bs *BlobStore) GetFile(user auth.User, id uuid.UUID,
) (data io.ReadCloser, size int64, err error) {
	_, err = bs.Get(user, id) // checks auth
	if err != nil {
		return nil, 0, err
	}
	f, err := bs.fileStore.GetFile(uuidToFilePath(id))
	if err != nil {
		return nil, 0, err //TODO ERROR handling
	}
	return f.Data, f.Size, nil
}