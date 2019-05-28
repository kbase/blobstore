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

// User is a user that may own or read Nodes.
type User struct {
	// ID is the internal blobstore ID for the user.
	ID uuid.UUID
	// AccountName is the ID of the user in external systems.
	AccountName string
}

// BlobNode contains basic information about a blob stored in the blobstore.
type BlobNode struct {
	ID       uuid.UUID
	Size     int64
	MD5      string
	Stored   time.Time
	Filename string
	Format   string
	Owner    User
	Readers  *[]User
	Public   bool
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

// NoBlobError is returned when a requested blob does not exist.
type NoBlobError string

// NewNoBlobError creates a new NoBlobError.
func NewNoBlobError(err string) *NoBlobError {
	e := NoBlobError(err)
	return &e
}

func (e *NoBlobError) Error() string {
	return string(*e)
}

// UnauthorizedError is returned when a user may not read a blob.
type UnauthorizedError string

// NewUnauthorizedError creates a new UnauthorizedError.
func NewUnauthorizedError(err string) *UnauthorizedError {
	e := UnauthorizedError(err)
	return &e
}

func (e *UnauthorizedError) Error() string {
	return string(*e)
}

// UnauthorizedACLError is returned when a user may not alter a blob's ACLs in the manner
// requested.
type UnauthorizedACLError string

// NewUnauthorizedACLError creates a new UnauthorizedACLError.
func NewUnauthorizedACLError(err string) *UnauthorizedACLError {
	e := UnauthorizedACLError(err)
	return &e
}

func (e *UnauthorizedACLError) Error() string {
	return string(*e)
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
		return nil, err // errors should only occur for unusual situations here
	}
	p, _ := filestore.NewStoreFileParams(
		uuidToFilePath(uid), size, data, filestore.FileName(filename), filestore.Format(format))
	f, err := bs.fileStore.StoreFile(p)
	if err != nil {
		return nil, err // errors should only occur for unusual situations here
	}
	node, _ := nodestore.NewNode(uid, *nodeuser, size, f.MD5, f.Stored,
		nodestore.FileName(filename), nodestore.Format(format))
	err = bs.nodeStore.StoreNode(node)
	if err != nil {
		return nil, err // errors should only occur for unusual situations here
		// consider deleting the file here, although errors should be extremely rare
		// since we recently contacted mongo
	}
	return toBlobNode(node), nil
}

func toBlobNode(node *nodestore.Node) *BlobNode {
	readers := &[]User{}
	for _, u := range *node.GetReaders() {
		*readers = append(*readers, toUser(u))
	}
	return &BlobNode{
		ID:       node.GetID(),
		Size:     node.GetSize(),
		MD5:      node.GetMD5(),
		Stored:   node.GetStoredTime(),
		Filename: node.GetFileName(),
		Format:   node.GetFormat(),
		Owner:    toUser(node.GetOwner()),
		Readers:  readers,
		Public:   node.GetPublic(),
	}
}

func toUser(u nodestore.User) User {
	return User{
		ID:          u.GetID(),
		AccountName: u.GetAccountName(),
	}
}

func uuidToFilePath(uid uuid.UUID) string {
	uidstr := uid.String()
	return "/" + uidstr[0:2] + "/" + uidstr[2:4] + "/" + uidstr[4:6] + "/" + uidstr
}

// Get gets details about a node. Returns NoBlobError and UnauthorizedError.
func (bs *BlobStore) Get(user *auth.User, id uuid.UUID) (*BlobNode, error) {
	node, nodeuser, err := bs.getNode(user, id)
	if err != nil {
		return nil, err
	}
	if !authok(user, nodeuser, node) {
		return nil, NewUnauthorizedError("Unauthorized")
	}
	return toBlobNode(node), nil
}

func (bs *BlobStore) getNode(user *auth.User, id uuid.UUID,
) (*nodestore.Node, *nodestore.User, error) {
	var nodeuser *nodestore.User
	if user != nil {
		var err error
		nodeuser, err = bs.nodeStore.GetUser(user.GetUserName())
		if err != nil {
			return nil, nil, err // errors should only occur for unusual situations here
		}
	}
	node, err := bs.nodeStore.GetNode(id)
	if err != nil {
		return nil, nil, translateError(err)
	}
	return node, nodeuser, nil
}

func translateError(err error) error {
	if _, ok := err.(*nodestore.NoNodeError); ok {
		// seems weird to rewrap, but also seems weird to expose errors in lower api levels
		return NewNoBlobError(err.Error())
	}
	// errors should only occur for unusual situations here
	return err
}

func authok(user *auth.User, nodeuser *nodestore.User, node *nodestore.Node) bool {
	if node.GetPublic() {
		return true
	}
	if user == nil {
		return false
	}
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

// GetFile gets the file from a node. Returns NoBlobError and UnauthorizedError.
func (bs *BlobStore) GetFile(user *auth.User, id uuid.UUID,
) (data io.ReadCloser, size int64, filename string, err error) {
	node, err := bs.Get(user, id) // checks auth
	if err != nil {
		return nil, 0, "", err
	}
	f, err := bs.fileStore.GetFile(uuidToFilePath(id))
	if err != nil {
		// errors should only occur for unusual situations here since we got the node
		return nil, 0, "", err
	}
	return f.Data, f.Size, node.Filename, nil
}

// SetNodePublic sets whether a node can be read by anyone, including anonymous users.
// Returns NoBlobError and UnauthorizedACLError.
func (bs *BlobStore) SetNodePublic(user auth.User, id uuid.UUID, public bool,
) (*BlobNode, error) {
	_, node, err := bs.writeok(user, id, false)
	if err != nil {
		return nil, err
	}
	err = bs.nodeStore.SetNodePublic(id, public)
	if err != nil {
		return nil, translateError(err)
	}
	return toBlobNode(node.WithPublic(public)), nil
}

func (bs *BlobStore) writeok(user auth.User, id uuid.UUID, removeself bool,
) (*nodestore.User, *nodestore.Node, error) {
	node, nodeuser, err := bs.getNode(&user, id)
	if err != nil {
		return nil, nil, err
	}
	if removeself && node.HasReader(*nodeuser) {
		return nodeuser, node, nil
	}
	if node.GetOwner() != *nodeuser && !user.IsAdmin() {
		return nil, nil,
			NewUnauthorizedACLError("Users can only remove themselves from the read ACL")
	}
	return nodeuser, node, nil
}

// AddReaders adds readers to a node.
// Has no effect if the user is the node's owner or the user is already in the read ACL.
// Returns NoBlobError and UnauthorizedACLError.
func (bs *BlobStore) AddReaders(user auth.User, id uuid.UUID, readerAccountNames []string,
) (*BlobNode, error) {
	return bs.alterReaders(user, id, readerAccountNames, true)
}

// RemoveReaders removes readers from a node.
// Has no effect if the user is not already in the read ACL.
// Returns NoBlobError and UnauthorizedACLError.
func (bs *BlobStore) RemoveReaders(user auth.User, id uuid.UUID, readerAccountNames []string,
) (*BlobNode, error) {
	return bs.alterReaders(user, id, readerAccountNames, false)
}

func (bs *BlobStore) alterReaders(
	user auth.User,
	id uuid.UUID,
	readerAccountNames []string,
	add bool,
) (*BlobNode, error) {
	removeself := !add &&
		len(readerAccountNames) == 1 &&
		user.GetUserName() == readerAccountNames[0]
	nodeuser, node, err := bs.writeok(user, id, removeself)
	if err != nil {
		return nil, err
	}
	// errors at this point should be unusual since we've already fetched the node
	readers := []nodestore.User{}
	if removeself {
		readers = append(readers, *nodeuser)
	} else {
		for _, ran := range readerAccountNames {
			u, err := bs.nodeStore.GetUser(ran)
			if err != nil {
				return nil, err // errors should only occur for unusual situations here
			}
			readers = append(readers, *u)
		}
	}
	for _, u := range readers {
		if add {
			err = bs.nodeStore.AddReader(id, u)
		} else {
			err = bs.nodeStore.RemoveReader(id, u)
		}
		if err != nil {
			return nil, translateError(err)
		}
	}
	if add {
		node = node.WithReaders(readers...)
	} else {
		node = node.WithoutReaders(readers...)
	}
	return toBlobNode(node), nil
}

// ChangeOwner changes the owner of a node.
// If the new owner is in the read ACL, the new owner will be removed.
// Setting the new owner to the current owner has no effect.
// Returns NoBlobError and UnauthorizedACLError.
func (bs *BlobStore) ChangeOwner(user auth.User, id uuid.UUID, newowner string,
) (*BlobNode, error) {
	_, node, err := bs.writeok(user, id, false)
	if err != nil {
		return nil, err
	}
	u, err := bs.nodeStore.GetUser(newowner)
	if err != nil {
		return nil, err // errors should only occur for unusual situations here
	}
	if err = bs.nodeStore.ChangeOwner(id, *u); err != nil {
		return nil, translateError(err)
	}
	return toBlobNode(node.WithOwner(*u)), nil
}
