package nodestore

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// TODO INPUT may need limits for strings.

// User is a user that may own or read Nodes.
type User struct {
	id          uuid.UUID
	accountName string
}

// NewUser creates a new user. The ID is a UUID assigned to the user by the system at first sight,
// and accountName is the name of the user in external systems.
func NewUser(id uuid.UUID, accountName string) (*User, error) {
	accountName = strings.TrimSpace(accountName)
	if accountName == "" {
		return nil, errors.New("accountName cannot be empty or whitespace only")
	}
	return &User{id, accountName}, nil
}

// GetID returns the user's system ID.
func (u *User) GetID() uuid.UUID {
	return u.id
}

// GetAccountName returns the user's name in external systems.
func (u *User) GetAccountName() string {
	return u.accountName
}

// Node is a collection of data about a file, including ACLs.
type Node struct {
	id       uuid.UUID
	owner    User
	readers  *[]User
	filename string
	format   string
	size     int64
	md5      string
	stored   time.Time
	public   bool
}

// Format provides an arbitrary file format (e.g. json, txt) to the NewStoreFileParams() method.
func Format(format string) func(*Node) error {
	return func(n *Node) error {
		n.format = strings.TrimSpace(format)
		return nil
	}
}

// FileName provides an arbitrary file name to the NewStoreFileParams() method.
func FileName(filename string) func(*Node) error {
	return func(n *Node) error {
		n.filename = strings.TrimSpace(filename)
		return nil
	}
}

// Reader adds a user to the node's read ACL.
func Reader(user User) func(*Node) error {
	return func(n *Node) error {
		r := append(*n.readers, user)
		n.readers = &r
		return nil
	}
}

// Public sets the node to publicly readable or not.
func Public(public bool) func(*Node) error {
	return func(n *Node) error {
		n.public = public
		return nil
	}
}

// NewNode creates a new node. The owner is automatically added to the reader list.
func NewNode(
	id uuid.UUID,
	owner User,
	size int64,
	md5 string,
	stored time.Time,
	options ...func(*Node) error) (*Node, error) {

	if size < 1 {
		return nil, errors.New("size must be > 0")
	}
	//TODO INPUT check valid MD5
	r := []User{}
	n := &Node{id: id, owner: owner, size: size, md5: md5, stored: stored, readers: &r}

	for _, option := range options {
		option(n) // currently no option funcs return nil
		// add this back in if that changes
		// err := option(p)
		// if err != nil {
		// 	return nil, err
		// }
	}
	rclean := []User{owner}
	seen := map[User]struct{}{owner: struct{}{}}
	for _, u := range *n.readers {
		if _, ok := seen[u]; !ok {
			rclean = append(rclean, u)
		}
		seen[u] = struct{}{}
	}
	n.readers = &rclean
	return n, nil
}

// GetID returns the node's ID.
func (n *Node) GetID() uuid.UUID {
	return n.id
}

// GetOwner returns the node's owner ID.
func (n *Node) GetOwner() User {
	return n.owner
}

// WithOwner returns a copy of the node with the owner as specified.
// The new owner will also be added to the readers list.
func (n *Node) WithOwner(user User) *Node {
	readers := []User{user}
	for _, r := range *n.readers {
		if r != user {
			readers = append(readers, r)
		}
	}
	return &Node{n.id, user, &readers, n.filename, n.format, n.size, n.md5, n.stored, n.public}

}

// GetSize returns the size of the file associated with the node.
func (n *Node) GetSize() int64 {
	return n.size
}

// GetMD5 returns the MD5 of the file associated with the node.
func (n *Node) GetMD5() string {
	return n.md5
}

// GetStoredTime returns the time the file associated with the node was stored.
func (n *Node) GetStoredTime() time.Time {
	return n.stored
}

// GetFileName gets the name of the file associated with the node, if any.
func (n *Node) GetFileName() string {
	return n.filename
}

// GetFormat gets the format of the file associated with the node, if any.
func (n *Node) GetFormat() string {
	return n.format
}

// GetReaders gets the IDs of users that may read the node.
func (n *Node) GetReaders() *[]User {
	return n.copyReaders()
}

// HasReader returns true if the given user exists in the node's list of readers.
func (n *Node) HasReader(user User) bool {
	for _, r := range *n.readers {
		if r == user {
			return true
		}
	}
	return false
}

// WithReaders returns a copy of the node with the sepecified readers added.
func (n *Node) WithReaders(readers ...User) *Node {
	rdrs := []User{}
	rs := map[User]struct{}{}
	for _, r := range *n.readers {
		rs[r] = struct{}{}
		rdrs = append(rdrs, r)
	}
	for _, r := range readers {
		if _, ok := rs[r]; !ok {
			rdrs = append(rdrs, r)
		}
	}
	return &Node{n.id, n.owner, &rdrs, n.filename, n.format, n.size, n.md5, n.stored, n.public}
}

// WithoutReaders returns a copy of the node without the sepecified readers.
// If any of the readers are the node's owner, they are not removed from the list.
func (n *Node) WithoutReaders(readers ...User) *Node {
	rs := map[User]struct{}{}
	for _, r := range readers {
		rs[r] = struct{}{}
	}
	clean := []User{}
	for _, r := range *n.readers {
		if r == n.owner {
			clean = append(clean, r)
		} else if _, ok := rs[r]; !ok {
			clean = append(clean, r)
		}
	}
	return &Node{n.id, n.owner, &clean, n.filename, n.format, n.size, n.md5, n.stored, n.public}
}

// GetPublic gets whether the node is publicly readable or not.
func (n *Node) GetPublic() bool {
	return n.public
}

func (n *Node) copyReaders() *[]User {
	r := make([]User, len(*n.readers))
	copy(r, *n.readers)
	return &r
}

// WithPublic returns a copy of the node with the public flag set as specified.
func (n *Node) WithPublic(public bool) *Node {
	return &Node{n.id, n.owner, n.copyReaders(), n.filename, n.format, n.size, n.md5, n.stored,
		public}
}

// NoNodeError is returned when a node doesn't exist.
type NoNodeError string

// NewNoNodeError creates a new NoNodeError.
func NewNoNodeError(err string) *NoNodeError {
	e := NoNodeError(err)
	return &e
}

func (e *NoNodeError) Error() string {
	return string(*e)
}

// NodeStore stores node information.
type NodeStore interface {

	// GetUser gets a user. If the user does not exist in the system, a new ID will be assigned
	// to the user.
	GetUser(accountName string) (*User, error)

	// StoreNode stores a node.
	// The caller is responsible for ensuring any users are valid - retrieving users via
	// GetUser() is the proper way to do so.
	// Attempting to store Nodes with the same ID is an error.
	StoreNode(node *Node) error

	// GetNode gets a node. Returns NoNodeError if the node does not exist.
	GetNode(id uuid.UUID) (*Node, error)

	// DeleteNode deletes a node. Returns NoNodeError if the node does not exist.
	DeleteNode(id uuid.UUID) error

	// SetNodePublic sets whether a node can be read by anyone, including anonymous users.
	// Returns NoNodeError if the node does not exist.
	SetNodePublic(id uuid.UUID, public bool) error

	// adding and removing readers one at a time isn't efficient, but that's by far the most
	// common use case so that's all we support for now. Optimize later.

	// AddReader adds a user to a node's read ACL.
	// The caller is responsible for ensuring the user is valid - retrieving the user via
	// GetUser() is the proper way to do so.
	// Has no effect if the user is already in the read ACL.
	// Returns NoNodeError if the node does not exist.
	AddReader(id uuid.UUID, user User) error

	// RemoveReader removes a user from the node's read ACL.
	// Has no effect if the user is not in the read ACL or is the node owner.
	// Returns NoNodeError if the node does not exist.
	RemoveReader(id uuid.UUID, user User) error

	// ChangeOwner changes the owner of a node.
	// The caller is responsible for ensuring the user is valid - retrieving the user via
	// GetUser() is the proper way to do so.
	// Adds the new owner to the the read acl.
	// Setting the new owner to the current owner has no effect.
	// Returns NoNodeError if the node does not exist.
	ChangeOwner(id uuid.UUID, user User) error
}
