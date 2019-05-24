package nodestore

import (
	"time"
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/google/uuid"
	"testing"
)

func TestNewUser(t *testing.T) {
	uid := uuid.New()
	u, err := NewUser(uid, "    username     ")
	assert.Nil(t, err, "unexpected error")

	assert.Equal(t, uid, u.GetID(), "incorrect id")
	assert.Equal(t, "username", u.GetAccountName(), "incorrect name")
}

func TestNewUserFailBadInput(t *testing.T) {
	u, err := NewUser(uuid.New(), "   \t   \n  ")
	assert.Nil(t, u, "expected nil object")
	assert.Equal(t, errors.New("accountName cannot be empty or whitespace only"), err)
}

func TestNewNodeMin(t *testing.T) {
	id := uuid.New()
	owner, _ := NewUser(uuid.New(), " owner ")
	tm := time.Now()
	n, err := NewNode(
		id,
		*owner,
		67,
		"1b9554867d35f0d59e4705f6b2712cd1",
		tm,
		)
	assert.Nil(t, err, "unexpected error")

	readers := []User{*owner}
	assert.Equal(t, id, n.GetID(), "incorrect ID")
	assert.Equal(t, *owner, n.GetOwner(), "incorrect owner")
	assert.Equal(t, int64(67), n.GetSize(), "incorrect size")
	assert.Equal(t, "1b9554867d35f0d59e4705f6b2712cd1", n.GetMD5(), "incorrect MD5")
	assert.Equal(t, tm, n.GetStoredTime(), "incorrect store time")
	assert.Equal(t, "", n.GetFormat(), "incorrect format")
	assert.Equal(t, "", n.GetFileName(), "incorrect filename")
	assert.Equal(t, false, n.GetPublic(), "incorrect public")
	assert.Equal(t, &readers, n.GetReaders(), "incorrect readers")
}

func TestNewNodeFull(t *testing.T) {
	id := uuid.New()
	owner, _ := NewUser(uuid.New(), " owner ")
	r1, _ := NewUser(uuid.New(), " r1 ")
	r2, _ := NewUser(uuid.New(), " r2")
	tm := time.Now()
	n, err := NewNode(
		id,
		*owner,
		67,
		"1b9554867d35f0d59e4705f6b2712cd1",
		tm,
		Format("    txt   "),
		FileName("   file.txt   "),
		Public(true),
		Reader(*r1), Reader(*r2), Reader(*r1), Reader(*owner), // test duplicates are removed
		)
	assert.Nil(t, err, "unexpected error")

	readers := []User{*owner, *r1, *r2}
	assert.Equal(t, id, n.GetID(), "incorrect ID")
	assert.Equal(t, *owner, n.GetOwner(), "incorrect owner")
	assert.Equal(t, int64(67), n.GetSize(), "incorrect size")
	assert.Equal(t, "1b9554867d35f0d59e4705f6b2712cd1", n.GetMD5(), "incorrect MD5")
	assert.Equal(t, tm, n.GetStoredTime(), "incorrect store time")
	assert.Equal(t, "txt", n.GetFormat(), "incorrect format")
	assert.Equal(t, "file.txt", n.GetFileName(), "incorrect filename")
	assert.Equal(t, true, n.GetPublic(), "incorrect public")
	assert.Equal(t, &readers, n.GetReaders(), "incorrect readers")
}

func TestNodeImmutable(t *testing.T) {
	owner, _ := NewUser(uuid.New(), " owner ")
	r1, _ := NewUser(uuid.New(), " r1 ")
	r2, _ := NewUser(uuid.New(), " r2")
	n, _ := NewNode(
		uuid.New(),
		*owner,
		67,
		"1b9554867d35f0d59e4705f6b2712cd1",
		time.Now(),
		Reader(*r1),
		)
	
	// this test isn't really failsafe since it's not clear when append returns a new slice
	readers := []User{*owner, *r1}
	_ = append(*n.GetReaders(), *r2)
	assert.Equal(t, &readers, n.GetReaders(), "incorrect readers")
}

func TestNodeBadInput(t *testing.T) {
	owner, _ := NewUser(uuid.New(), " owner ")
	n, err := NewNode(
		uuid.New(),
		*owner,
		0,
		"1b9554867d35f0d59e4705f6b2712cd1",
		time.Now(),
		)
	assert.Nil(t, n, "expected nil object")
	assert.Equal(t, errors.New("size must be > 0"), err, "incorrect error")
}

func TestNodeWithPublic(t *testing.T) {
	owner, _ := NewUser(uuid.New(), " owner ")
	r1, _ := NewUser(uuid.New(), " r1 ")
	tme := time.Now()
	nid := uuid.New()
	n, _ := NewNode(
		nid,
		*owner,
		67,
		"1b9554867d35f0d59e4705f6b2712cd1",
		tme,
		Reader(*r1),
		)

	expected, _ := NewNode(
		nid,
		*owner,
		67,
		"1b9554867d35f0d59e4705f6b2712cd1",
		tme,
		Reader(*r1),
		Public(true),
		)

	assert.Equal(t, expected, n.WithPublic(true), "incorrect node")
	assert.Equal(t, false, n.GetPublic(), "incorrect public") // check orignal node unchanged

	assert.Equal(t, n, n.WithPublic(true).WithPublic(false), "incorrect node")
	assert.Equal(t, false, n.GetPublic(), "incorrect public") // check orignal node unchanged
}

func TestNodeWithOwner(t *testing.T) {
	owner, _ := NewUser(uuid.New(), " owner ")
	newowner, _ := NewUser(uuid.New(), "newowner")
	r1, _ := NewUser(uuid.New(), " r1 ")
	tme := time.Now()
	nid := uuid.New()
	n, _ := NewNode(
		nid,
		*owner,
		67,
		"1b9554867d35f0d59e4705f6b2712cd1",
		tme,
		Reader(*r1),
		)

	expected, _ := NewNode(
		nid,
		*newowner,
		67,
		"1b9554867d35f0d59e4705f6b2712cd1",
		tme,
		Reader(*owner),
		Reader(*r1),
		)

	assert.Equal(t, expected, n.WithOwner(*newowner), "incorrect node")
	// check orignal node unchanged
	assert.Equal(t, *owner, n.GetOwner(), "incorrect owner")
	assert.Equal(t, &[]User{*owner, *r1}, n.GetReaders(), "incorrect readers")

	// test with new owner already in read list
	n2, _ := NewNode(
		nid,
		*owner,
		67,
		"1b9554867d35f0d59e4705f6b2712cd1",
		tme,
		Reader(*r1),
		Reader(*newowner),
		)

	assert.Equal(t, expected, n2.WithOwner(*newowner), "incorrect node")
	// check orignal node unchanged
	assert.Equal(t, *owner, n2.GetOwner(), "incorrect owner")
	assert.Equal(t, &[]User{*owner, *r1, *newowner}, n2.GetReaders(), "incorrect readers")
}

func TestNodeWithReaders(t *testing.T) {
	owner, _ := NewUser(uuid.New(), " owner ")
	r1, _ := NewUser(uuid.New(), " r1 ")
	tme := time.Now()
	nid := uuid.New()
	n, _ := NewNode(
		nid,
		*owner,
		67,
		"1b9554867d35f0d59e4705f6b2712cd1",
		tme,
		Reader(*r1),
		)

	r2, _ := NewUser(uuid.New(), " r2 ")
	r3, _ := NewUser(uuid.New(), " r3 ")

	expected, _ := NewNode(
		nid,
		*owner,
		67,
		"1b9554867d35f0d59e4705f6b2712cd1",
		tme,
		Reader(*r1), Reader(*r2), Reader(*r3),
		)

	n2 := n.WithReaders(*r2, *r1, *owner, *r3)
	assert.Equal(t, expected, n2, "incorrect node")
	assert.Equal(t, &[]User{*owner, *r1, *r2, *r3}, n2.GetReaders(), "incorrect readers")
	// check orignal node unchanged
	assert.Equal(t, &[]User{*owner, *r1}, n.GetReaders(), "incorrect readers")
}

func TestNodeWithoutReaders(t *testing.T) {
	owner, _ := NewUser(uuid.New(), " owner ")
	r1, _ := NewUser(uuid.New(), " r1 ")
	r2, _ := NewUser(uuid.New(), " r2 ")
	r3, _ := NewUser(uuid.New(), " r3 ")
	tme := time.Now()
	nid := uuid.New()
	n, _ := NewNode(
		nid,
		*owner,
		67,
		"1b9554867d35f0d59e4705f6b2712cd1",
		tme,
		Reader(*r1), Reader(*r2), Reader(*r3),
		)


	expected, _ := NewNode(
		nid,
		*owner,
		67,
		"1b9554867d35f0d59e4705f6b2712cd1",
		tme,
		Reader(*r1), Reader(*r3),
		)

		n2 := n.WithoutReaders(*r2, *owner)
		assert.Equal(t, expected, n2, "incorrect node")
		assert.Equal(t, &[]User{*owner, *r1, *r3}, n2.GetReaders(), "incorrect readers")
		// check orignal node unchanged
		assert.Equal(t, &[]User{*owner, *r1, *r2, *r3}, n.GetReaders(), "incorrect readers")
}

func TestNodeHasReader(t *testing.T) {
	owner, _ := NewUser(uuid.New(), " owner ")
	r1, _ := NewUser(uuid.New(), " r1 ")
	r2, _ := NewUser(uuid.New(), " r2 ")
	r3, _ := NewUser(uuid.New(), " r3 ")
	tme := time.Now()
	nid := uuid.New()
	n, _ := NewNode(
		nid,
		*owner,
		67,
		"1b9554867d35f0d59e4705f6b2712cd1",
		tme,
		Reader(*r1), Reader(*r3),
		)

	assert.Equal(t, true, n.HasReader(*owner), "incorrect has reader")
	assert.Equal(t, true, n.HasReader(*r1), "incorrect has reader")
	assert.Equal(t, false, n.HasReader(*r2), "incorrect has reader")
	assert.Equal(t, true, n.HasReader(*r3), "incorrect has reader")
}

func TestNoNodeError(t *testing.T) {
	e := NewNoNodeError("err")
	assert.Equal(t, "err", e.Error(), "incorrect error")
}
