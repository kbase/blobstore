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

	readers := []User(nil)
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
		Reader(*r1), Reader(*r2),
		)
	assert.Nil(t, err, "unexpected error")

	readers := []User{*r1, *r2}
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
	readers := []User{*r1}
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

func TestNoNodeError(t *testing.T) {
	e := NewNoNodeError("err")
	assert.Equal(t, "err", e.Error(), "incorrect error")
}
