package core

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"time"
	"github.com/kbase/blobstore/filestore"
	"github.com/kbase/blobstore/nodestore"
	"github.com/kbase/blobstore/auth"
	"strings"
	"github.com/google/uuid"
	nsmocks "github.com/kbase/blobstore/nodestore/mocks"
	fsmocks "github.com/kbase/blobstore/filestore/mocks"
	cmocks "github.com/kbase/blobstore/core/mocks"
	"testing"
)

func TestStoreBasic(t *testing.T) {
	uidmock := new(cmocks.UUIDGen)
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := NewWithUUIDGen(fsmock, nsmock, uidmock)

	uid, _ := uuid.Parse("4122a860-ce69-45cc-9d5d-3d2585fbfd74")
	userid := uuid.New()
	nuser, _ := nodestore.NewUser(userid, "username")

	uidmock.On("GetUUID").Return(uid)
	nsmock.On("GetUser", "username").Return(nuser, nil)

	p, _ := filestore.NewStoreFileParams(
		"/41/22/a8/4122a860-ce69-45cc-9d5d-3d2585fbfd74",
		12,
		strings.NewReader("012345678910"))
	tme := time.Now()
	sto := filestore.StoreFileOutput{
		ID: "/41/22/a8/4122a860-ce69-45cc-9d5d-3d2585fbfd74",
		Size: 12,
		Format: "",
		Filename: "",
		MD5: "fakemd5",
		Stored: tme,
	}
	fsmock.On("StoreFile", p).Return(&sto, nil)

	node, _ := nodestore.NewNode(uid, *nuser, 12, "fakemd5", tme)
	nsmock.On("StoreNode", node).Return(nil)
	auser, _ := auth.NewUser("username", false)

	bnode, err := bs.Store(
		*auser,
		strings.NewReader("012345678910"),
		12,
		"",
		"",	
	)
	assert.Nil(t, err, "unexpected error")
	expected := &BlobNode {
		ID: uid,
		Size: 12,
		MD5: "fakemd5",
		Stored: tme,
		Filename: "",
		Format: "",
	}
	assert.Equal(t, expected, bnode, "incorrect node")
}

func TestStoreWithFilenameAndFormat(t *testing.T) {
	uidmock := new(cmocks.UUIDGen)
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := NewWithUUIDGen(fsmock, nsmock, uidmock)

	uid, _ := uuid.Parse("4122a860-ce69-45cc-9d5d-3d2585fbfd74")
	userid := uuid.New()
	nuser, _ := nodestore.NewUser(userid, "username")

	uidmock.On("GetUUID").Return(uid)
	nsmock.On("GetUser", "username").Return(nuser, nil)

	p, _ := filestore.NewStoreFileParams(
		"/41/22/a8/4122a860-ce69-45cc-9d5d-3d2585fbfd74",
		12,
		strings.NewReader("012345678910"),
		filestore.FileName("myfile"),
		filestore.Format("excel"))
	tme := time.Now()
	sto := filestore.StoreFileOutput{
		ID: "/41/22/a8/4122a860-ce69-45cc-9d5d-3d2585fbfd74",
		Size: 12,
		Format: "myfile",
		Filename: "excel",
		MD5: "fakemd5",
		Stored: tme,
	}
	fsmock.On("StoreFile", p).Return(&sto, nil)

	node, _ := nodestore.NewNode(
		uid, *nuser, 12, "fakemd5", tme, nodestore.FileName("myfile"), nodestore.Format("excel"))
	nsmock.On("StoreNode", node).Return(nil)

	auser, _ := auth.NewUser("username", false)

	bnode, err := bs.Store(
		*auser,
		strings.NewReader("012345678910"),
		12,
		"myfile",
		"excel",
	)
	assert.Nil(t, err, "unexpected error")
	expected := &BlobNode {
		ID: uid,
		Size: 12,
		MD5: "fakemd5",
		Stored: tme,
		Filename: "myfile",
		Format: "excel",
	}
	assert.Equal(t, expected, bnode, "incorrect node")
}

func TestStoreFailSize(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := New(fsmock, nsmock)

	auser, _ := auth.NewUser("username", false)

	bnode, err := bs.Store(
		*auser,
		strings.NewReader("012345678910"),
		0,
		"myfile",
		"excel",
	)
	assert.Nil(t, bnode, "expected error")
	assert.Equal(t, errors.New("size must be > 0"), err, "incorrect error")
}

func TestStoreFailGetUser(t *testing.T) {
	uidmock := new(cmocks.UUIDGen)
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := NewWithUUIDGen(fsmock, nsmock, uidmock)

	uid, _ := uuid.Parse("4122a860-ce69-45cc-9d5d-3d2585fbfd74")

	uidmock.On("GetUUID").Return(uid)
	nsmock.On("GetUser", "username").Return(nil, errors.New("lovely error"))

	auser, _ := auth.NewUser("username", false)

	bnode, err := bs.Store(
		*auser,
		strings.NewReader("012345678910"),
		12,
		"myfile",
		"excel",
	)
	assert.Nil(t, bnode, "expected error")
	assert.Equal(t, errors.New("lovely error"), err, "incorrect error")
}

func TestStoreFailStoreFile(t *testing.T) {
	uidmock := new(cmocks.UUIDGen)
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := NewWithUUIDGen(fsmock, nsmock, uidmock)

	uid, _ := uuid.Parse("4122a860-ce69-45cc-9d5d-3d2585fbfd74")
	userid := uuid.New()
	nuser, _ := nodestore.NewUser(userid, "username")

	uidmock.On("GetUUID").Return(uid)
	nsmock.On("GetUser", "username").Return(nuser, nil)

	p, _ := filestore.NewStoreFileParams(
		"/41/22/a8/4122a860-ce69-45cc-9d5d-3d2585fbfd74",
		12,
		strings.NewReader("012345678910"))
	fsmock.On("StoreFile", p).Return(nil, errors.New("even more lovely"))

	auser, _ := auth.NewUser("username", false)

	bnode, err := bs.Store(
		*auser,
		strings.NewReader("012345678910"),
		12,
		"",
		"",
	)
	assert.Nil(t, bnode, "expected error")
	assert.Equal(t, errors.New("even more lovely"), err, "incorrect error")
}

func TestStoreFailStoreNode(t *testing.T) {
	uidmock := new(cmocks.UUIDGen)
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := NewWithUUIDGen(fsmock, nsmock, uidmock)

	uid, _ := uuid.Parse("4122a860-ce69-45cc-9d5d-3d2585fbfd74")
	userid := uuid.New()
	nuser, _ := nodestore.NewUser(userid, "username")

	uidmock.On("GetUUID").Return(uid)
	nsmock.On("GetUser", "username").Return(nuser, nil)

	p, _ := filestore.NewStoreFileParams(
		"/41/22/a8/4122a860-ce69-45cc-9d5d-3d2585fbfd74",
		12,
		strings.NewReader("012345678910"))
	tme := time.Now()
	sto := filestore.StoreFileOutput{
		ID: "/41/22/a8/4122a860-ce69-45cc-9d5d-3d2585fbfd74",
		Size: 12,
		Format: "",
		Filename: "",
		MD5: "fakemd5",
		Stored: tme,
	}
	fsmock.On("StoreFile", p).Return(&sto, nil)

	node, _ := nodestore.NewNode(uid, *nuser, 12, "fakemd5", tme)
	nsmock.On("StoreNode", node).Return(errors.New("the loveliest of them all"))

	auser, _ := auth.NewUser("username", false)

	bnode, err := bs.Store(
		*auser,
		strings.NewReader("012345678910"),
		12,
		"",
		"",	
	)
	assert.Nil(t, bnode, "expected error")
	assert.Equal(t, errors.New("the loveliest of them all"), err, "incorrect error")
}

func TestGetAsOwner(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := New(fsmock, nsmock)

	uid := uuid.New()
	auser, _ := auth.NewUser("un", false)

	userid := uuid.New()
	nuser, _ := nodestore.NewUser(userid, "username")

	nsmock.On("GetUser", "un").Return(nuser, nil)

	tme := time.Now()
	node, _ := nodestore.NewNode(
		uid, *nuser, 12, "fakemd5", tme, nodestore.FileName("fn"), nodestore.Format("json"))

	nsmock.On("GetNode", uid).Return(node, nil)

	bnode, err := bs.Get(*auser, uid)
	assert.Nil(t, err, "unexpected error")
	expected := &BlobNode {
		ID: uid,
		Size: 12,
		MD5: "fakemd5",
		Stored: tme,
		Filename: "fn",
		Format: "json",
	}
	assert.Equal(t, expected, bnode, "incorrect node")
}

func TestGetAsReader(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := New(fsmock, nsmock)

	uid := uuid.New()
	auser, _ := auth.NewUser("reader", false)

	nuser, _ := nodestore.NewUser(uuid.New(), "username")
	ruser, _ := nodestore.NewUser(uuid.New(), "reader")
	ouser, _ := nodestore.NewUser(uuid.New(), "other")

	nsmock.On("GetUser", "reader").Return(ruser, nil)

	tme := time.Now()
	node, _ := nodestore.NewNode(
		uid, *nuser, 12, "fakemd5", tme, nodestore.Reader(*ouser), nodestore.Reader(*ruser))

	nsmock.On("GetNode", uid).Return(node, nil)

	bnode, err := bs.Get(*auser, uid)
	assert.Nil(t, err, "unexpected error")
	expected := &BlobNode {
		ID: uid,
		Size: 12,
		MD5: "fakemd5",
		Stored: tme,
		Filename: "",
		Format: "",
	}
	assert.Equal(t, expected, bnode, "incorrect node")
}

func TestGetAsAdmin(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := New(fsmock, nsmock)

	uid := uuid.New()
	auser, _ := auth.NewUser("reader", true)

	nuser, _ := nodestore.NewUser(uuid.New(), "username")
	ruser, _ := nodestore.NewUser(uuid.New(), "reader")
	ouser, _ := nodestore.NewUser(uuid.New(), "other")

	nsmock.On("GetUser", "reader").Return(ruser, nil)

	tme := time.Now()
	node, _ := nodestore.NewNode(uid, *nuser, 12, "fakemd5", tme, nodestore.Reader(*ouser))

	nsmock.On("GetNode", uid).Return(node, nil)

	bnode, err := bs.Get(*auser, uid)
	assert.Nil(t, err, "unexpected error")
	expected := &BlobNode {
		ID: uid,
		Size: 12,
		MD5: "fakemd5",
		Stored: tme,
		Filename: "",
		Format: "",
	}
	assert.Equal(t, expected, bnode, "incorrect node")
}

func TestGetFailGetUser(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := New(fsmock, nsmock)

	uid := uuid.New()
	auser, _ := auth.NewUser("un", false)

	nsmock.On("GetUser", "un").Return(nil, errors.New("no users here"))

	bnode, err := bs.Get(*auser, uid)
	assert.Nil(t, bnode, "expected error")
	assert.Equal(t, errors.New("no users here"), err, "incorrect error")
}

func TestGetFailGetNode(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := New(fsmock, nsmock)

	uid := uuid.New()
	auser, _ := auth.NewUser("un", false)

	userid := uuid.New()
	nuser, _ := nodestore.NewUser(userid, "username")

	nsmock.On("GetUser", "un").Return(nuser, nil)

	nsmock.On("GetNode", uid).Return(
		nil, errors.New("that node isn't the messiah, he's a very naughty boy"))

	bnode, err := bs.Get(*auser, uid)
	assert.Nil(t, bnode, "expected error")
	assert.Equal(t, errors.New("that node isn't the messiah, he's a very naughty boy"),
		err, "incorrect error")
}

func TestGetFailUnauthorized(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := New(fsmock, nsmock)

	uid := uuid.New()
	auser, _ := auth.NewUser("other", false)

	nuser, _ := nodestore.NewUser(uuid.New(), "username")
	ruser, _ := nodestore.NewUser(uuid.New(), "reader")
	ouser, _ := nodestore.NewUser(uuid.New(), "other")

	nsmock.On("GetUser", "other").Return(ouser, nil)

	tme := time.Now()
	node, _ := nodestore.NewNode(uid, *nuser, 12, "fakemd5", tme, nodestore.Reader(*ruser))

	nsmock.On("GetNode", uid).Return(node, nil)

	bnode, err := bs.Get(*auser, uid)
	assert.Nil(t, bnode, "expected error")
	assert.Equal(t, errors.New("Unauthorized"), err, "incorrect error")
}