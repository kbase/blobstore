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