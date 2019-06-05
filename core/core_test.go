package core

import (
	"github.com/kbase/blobstore/core/values"
	"io/ioutil"
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

func TestNoBlobError(t *testing.T) {
	e := NewNoBlobError("some error")
	assert.Equal(t, "some error", e.Error(), "incorrect error")
}

func TestUnauthorizedError(t *testing.T) {
	e := NewUnauthorizedError("some error")
	assert.Equal(t, "some error", e.Error(), "incorrect error")
}

func TestUnauthorizedACLError(t *testing.T) {
	e := NewUnauthorizedACLError("some error")
	assert.Equal(t, "some error", e.Error(), "incorrect error")
}

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
		"41/22/a8/4122a860-ce69-45cc-9d5d-3d2585fbfd74",
		12,
		strings.NewReader("012345678910"))
	tme := time.Now()
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	sto := filestore.FileInfo{
		ID: "41/22/a8/4122a860-ce69-45cc-9d5d-3d2585fbfd74",
		Size: 12,
		Format: "",
		Filename: "",
		MD5: *md5,
		Stored: tme,
	}
	fsmock.On("StoreFile", p).Return(&sto, nil)

	node, _ := nodestore.NewNode(uid, *nuser, 12, *md5, tme)
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
		MD5: *md5,
		Stored: tme,
		Filename: "",
		Format: "",
		Owner: User{userid, "username"},
		Readers: &[]User{User{userid, "username"}},
		Public: false,
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

	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	p, _ := filestore.NewStoreFileParams(
		"41/22/a8/4122a860-ce69-45cc-9d5d-3d2585fbfd74",
		12,
		strings.NewReader("012345678910"),
		filestore.FileName("myfile"),
		filestore.Format("excel"))
	tme := time.Now()
	sto := filestore.FileInfo{
		ID: "41/22/a8/4122a860-ce69-45cc-9d5d-3d2585fbfd74",
		Size: 12,
		Format: "myfile",
		Filename: "excel",
		MD5: *md5,
		Stored: tme,
	}
	fsmock.On("StoreFile", p).Return(&sto, nil)

	node, _ := nodestore.NewNode(
		uid, *nuser, 12, *md5, tme, nodestore.FileName("myfile"), nodestore.Format("excel"))
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
		MD5: *md5,
		Stored: tme,
		Filename: "myfile",
		Format: "excel",
		Owner: User{userid, "username"},
		Readers: &[]User{User{userid, "username"}},
		Public: false,
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
		"41/22/a8/4122a860-ce69-45cc-9d5d-3d2585fbfd74",
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
		"41/22/a8/4122a860-ce69-45cc-9d5d-3d2585fbfd74",
		12,
		strings.NewReader("012345678910"))
	tme := time.Now()
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	sto := filestore.FileInfo{
		ID: "/41/22/a8/4122a860-ce69-45cc-9d5d-3d2585fbfd74",
		Size: 12,
		Format: "",
		Filename: "",
		MD5: *md5,
		Stored: tme,
	}
	fsmock.On("StoreFile", p).Return(&sto, nil)

	node, _ := nodestore.NewNode(uid, *nuser, 12, *md5, tme)
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
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	node, _ := nodestore.NewNode(
		uid, *nuser, 12, *md5, tme, nodestore.FileName("fn"), nodestore.Format("json"))

	nsmock.On("GetNode", uid).Return(node, nil)

	bnode, err := bs.Get(auser, uid)
	assert.Nil(t, err, "unexpected error")
	expected := &BlobNode {
		ID: uid,
		Size: 12,
		MD5: *md5,
		Stored: tme,
		Filename: "fn",
		Format: "json",
		Owner: User{userid, "username"},
		Readers: &[]User{User{userid, "username"}},
		Public: false,
	}
	assert.Equal(t, expected, bnode, "incorrect node")
}

func TestGetAsReader(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := New(fsmock, nsmock)

	uid := uuid.New()
	auser, _ := auth.NewUser("reader", false)

	nid := uuid.New()
	nuser, _ := nodestore.NewUser(nid, "username")
	rid := uuid.New()
	ruser, _ := nodestore.NewUser(rid, "reader")
	oid := uuid.New()
	ouser, _ := nodestore.NewUser(oid, "other")

	nsmock.On("GetUser", "reader").Return(ruser, nil)

	tme := time.Now()
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	node, _ := nodestore.NewNode(
		uid, *nuser, 12, *md5, tme, nodestore.Reader(*ouser), nodestore.Reader(*ruser))

	nsmock.On("GetNode", uid).Return(node, nil)

	bnode, err := bs.Get(auser, uid)
	assert.Nil(t, err, "unexpected error")
	expected := &BlobNode {
		ID: uid,
		Size: 12,
		MD5: *md5,
		Stored: tme,
		Filename: "",
		Format: "",
		Owner: User{nid, "username"},
		Readers: &[]User{User{nid, "username"}, User{oid, "other"}, User{rid, "reader"}},
		Public: false,
	}
	assert.Equal(t, expected, bnode, "incorrect node")
}

func TestGetAsAdmin(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := New(fsmock, nsmock)

	uid := uuid.New()
	auser, _ := auth.NewUser("reader", true)

	nid := uuid.New()
	nuser, _ := nodestore.NewUser(nid, "username")
	ruser, _ := nodestore.NewUser(uuid.New(), "reader")
	oid := uuid.New()
	ouser, _ := nodestore.NewUser(oid, "other")

	nsmock.On("GetUser", "reader").Return(ruser, nil)

	tme := time.Now()
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	node, _ := nodestore.NewNode(uid, *nuser, 12, *md5, tme, nodestore.Reader(*ouser))

	nsmock.On("GetNode", uid).Return(node, nil)

	bnode, err := bs.Get(auser, uid)
	assert.Nil(t, err, "unexpected error")
	expected := &BlobNode {
		ID: uid,
		Size: 12,
		MD5: *md5,
		Stored: tme,
		Filename: "",
		Format: "",
		Owner: User{nid, "username"},
		Readers: &[]User{User{nid, "username"}, User{oid, "other"}},
		Public: false,
	}
	assert.Equal(t, expected, bnode, "incorrect node")
}

func TestGetPublic(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := New(fsmock, nsmock)

	uid := uuid.New()
	auser, _ := auth.NewUser("reader", false)

	nid := uuid.New()
	nuser, _ := nodestore.NewUser(nid, "username")
	ruser, _ := nodestore.NewUser(uuid.New(), "reader")

	nsmock.On("GetUser", "reader").Return(ruser, nil)

	tme := time.Now()
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	node, _ := nodestore.NewNode(uid, *nuser, 12, *md5, tme, nodestore.Public(true))

	nsmock.On("GetNode", uid).Return(node, nil)
	
	expected := &BlobNode {
		ID: uid,
		Size: 12,
		MD5: *md5,
		Stored: tme,
		Filename: "",
		Format: "",
		Owner: User{nid, "username"},
		Readers: &[]User{User{nid, "username"}},
		Public: true,
	}
	bnode, err := bs.Get(nil, uid)
	assert.Nil(t, err, "unexpected error")
	assert.Equal(t, expected, bnode, "incorrect node")

	bnode, err = bs.Get(auser, uid)
	assert.Nil(t, err, "unexpected error")
	assert.Equal(t, expected, bnode, "incorrect node")
}

func TestGetFailGetUser(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := New(fsmock, nsmock)

	uid := uuid.New()
	auser, _ := auth.NewUser("un", false)

	nsmock.On("GetUser", "un").Return(nil, errors.New("no users here"))

	bnode, err := bs.Get(auser, uid)
	assert.Nil(t, bnode, "expected error")
	assert.Equal(t, errors.New("no users here"), err, "incorrect error")
}

func TestGetFailGetNode(t *testing.T) {
	uid := uuid.New()
	auser, _ := auth.NewUser("un", false)

	userid := uuid.New()
	nuser, _ := nodestore.NewUser(userid, "username")


	inputs := map[error]error{
		errors.New("that node isn't the messiah, he's a very naughty boy"):
			errors.New("that node isn't the messiah, he's a very naughty boy"),
		nodestore.NewNoNodeError("oops"): NewNoBlobError("oops"),
	}

	for causeerr, expectederr := range inputs {
		fsmock := new(fsmocks.FileStore)
		nsmock := new(nsmocks.NodeStore)
		bs := New(fsmock, nsmock)
		nsmock.On("GetUser", "un").Return(nuser, nil)

		nsmock.On("GetNode", uid).Return(nil, causeerr)
	
		bnode, err := bs.Get(auser, uid)
		assert.Nil(t, bnode, "expected error")
		assert.Equal(t, expectederr, err, "incorrect error")
	}
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
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	node, _ := nodestore.NewNode(uid, *nuser, 12, *md5, tme, nodestore.Reader(*ruser))

	nsmock.On("GetNode", uid).Return(node, nil)

	bnode, err := bs.Get(auser, uid)
	assert.Nil(t, bnode, "expected error")
	assert.Equal(t, NewUnauthorizedError("Unauthorized"), err, "incorrect error")

	bnode, err = bs.Get(nil, uid)
	assert.Nil(t, bnode, "expected error")
	assert.Equal(t, NewUnauthorizedError("Unauthorized"), err, "incorrect error")
}

// GetFile calls GET under the hood, so we only test one error case (auth) from the Get code

func TestGetFileAsOwner(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := New(fsmock, nsmock)

	uid, err := uuid.Parse("f6029a11-0914-42b3-beea-fed420f75d7d")
	auser, _ := auth.NewUser("un", false)

	userid := uuid.New()
	nuser, _ := nodestore.NewUser(userid, "username")

	nsmock.On("GetUser", "un").Return(nuser, nil)

	tme := time.Now()
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	node, _ := nodestore.NewNode(uid, *nuser, 12, *md5, tme, nodestore.FileName("a_file"))

	nsmock.On("GetNode", uid).Return(node, nil)

	md5fake, _ := values.NewMD5("4d838d477ddf355Bc15df1db90bee0aa")
	gfo := filestore.GetFileOutput{
		ID: "f6/02/9a/f6029a11-0914-42b3-beea-fed420f75d7d",
		Size: 9,
		Format: "who cares",
		Filename: "my_lovely_file",
		MD5: *md5fake,
		Stored: time.Now(),
		Data: ioutil.NopCloser(strings.NewReader("012345678")),
	}
	fsmock.On("GetFile", "f6/02/9a/f6029a11-0914-42b3-beea-fed420f75d7d").Return(&gfo, nil)

	rd, size, filename, err := bs.GetFile(auser, uid)
	assert.Nil(t, err, "unexpected error")
	assert.Equal(t, int64(9), size, "incorrect size")
	assert.Equal(t, "a_file", filename, "incorrect filename")
	assert.Equal(t, rd, ioutil.NopCloser(strings.NewReader("012345678")), "incorrect data")
}

func TestGetFileAsReader(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := New(fsmock, nsmock)

	uid, err := uuid.Parse("f6029a11-0914-42b3-beea-fed420f75d7d")
	auser, _ := auth.NewUser("reader", false)

	nuser, _ := nodestore.NewUser(uuid.New(), "username")
	ruser, _ := nodestore.NewUser(uuid.New(), "reader")
	ouser, _ := nodestore.NewUser(uuid.New(), "other")

	nsmock.On("GetUser", "reader").Return(ruser, nil)

	tme := time.Now()
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	node, _ := nodestore.NewNode(uid, *nuser, 12, *md5, tme,
		nodestore.Reader(*ouser), nodestore.Reader(*ruser), nodestore.FileName(""))

	nsmock.On("GetNode", uid).Return(node, nil)

	md5fake, _ := values.NewMD5("3d838d477ddf955fc15df1db90bee0aa")
	gfo := filestore.GetFileOutput{
		ID: "f6/02/9a/f6029a11-0914-42b3-beea-fed420f75d7d",
		Size: 9,
		Format: "who cares",
		Filename: "",
		MD5: *md5fake,
		Stored: time.Now(),
		Data: ioutil.NopCloser(strings.NewReader("012345678")),
	}
	fsmock.On("GetFile", "f6/02/9a/f6029a11-0914-42b3-beea-fed420f75d7d").Return(&gfo, nil)

	rd, size, filename, err := bs.GetFile(auser, uid)
	assert.Nil(t, err, "unexpected error")
	assert.Equal(t, int64(9), size, "incorrect size")
	assert.Equal(t, "", filename, "incorrect filename")
	assert.Equal(t, rd, ioutil.NopCloser(strings.NewReader("012345678")), "incorrect data")
}

func TestGetFileAsAdmin(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := New(fsmock, nsmock)

	uid, err := uuid.Parse("f6029a11-0914-42b3-beea-fed420f75d7d")
	auser, _ := auth.NewUser("other", true)

	nuser, _ := nodestore.NewUser(uuid.New(), "username")
	ruser, _ := nodestore.NewUser(uuid.New(), "reader")
	ouser, _ := nodestore.NewUser(uuid.New(), "other")

	nsmock.On("GetUser", "other").Return(ouser, nil)

	tme := time.Now()
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	node, _ := nodestore.NewNode(uid, *nuser, 12, *md5, tme, nodestore.Reader(*ruser),
		nodestore.FileName("bfile"))

	nsmock.On("GetNode", uid).Return(node, nil)

	md5fake, _ := values.NewMD5("2d838d487ddf355fc15df1db90bee0aa")
	gfo := filestore.GetFileOutput{
		ID: "f6/02/9a/f6029a11-0914-42b3-beea-fed420f75d7d",
		Size: 9,
		Format: "who cares",
		Filename: "afile",
		MD5: *md5fake,
		Stored: time.Now(),
		Data: ioutil.NopCloser(strings.NewReader("012345678")),
	}
	fsmock.On("GetFile", "f6/02/9a/f6029a11-0914-42b3-beea-fed420f75d7d").Return(&gfo, nil)

	rd, size, filename, err := bs.GetFile(auser, uid)
	assert.Nil(t, err, "unexpected error")
	assert.Equal(t, int64(9), size, "incorrect size")
	assert.Equal(t, "bfile", filename, "incorrect filename")
	assert.Equal(t, rd, ioutil.NopCloser(strings.NewReader("012345678")), "incorrect data")
}

func TestGetFilePublic(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := New(fsmock, nsmock)

	uid, err := uuid.Parse("f6029a11-0914-42b3-beea-fed420f75d7d")
	auser, _ := auth.NewUser("other", false)

	nid := uuid.New()
	nuser, _ := nodestore.NewUser(nid, "username")
	rid := uuid.New()
	ruser, _ := nodestore.NewUser(rid, "reader")
	ouser, _ := nodestore.NewUser(uuid.New(), "other")

	nsmock.On("GetUser", "other").Return(ouser, nil)

	tme := time.Now()
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	node, _ := nodestore.NewNode(uid, *nuser, 12, *md5, tme, nodestore.Reader(*ruser),
		nodestore.FileName("bfile"), nodestore.Public(true))

	nsmock.On("GetNode", uid).Return(node, nil)

	md5fake, _ := values.NewMD5("4d838d477ddf355fc15df1db90bee0aa")
	gfo := filestore.GetFileOutput{
		ID: "f6/02/9a/f6029a11-0914-42b3-beea-fed420f75d7d",
		Size: 9,
		Format: "who cares",
		Filename: "afile",
		MD5: *md5fake,
		Stored: time.Now(),
		Data: ioutil.NopCloser(strings.NewReader("012345678")),
	}
	fsmock.On("GetFile", "f6/02/9a/f6029a11-0914-42b3-beea-fed420f75d7d").Return(&gfo, nil)

	rd, size, filename, err := bs.GetFile(auser, uid)
	assert.Nil(t, err, "unexpected error")
	assert.Equal(t, int64(9), size, "incorrect size")
	assert.Equal(t, "bfile", filename, "incorrect filename")
	assert.Equal(t, rd, ioutil.NopCloser(strings.NewReader("012345678")), "incorrect data")

	rd, size, filename, err = bs.GetFile(nil, uid)
	assert.Nil(t, err, "unexpected error")
	assert.Equal(t, int64(9), size, "incorrect size")
	assert.Equal(t, "bfile", filename, "incorrect filename")
	assert.Equal(t, rd, ioutil.NopCloser(strings.NewReader("012345678")), "incorrect data")
}

func TestGetFileUnauthorized(t *testing.T) {
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
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	node, _ := nodestore.NewNode(uid, *nuser, 12, *md5, tme, nodestore.Reader(*ruser),
		nodestore.FileName("foo"))

	nsmock.On("GetNode", uid).Return(node, nil)

	rd, size, filename, err := bs.GetFile(auser, uid)
	assert.Equal(t, int64(0), size, "expected error")
	assert.Equal(t, rd, nil, "expected error")
	assert.Equal(t, "", filename, "incorrect filename")
	assert.Equal(t, NewUnauthorizedError("Unauthorized"), err, "incorrect error")

	rd, size, filename, err = bs.GetFile(nil, uid)
	assert.Equal(t, int64(0), size, "expected error")
	assert.Equal(t, rd, nil, "expected error")
	assert.Equal(t, "", filename, "incorrect filename")
	assert.Equal(t, NewUnauthorizedError("Unauthorized"), err, "incorrect error")
}

func TestGetFileFailGetFromStorage(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := New(fsmock, nsmock)

	auser, _ := auth.NewUser("un", false)
	
	nuser, _ := nodestore.NewUser(uuid.New(), "un")
	
	nsmock.On("GetUser", "un").Return(nuser, nil)
	
	nid, _ := uuid.Parse("f6029a11-0914-42b3-beea-fed420f75d7d")
	tme := time.Now()
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	node, _ := nodestore.NewNode(nid, *nuser, 12, *md5, tme, nodestore.FileName("foo"))

	nsmock.On("GetNode", nid).Return(node, nil)

	fsmock.On("GetFile", "f6/02/9a/f6029a11-0914-42b3-beea-fed420f75d7d").Return(
		nil, errors.New("whoopsie"))

	rd, size, filename, err := bs.GetFile(auser, nid)
	assert.Equal(t, int64(0), size, "expected error")
	assert.Equal(t, rd, nil, "expected error")
	assert.Equal(t, "", filename, "incorrect filename")
	assert.Equal(t, errors.New("whoopsie"), err, "incorrect error")
}

func TestSetNodePublicTrueAsOwner(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := New(fsmock, nsmock)

	auser, _ := auth.NewUser("un", false)
	
	oid := uuid.New()
	nuser, _ := nodestore.NewUser(oid, "un")
	
	nsmock.On("GetUser", "un").Return(nuser, nil)
	
	nid, _ := uuid.Parse("f6029a11-0914-42b3-beea-fed420f75d7d")
	tme := time.Now()
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	node, _ := nodestore.NewNode(nid, *nuser, 12, *md5, tme, nodestore.FileName("foo"))

	nsmock.On("GetNode", nid).Return(node, nil)

	nsmock.On("SetNodePublic", nid, true).Return(nil)

	bnode, err := bs.SetNodePublic(*auser, nid, true)
	assert.Nil(t, err, "unexpected error")
	expected := &BlobNode {
		ID: nid,
		Size: 12,
		MD5: *md5,
		Stored: tme,
		Filename: "foo",
		Format: "",
		Owner: User{oid, "un"},
		Readers: &[]User{User{oid, "un"}},
		Public: true,
	}
	assert.Equal(t, expected, bnode, "incorrect node")
}

func TestSetNodePublicFalseAsAdmin(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := New(fsmock, nsmock)

	auser, _ := auth.NewUser("un", true)
	
	nuser, _ := nodestore.NewUser(uuid.New(), "un")

	oid := uuid.New()
	nowner, _ := nodestore.NewUser(oid, "owner")
	
	nsmock.On("GetUser", "un").Return(nuser, nil)
	
	nid, _ := uuid.Parse("f6029a11-0914-42b3-beea-fed420f75d7d")
	tme := time.Now()
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	node, _ := nodestore.NewNode(nid, *nowner, 12, *md5, tme, nodestore.FileName("foo"))

	nsmock.On("GetNode", nid).Return(node, nil)

	nsmock.On("SetNodePublic", nid, false).Return(nil)

	bnode, err := bs.SetNodePublic(*auser, nid, false)
	assert.Nil(t, err, "unexpected error")
	expected := &BlobNode {
		ID: nid,
		Size: 12,
		MD5: *md5,
		Stored: tme,
		Filename: "foo",
		Format: "",
		Owner: User{oid, "owner"},
		Readers: &[]User{User{oid, "owner"}},
		Public: false,
	}
	assert.Equal(t, expected, bnode, "incorrect node")
}

func TestSetNodePublicFailGetUser(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := New(fsmock, nsmock)

	uid := uuid.New()
	auser, _ := auth.NewUser("un", false)

	nsmock.On("GetUser", "un").Return(nil, errors.New("no users here"))

	bnode, err := bs.SetNodePublic(*auser, uid, true)
	assert.Equal(t, errors.New("no users here"), err, "incorrect error")
	assert.Nil(t, bnode, "expected error")
}

func TestSetNodePublicFailGetNode(t *testing.T) {
	uid := uuid.New()
	auser, _ := auth.NewUser("un", false)

	userid := uuid.New()
	nuser, _ := nodestore.NewUser(userid, "username")


	inputs := map[error]error{
		errors.New("You are all individuals"): errors.New("You are all individuals"),
		nodestore.NewNoNodeError("oops"): NewNoBlobError("oops"),
	}

	for causeerr, expectederr := range inputs {
		fsmock := new(fsmocks.FileStore)
		nsmock := new(nsmocks.NodeStore)
		bs := New(fsmock, nsmock)
		nsmock.On("GetUser", "un").Return(nuser, nil)

		nsmock.On("GetNode", uid).Return(nil, causeerr)
	
		bnode, err := bs.SetNodePublic(*auser, uid, false)
		assert.Nil(t, bnode, "expected error")
		assert.Equal(t, expectederr, err, "incorrect error")
	}
}

func TestSetNodePublicFailUnauthorized(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := New(fsmock, nsmock)

	auser, _ := auth.NewUser("un", false)
	
	nuser, _ := nodestore.NewUser(uuid.New(), "un")

	nowner, _ := nodestore.NewUser(uuid.New(), "owner")
	
	nsmock.On("GetUser", "un").Return(nuser, nil)
	
	nid, _ := uuid.Parse("f6029a11-0914-42b3-beea-fed420f75d7d")
	tme := time.Now()
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	node, _ := nodestore.NewNode(nid, *nowner, 12, *md5, tme, nodestore.FileName("foo"))

	nsmock.On("GetNode", nid).Return(node, nil)

	bnode, err := bs.SetNodePublic(*auser, nid, false)
	assert.Equal(t, NewUnauthorizedACLError("Users can only remove themselves from the read ACL"),
		err, "incorrect error")
	assert.Nil(t, bnode, "expected error")
}

func TestSetNodePublicFailSetPublic(t *testing.T) {
	
	auser, _ := auth.NewUser("un", true)
	
	nuser, _ := nodestore.NewUser(uuid.New(), "un")
	
	inputs := map[error]error{
		errors.New("You are all individuals"): errors.New("You are all individuals"),
		nodestore.NewNoNodeError("oops"): NewNoBlobError("oops"),
	}
	
	for causeerr, expectederr := range inputs {
		fsmock := new(fsmocks.FileStore)
		nsmock := new(nsmocks.NodeStore)
		bs := New(fsmock, nsmock)
		
		nsmock.On("GetUser", "un").Return(nuser, nil)
		
		nid, _ := uuid.Parse("f6029a11-0914-42b3-beea-fed420f75d7d")
		tme := time.Now()
		md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
		node, _ := nodestore.NewNode(nid, *nuser, 12, *md5, tme, nodestore.FileName("foo"))

		nsmock.On("GetNode", nid).Return(node, nil)

		nsmock.On("SetNodePublic", nid, false).Return(causeerr)

		bnode, err := bs.SetNodePublic(*auser, nid, false)
		assert.Nil(t, bnode, "expected error")
		assert.Equal(t, expectederr, err, "incorrect error")
	}
}

func TestAddReaders(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)
	bs := New(fsmock, nsmock)
	
	auser, _ := auth.NewUser("owner", false)
	oid := uuid.New()
	o, _ := nodestore.NewUser(oid, "owner")
	nsmock.On("GetUser", "owner").Return(o, nil)
	
	nid, _ := uuid.Parse("f6029a11-0914-42b3-beea-fed420f75d7d")
	tme := time.Now()
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	node, _ := nodestore.NewNode(nid, *o, 12, *md5, tme, nodestore.FileName("foo"))

	nsmock.On("GetNode", nid).Return(node, nil)

	r1id := uuid.New()
	r1, _ := nodestore.NewUser(r1id, "r1")
	nsmock.On("GetUser", "r1").Return(r1, nil)
	nsmock.On("AddReader", nid, *r1).Return(nil)

	r2id := uuid.New()
	r2, _ := nodestore.NewUser(r2id, "r2")
	nsmock.On("GetUser", "r2").Return(r2, nil)
	nsmock.On("AddReader", nid, *r2).Return(nil)

	bnode, err := bs.AddReaders(*auser, nid, []string{"r1", "r2"})
	assert.Nil(t, err, "unexpected error")
	expected := &BlobNode {
		ID: nid,
		Size: 12,
		MD5: *md5,
		Stored: tme,
		Filename: "foo",
		Format: "",
		Owner: User{oid, "owner"},
		Readers: &[]User{User{oid, "owner"}, User{r1id, "r1"}, User{r2id, "r2"}},
		Public: false,
	}
	assert.Equal(t, expected, bnode, "incorrect node")

	// test as admin
	auser, _ = auth.NewUser("notowner", true)
	no, _ := nodestore.NewUser(uuid.New(), "notowner")
	nsmock.On("GetUser", "notowner").Return(no, nil)
	bnode, err = bs.AddReaders(*auser, nid, []string{"r1", "r2"})
	assert.Nil(t, err, "unexpected error")
	assert.Equal(t, expected, bnode, "incorrect node")
}

func TestRemoveReaders(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)
	bs := New(fsmock, nsmock)
	
	auser, _ := auth.NewUser("owner", false)
	oid := uuid.New()
	o, _ := nodestore.NewUser(oid, "owner")
	nsmock.On("GetUser", "owner").Return(o, nil)
	
	r1id := uuid.New()
	r1, _ := nodestore.NewUser(r1id, "r1")
	r2id := uuid.New()
	r2, _ := nodestore.NewUser(r2id, "r2")
	
	nid, _ := uuid.Parse("f6029a11-0914-42b3-beea-fed420f75d7d")
	tme := time.Now()
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	node, _ := nodestore.NewNode(nid, *o, 12, *md5, tme, nodestore.FileName("foo"),
		nodestore.Reader(*r1), nodestore.Reader(*r2))

	nsmock.On("GetNode", nid).Return(node, nil)

	nsmock.On("GetUser", "r1").Return(r1, nil)
	nsmock.On("RemoveReader", nid, *r1).Return(nil)

	nsmock.On("GetUser", "r2").Return(r2, nil)
	nsmock.On("RemoveReader", nid, *r2).Return(nil)

	bnode, err := bs.RemoveReaders(*auser, nid, []string{"r1", "r2"})
	assert.Nil(t, err, "unexpected error")
	expected := &BlobNode {
		ID: nid,
		Size: 12,
		MD5: *md5,
		Stored: tme,
		Filename: "foo",
		Format: "",
		Owner: User{oid, "owner"},
		Readers: &[]User{User{oid, "owner"}},
		Public: false,
	}
	assert.Equal(t, expected, bnode, "incorrect node")

	// test as admin
	auser, _ = auth.NewUser("notowner", true)
	no, _ := nodestore.NewUser(uuid.New(), "notowner")
	nsmock.On("GetUser", "notowner").Return(no, nil)
	bnode, err = bs.RemoveReaders(*auser, nid, []string{"r1", "r2"})
	assert.Nil(t, err, "unexpected error")
	assert.Equal(t, expected, bnode, "incorrect node")
}

func TestRemoveReaderSelf(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)
	bs := New(fsmock, nsmock)
	
	auser, _ := auth.NewUser("r1", false)

	oid := uuid.New()
	o, _ := nodestore.NewUser(oid, "owner")
	
	r1id := uuid.New()
	r1, _ := nodestore.NewUser(r1id, "r1")
	r2id := uuid.New()
	r2, _ := nodestore.NewUser(r2id, "r2")
	
	nid, _ := uuid.Parse("f6029a11-0914-42b3-beea-fed420f75d7d")
	tme := time.Now()
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	node, _ := nodestore.NewNode(nid, *o, 12, *md5, tme, nodestore.FileName("foo"),
		nodestore.Reader(*r1), nodestore.Reader(*r2))
	
	nsmock.On("GetUser", "r1").Return(r1, nil)

	nsmock.On("GetNode", nid).Return(node, nil)

	nsmock.On("RemoveReader", nid, *r1).Return(nil)

	bnode, err := bs.RemoveReaders(*auser, nid, []string{"r1"})
	assert.Nil(t, err, "unexpected error")
	expected := &BlobNode {
		ID: nid,
		Size: 12,
		MD5: *md5,
		Stored: tme,
		Filename: "foo",
		Format: "",
		Owner: User{oid, "owner"},
		Readers: &[]User{User{oid, "owner"}, User{r2id, "r2"}},
		Public: false,
	}
	assert.Equal(t, expected, bnode, "incorrect node")
}

func TestAddAndRemoveReadersFailGetUser(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := New(fsmock, nsmock)

	uid := uuid.New()
	auser, _ := auth.NewUser("un", false)

	nsmock.On("GetUser", "un").Return(nil, errors.New("no users here"))

	bnode, err := bs.AddReaders(*auser, uid, []string{"r"})
	assert.Equal(t, errors.New("no users here"), err, "incorrect error")
	assert.Nil(t, bnode, "expected error")

	bnode, err = bs.RemoveReaders(*auser, uid, []string{"r"})
	assert.Equal(t, errors.New("no users here"), err, "incorrect error")
	assert.Nil(t, bnode, "expected error")
}

func TestAddAndRemoveReadersFailGetNode(t *testing.T) {
	uid := uuid.New()
	auser, _ := auth.NewUser("un", false)

	userid := uuid.New()
	nuser, _ := nodestore.NewUser(userid, "username")


	inputs := map[error]error{
		errors.New("You are all individuals"): errors.New("You are all individuals"),
		nodestore.NewNoNodeError("oops"): NewNoBlobError("oops"),
	}

	for causeerr, expectederr := range inputs {
		fsmock := new(fsmocks.FileStore)
		nsmock := new(nsmocks.NodeStore)
		bs := New(fsmock, nsmock)
		nsmock.On("GetUser", "un").Return(nuser, nil)

		nsmock.On("GetNode", uid).Return(nil, causeerr)
	
		bnode, err := bs.AddReaders(*auser, uid, []string{"r"})
		assert.Nil(t, bnode, "expected error")
		assert.Equal(t, expectederr, err, "incorrect error")

		bnode, err = bs.RemoveReaders(*auser, uid, []string{"r"})
		assert.Nil(t, bnode, "expected error")
		assert.Equal(t, expectederr, err, "incorrect error")
	}
}

func TestAddAndRemoveReadersFailUnauthorized(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := New(fsmock, nsmock)

	auser, _ := auth.NewUser("un", false)
	
	nuser, _ := nodestore.NewUser(uuid.New(), "un")

	nowner, _ := nodestore.NewUser(uuid.New(), "owner")
	
	nsmock.On("GetUser", "un").Return(nuser, nil)
	
	nid, _ := uuid.Parse("f6029a11-0914-42b3-beea-fed420f75d7d")
	tme := time.Now()
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	node, _ := nodestore.NewNode(nid, *nowner, 12, *md5, tme, nodestore.FileName("foo"))

	nsmock.On("GetNode", nid).Return(node, nil)

	readers := [][]string{
		[]string{"r"},       // tests reader != self check
		[]string{"un", "r2"}, // tests single reader check
	}

	for _, rdrs := range readers {
		bnode, err := bs.AddReaders(*auser, nid, rdrs)
		expectederr := NewUnauthorizedACLError(
			"Users can only remove themselves from the read ACL")
		assert.Equal(t, expectederr, err, "incorrect error")
		assert.Nil(t, bnode, "expected error")

		bnode, err = bs.RemoveReaders(*auser, nid, rdrs)
		assert.Equal(t, expectederr, err, "incorrect error")
		assert.Nil(t, bnode, "expected error")
	}
}

func TestAddReaderSelfFailUnauthorized(t *testing.T) {
	// check that the remove self code doesn't allow adding self
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := New(fsmock, nsmock)

	auser, _ := auth.NewUser("reader", false)
	
	ruser, _ := nodestore.NewUser(uuid.New(), "reader")

	nowner, _ := nodestore.NewUser(uuid.New(), "owner")
	
	nsmock.On("GetUser", "reader").Return(ruser, nil)
	
	nid, _ := uuid.Parse("f6029a11-0914-42b3-beea-fed420f75d7d")
	tme := time.Now()
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	node, _ := nodestore.NewNode(nid, *nowner, 12, *md5, tme, nodestore.FileName("foo"))

	nsmock.On("GetNode", nid).Return(node, nil)

	bnode, err := bs.AddReaders(*auser, nid, []string{"reader"})
	expectederr := NewUnauthorizedACLError(
		"Users can only remove themselves from the read ACL")
	assert.Equal(t, expectederr, err, "incorrect error")
	assert.Nil(t, bnode, "expected error")
}

func TestAddAndRemoveReadersFailGetReader(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)
	bs := New(fsmock, nsmock)
	
	auser, _ := auth.NewUser("notowner", true)
	no, _ := nodestore.NewUser(uuid.New(), "notowner")
	nsmock.On("GetUser", "notowner").Return(no, nil)
	
	o, _ := nodestore.NewUser(uuid.New(), "owner")
	nid, _ := uuid.Parse("f6029a11-0914-42b3-beea-fed420f75d7d")
	tme := time.Now()
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	node, _ := nodestore.NewNode(nid, *o, 12, *md5, tme, nodestore.FileName("foo"))

	nsmock.On("GetNode", nid).Return(node, nil)

	nsmock.On("GetUser", "r").Return(nil, errors.New("Yeah? Sausages and?"))

	bnode, err := bs.AddReaders(*auser, nid, []string{"r"})
	assert.Equal(t, errors.New("Yeah? Sausages and?"), err, "incorrect error")
	assert.Nil(t, bnode, "expected error")

	bnode, err = bs.RemoveReaders(*auser, nid, []string{"r"})
	assert.Equal(t, errors.New("Yeah? Sausages and?"), err, "incorrect error")
	assert.Nil(t, bnode, "expected error")
}

func TestAddAndRemoveReadersFailAddRemoveReader(t *testing.T) {
	
	auser, _ := auth.NewUser("un", true)
	
	nuser, _ := nodestore.NewUser(uuid.New(), "un")
	r, _ := nodestore.NewUser(uuid.New(), "r")
	
	inputs := map[error]error{
		errors.New("Sausages and plant and goldfish"):
			errors.New("Sausages and plant and goldfish"),
		nodestore.NewNoNodeError("oops"): NewNoBlobError("oops"),
	}
	
	for causeerr, expectederr := range inputs {
		fsmock := new(fsmocks.FileStore)
		nsmock := new(nsmocks.NodeStore)
		bs := New(fsmock, nsmock)
		
		nsmock.On("GetUser", "un").Return(nuser, nil)
		
		nid, _ := uuid.Parse("f6029a11-0914-42b3-beea-fed420f75d7d")
		tme := time.Now()
		md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
		node, _ := nodestore.NewNode(nid, *nuser, 12, *md5, tme, nodestore.FileName("foo"))

		nsmock.On("GetNode", nid).Return(node, nil)

		nsmock.On("GetUser", "r").Return(r, nil)

		nsmock.On("AddReader", nid, *r).Return(causeerr)
		nsmock.On("RemoveReader", nid, *r).Return(causeerr)

		bnode, err := bs.AddReaders(*auser, nid, []string{"r"})
		assert.Equal(t, expectederr, err, "incorrect error")
		assert.Nil(t, bnode, "expected error")

		bnode, err = bs.RemoveReaders(*auser, nid, []string{"r"})
		assert.Equal(t, expectederr, err, "incorrect error")
		assert.Nil(t, bnode, "expected error")
	}
}

func TestChangeOwner(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)
	bs := New(fsmock, nsmock)
	
	auser, _ := auth.NewUser("owner", false)
	oid := uuid.New()
	o, _ := nodestore.NewUser(oid, "owner")
	nsmock.On("GetUser", "owner").Return(o, nil)
	
	r1id := uuid.New()
	r1, _ := nodestore.NewUser(r1id, "r1")

	nid, _ := uuid.Parse("f6029a11-0914-42b3-beea-fed420f75d7d")
	tme := time.Now()
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	node, _ := nodestore.NewNode(nid, *o, 12, *md5, tme, nodestore.FileName("foo"),
		nodestore.Reader(*r1))

	nsmock.On("GetNode", nid).Return(node, nil)

	newid := uuid.New()
	newowner, _ := nodestore.NewUser(newid, "new")
	nsmock.On("GetUser", "new").Return(newowner, nil)
	nsmock.On("ChangeOwner", nid, *newowner).Return(nil)

	bnode, err := bs.ChangeOwner(*auser, nid, "new")
	expected := &BlobNode {
		ID: nid,
		Size: 12,
		MD5: *md5,
		Stored: tme,
		Filename: "foo",
		Format: "",
		Owner: User{newid, "new"},
		Readers: &[]User{User{newid, "new"}, User{oid, "owner"}, User{r1id, "r1"}},
		Public: false,
	}
	assert.Equal(t, expected, bnode, "incorrect node")
	assert.Nil(t, err, "unexpected error")

	// test as admin
	auser, _ = auth.NewUser("notowner", true)
	no, _ := nodestore.NewUser(uuid.New(), "notowner")
	nsmock.On("GetUser", "notowner").Return(no, nil)
	bnode, err = bs.ChangeOwner(*auser, nid, "new")
	assert.Nil(t, err, "unexpected error")
	assert.Equal(t, expected, bnode, "incorrect node")
}

func TestChangeOwnerFailGetUser(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := New(fsmock, nsmock)

	uid := uuid.New()
	auser, _ := auth.NewUser("un", false)

	nsmock.On("GetUser", "un").Return(nil, errors.New("no users here"))

	bnode, err := bs.ChangeOwner(*auser, uid, "foo")
	assert.Equal(t, errors.New("no users here"), err, "incorrect error")
	assert.Nil(t, bnode, "expected error")
}

func TestChangeOwnerFailGetNode(t *testing.T) {
	uid := uuid.New()
	auser, _ := auth.NewUser("un", false)

	userid := uuid.New()
	nuser, _ := nodestore.NewUser(userid, "username")


	inputs := map[error]error{
		errors.New("You are all individuals"): errors.New("You are all individuals"),
		nodestore.NewNoNodeError("oops"): NewNoBlobError("oops"),
	}

	for causeerr, expectederr := range inputs {
		fsmock := new(fsmocks.FileStore)
		nsmock := new(nsmocks.NodeStore)
		bs := New(fsmock, nsmock)
		nsmock.On("GetUser", "un").Return(nuser, nil)

		nsmock.On("GetNode", uid).Return(nil, causeerr)
	
		bnode, err := bs.ChangeOwner(*auser, uid, "foo")
		assert.Equal(t, expectederr, err, "incorrect error")
		assert.Nil(t, bnode, "expected error")
	}
}

func TestChangeOwnerFailUnauthorized(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := New(fsmock, nsmock)

	auser, _ := auth.NewUser("un", false)
	
	nuser, _ := nodestore.NewUser(uuid.New(), "un")

	nowner, _ := nodestore.NewUser(uuid.New(), "owner")
	
	nsmock.On("GetUser", "un").Return(nuser, nil)
	
	nid, _ := uuid.Parse("f6029a11-0914-42b3-beea-fed420f75d7d")
	tme := time.Now()
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	node, _ := nodestore.NewNode(nid, *nowner, 12, *md5, tme, nodestore.FileName("foo"))

	nsmock.On("GetNode", nid).Return(node, nil)

	bnode, err := bs.ChangeOwner(*auser, nid, "foo")
	expectederr := NewUnauthorizedACLError("Users can only remove themselves from the read ACL")
	assert.Equal(t, expectederr, err, "incorrect error")
	assert.Nil(t, bnode, "expected error")
}

func TestChangeOwnerFailGetNewOwner(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)
	bs := New(fsmock, nsmock)
	
	auser, _ := auth.NewUser("notowner", true)
	no, _ := nodestore.NewUser(uuid.New(), "notowner")
	nsmock.On("GetUser", "notowner").Return(no, nil)
	
	o, _ := nodestore.NewUser(uuid.New(), "owner")
	nid, _ := uuid.Parse("f6029a11-0914-42b3-beea-fed420f75d7d")
	tme := time.Now()
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	node, _ := nodestore.NewNode(nid, *o, 12, *md5, tme, nodestore.FileName("foo"))

	nsmock.On("GetNode", nid).Return(node, nil)

	nsmock.On("GetUser", "newown").Return(nil, errors.New("I've discharged my responsibilities"))

	bnode, err := bs.ChangeOwner(*auser, nid, "newown")
	assert.Equal(t, errors.New("I've discharged my responsibilities"), err, "incorrect error")
	assert.Nil(t, bnode, "expected error")
}

func TestChangeOwnerFailChangeOwner(t *testing.T) {
	
	auser, _ := auth.NewUser("un", false)
	
	nuser, _ := nodestore.NewUser(uuid.New(), "un")
	newowner, _ := nodestore.NewUser(uuid.New(), "new")
	
	inputs := map[error]error{
		errors.New("Now you discharge yours"):
			errors.New("Now you discharge yours"),
		nodestore.NewNoNodeError("oops"): NewNoBlobError("oops"),
	}
	
	for causeerr, expectederr := range inputs {
		fsmock := new(fsmocks.FileStore)
		nsmock := new(nsmocks.NodeStore)
		bs := New(fsmock, nsmock)
		
		nsmock.On("GetUser", "un").Return(nuser, nil)
		
		nid, _ := uuid.Parse("f6029a11-0914-42b3-beea-fed420f75d7d")
		tme := time.Now()
		md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
		node, _ := nodestore.NewNode(nid, *nuser, 12, *md5, tme, nodestore.FileName("foo"))

		nsmock.On("GetNode", nid).Return(node, nil)

		nsmock.On("GetUser", "new").Return(newowner, nil)
		
		nsmock.On("ChangeOwner", nid, *newowner).Return(causeerr)

		bnode, err := bs.ChangeOwner(*auser, nid, "new")
		assert.Equal(t, expectederr, err, "incorrect error")
		assert.Nil(t, bnode, "expected error")
	}
}

func TestDeleteNode(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)
	bs := New(fsmock, nsmock)
	
	auser, _ := auth.NewUser("owner", false)
	
	o, _ := nodestore.NewUser(uuid.New(), "owner")
	nsmock.On("GetUser", "owner").Return(o, nil)

	nid, _ := uuid.Parse("f6029a11-0914-42b3-beea-fed420f75d7d")
	tme := time.Now()
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	node, _ := nodestore.NewNode(nid, *o, 12, *md5, tme, nodestore.FileName("foo"))

	nsmock.On("GetNode", nid).Return(node, nil)

	nsmock.On("DeleteNode", nid).Return(nil)

	fsmock.On("DeleteFile", "f6/02/9a/f6029a11-0914-42b3-beea-fed420f75d7d").Return(nil)

	err := bs.DeleteNode(*auser, nid)
	assert.Nil(t, err, "unexpected error")

	// test as admin
	auser, _ = auth.NewUser("notowner", true)
	no, _ := nodestore.NewUser(uuid.New(), "notowner")
	nsmock.On("GetUser", "notowner").Return(no, nil)
	err = bs.DeleteNode(*auser, nid)
	assert.Nil(t, err, "unexpected error")
}

func TestDeleteNodeFailGetUser(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := New(fsmock, nsmock)

	uid := uuid.New()
	auser, _ := auth.NewUser("un", false)

	nsmock.On("GetUser", "un").Return(nil, errors.New("no users here"))

	err := bs.DeleteNode(*auser, uid)
	assert.Equal(t, errors.New("no users here"), err, "incorrect error")
}

func TestDeleteNodeFailGetNode(t *testing.T) {
	uid := uuid.New()
	auser, _ := auth.NewUser("un", false)

	userid := uuid.New()
	nuser, _ := nodestore.NewUser(userid, "username")


	inputs := map[error]error{
		errors.New("I'm not"): errors.New("I'm not"),
		nodestore.NewNoNodeError("oops"): NewNoBlobError("oops"),
	}

	for causeerr, expectederr := range inputs {
		fsmock := new(fsmocks.FileStore)
		nsmock := new(nsmocks.NodeStore)
		bs := New(fsmock, nsmock)
		nsmock.On("GetUser", "un").Return(nuser, nil)

		nsmock.On("GetNode", uid).Return(nil, causeerr)
	
		err := bs.DeleteNode(*auser, uid)
		assert.Equal(t, expectederr, err, "incorrect error")
	}
}

func TestDeleteNodeFailUnauthorized(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := New(fsmock, nsmock)

	auser, _ := auth.NewUser("un", false)
	
	nuser, _ := nodestore.NewUser(uuid.New(), "un")

	nowner, _ := nodestore.NewUser(uuid.New(), "owner")
	
	nsmock.On("GetUser", "un").Return(nuser, nil)
	
	nid, _ := uuid.Parse("f6029a11-0914-42b3-beea-fed420f75d7d")
	tme := time.Now()
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	node, _ := nodestore.NewNode(nid, *nowner, 12, *md5, tme, nodestore.FileName("foo"))

	nsmock.On("GetNode", nid).Return(node, nil)

	err := bs.DeleteNode(*auser, nid)
	assert.Equal(t, NewUnauthorizedError("Unauthorized"), err, "incorrect error")
}

func TestDeleteNodeFailDeleteNode(t *testing.T) {
	auser, _ := auth.NewUser("un", false)
	
	nuser, _ := nodestore.NewUser(uuid.New(), "un")
	
	inputs := map[error]error{
		errors.New("vivian! You bastard"):
			errors.New("vivian! You bastard"),
		nodestore.NewNoNodeError("oops"): NewNoBlobError("oops"),
	}
	nid, _ := uuid.Parse("f6029a11-0914-42b3-beea-fed420f75d7d")
	
	for causeerr, expectederr := range inputs {
		fsmock := new(fsmocks.FileStore)
		nsmock := new(nsmocks.NodeStore)
		bs := New(fsmock, nsmock)
		
		nsmock.On("GetUser", "un").Return(nuser, nil)
		
		tme := time.Now()
		md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
		node, _ := nodestore.NewNode(nid, *nuser, 12, *md5, tme, nodestore.FileName("foo"))

		nsmock.On("GetNode", nid).Return(node, nil)

		nsmock.On("DeleteNode", nid).Return(causeerr)

		err := bs.DeleteNode(*auser, nid)
		assert.Equal(t, expectederr, err, "incorrect error")
	}
}

func TestDeleteNodeFailDeleteFile(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)
	bs := New(fsmock, nsmock)
	
	auser, _ := auth.NewUser("owner", false)
	
	o, _ := nodestore.NewUser(uuid.New(), "owner")
	nsmock.On("GetUser", "owner").Return(o, nil)

	nid, _ := uuid.Parse("f6029a11-0914-42b3-beea-fed420f75d7d")
	tme := time.Now()
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	node, _ := nodestore.NewNode(nid, *o, 12, *md5, tme, nodestore.FileName("foo"))

	nsmock.On("GetNode", nid).Return(node, nil)

	nsmock.On("DeleteNode", nid).Return(nil)

	fsmock.On("DeleteFile", "f6/02/9a/f6029a11-0914-42b3-beea-fed420f75d7d").Return(
		errors.New("whoopsie daisy"),
	)

	err := bs.DeleteNode(*auser, nid)
	assert.Equal(t, errors.New("whoopsie daisy"), err, "incorrect error")
}

func TestCopyNode(t *testing.T) {
	testCopyNodeWithFnF(t, "", "")
	testCopyNodeWithFnF(t, "filename.txt", "JSON")
}

func testCopyNodeWithFnF(t *testing.T, filename string, format string) {
	
	owner, _ := auth.NewUser("owner", false)
	admin, _ := auth.NewUser("admin", true)
	reader, _ := auth.NewUser("r1", true)
	noperms, _ := auth.NewUser("noperms", true)
	
	o, _ := nodestore.NewUser(uuid.New(), "owner")
	a, _ := nodestore.NewUser(uuid.New(), "admin")
	r1, _ := nodestore.NewUser(uuid.New(), "r1")
	r2, _ := nodestore.NewUser(uuid.New(), "r2")
	np, _ := nodestore.NewUser(uuid.New(), "noperms")
	
	nid, _ := uuid.Parse("f6029a11-0914-42b3-beea-fed420f75d7d")
	fid := "f6/02/9a/f6029a11-0914-42b3-beea-fed420f75d7d"
	tme, _ := time.Parse("2000-01-01T01:01:01Z01:00", time.RFC3339)
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	node, _ := nodestore.NewNode(nid, *o, 12, *md5, tme, nodestore.Reader(*r1),
		nodestore.Reader(*r2), nodestore.FileName(filename), nodestore.Format(format))

	pubnode, _ := nodestore.NewNode(nid, *o, 12, *md5, tme, nodestore.Public(true),
		nodestore.FileName(filename), nodestore.Format(format))


	newnid, _ := uuid.Parse("b6f2d8b7-429e-4639-b2d9-c619e4e9f4e1")
	newfid := "b6/f2/d8/b6f2d8b7-429e-4639-b2d9-c619e4e9f4e1"
	newtme, _ := time.Parse("2000-01-01T01:01:02Z01:00", time.RFC3339)

	type testcase struct {
		node *nodestore.Node
		user auth.User
		nuser nodestore.User
	}

	testcases := []testcase{
		testcase{node, *owner, *o},
		testcase{node, *admin, *a},
		testcase{node, *reader, *r1},
		testcase{pubnode, *noperms, *np},
	}

	for _, tc := range testcases {
		fsmock := new(fsmocks.FileStore)
		nsmock := new(nsmocks.NodeStore)
		uuidmock := new(cmocks.UUIDGen)
		bs := NewWithUUIDGen(fsmock, nsmock, uuidmock)

		nsmock.On("GetUser", tc.user.GetUserName()).Return(&tc.nuser, nil)
		nsmock.On("GetNode", nid).Return(tc.node, nil)
		uuidmock.On("GetUUID").Return(newnid)
		md5fake, _ := values.NewMD5("4d838d477ddf355fc15df1db90bee0aa")
		fsmock.On("CopyFile", fid, newfid).Return(
			&filestore.FileInfo{
				ID: newfid, Size: 120, Format: "ignored", Filename: "ignored", MD5: *md5fake,
				Stored: newtme},
			nil,
		)

		md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
		newnode, _ := nodestore.NewNode(newnid, tc.nuser, 12, *md5, newtme,
			nodestore.FileName(filename), nodestore.Format(format))
		nsmock.On("StoreNode", newnode).Return(nil)

		bnode, err := bs.CopyNode(tc.user, nid)
		assert.Nil(t, err, "unexpected error for user " + tc.user.GetUserName())
		expected := &BlobNode {
			ID: newnid,
			Size: 12,
			MD5: *md5,
			Stored: newtme,
			Filename: filename,
			Format: format,
			Owner: User{tc.nuser.GetID(), tc.user.GetUserName()},
			Readers: &[]User{User{tc.nuser.GetID(), tc.user.GetUserName()}},
			Public: false,
		}
		assert.Equal(t, expected, bnode, "incorrect node")
	}
}

func TestCopyNodeFailGetUser(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := New(fsmock, nsmock)

	uid := uuid.New()
	auser, _ := auth.NewUser("un", false)

	nsmock.On("GetUser", "un").Return(nil, errors.New("no users here"))

	bnode, err := bs.CopyNode(*auser, uid)
	assert.Nil(t, bnode, "expected error")
	assert.Equal(t, errors.New("no users here"), err, "incorrect error")
}

func TestCopyNodeFailGetNode(t *testing.T) {
	uid := uuid.New()
	auser, _ := auth.NewUser("un", false)

	userid := uuid.New()
	nuser, _ := nodestore.NewUser(userid, "username")


	inputs := map[error]error{
		errors.New("Bacon sandwich"): errors.New("Bacon sandwich"),
		nodestore.NewNoNodeError("oops"): NewNoBlobError("oops"),
	}

	for causeerr, expectederr := range inputs {
		fsmock := new(fsmocks.FileStore)
		nsmock := new(nsmocks.NodeStore)
		bs := New(fsmock, nsmock)
		nsmock.On("GetUser", "un").Return(nuser, nil)

		nsmock.On("GetNode", uid).Return(nil, causeerr)
	
		bnode, err := bs.CopyNode(*auser, uid)
		assert.Nil(t, bnode, "expected error")
		assert.Equal(t, expectederr, err, "incorrect error")
	}
}

func TestCopyNodeFailUnauthorized(t *testing.T) {
	fsmock := new(fsmocks.FileStore)
	nsmock := new(nsmocks.NodeStore)

	bs := New(fsmock, nsmock)

	auser, _ := auth.NewUser("un", false)
	
	nuser, _ := nodestore.NewUser(uuid.New(), "un")

	nowner, _ := nodestore.NewUser(uuid.New(), "owner")
	
	nsmock.On("GetUser", "un").Return(nuser, nil)
	
	nid, _ := uuid.Parse("f6029a11-0914-42b3-beea-fed420f75d7d")
	tme := time.Now()
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	node, _ := nodestore.NewNode(nid, *nowner, 12, *md5, tme, nodestore.FileName("foo"))

	nsmock.On("GetNode", nid).Return(node, nil)

	bnode, err := bs.CopyNode(*auser, nid)
	assert.Nil(t, bnode, "expected error")
	assert.Equal(t, NewUnauthorizedError("Unauthorized"), err, "incorrect error")
}

func TestCopyNodeFailCopyFile(t *testing.T) {
	owner, _ := auth.NewUser("owner", false)
	
	o, _ := nodestore.NewUser(uuid.New(), "owner")
	
	nid, _ := uuid.Parse("f6029a11-0914-42b3-beea-fed420f75d7d")
	fid := "f6/02/9a/f6029a11-0914-42b3-beea-fed420f75d7d"
	tme, _ := time.Parse("2000-01-01T01:01:01Z01:00", time.RFC3339)
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	node, _ := nodestore.NewNode(nid, *o, 12, *md5, tme)

	newnid, _ := uuid.Parse("b6f2d8b7-429e-4639-b2d9-c619e4e9f4e1")
	newfid := "b6/f2/d8/b6f2d8b7-429e-4639-b2d9-c619e4e9f4e1"
	fsmock := new(fsmocks.FileStore)
	
	nsmock := new(nsmocks.NodeStore)
	uuidmock := new(cmocks.UUIDGen)
	bs := NewWithUUIDGen(fsmock, nsmock, uuidmock)

	nsmock.On("GetUser", "owner").Return(o, nil)
	nsmock.On("GetNode", nid).Return(node, nil)
	uuidmock.On("GetUUID").Return(newnid)
	fsmock.On("CopyFile", fid, newfid).Return(nil, errors.New("well poop"))

	bnode, err := bs.CopyNode(*owner, nid)
	assert.Nil(t, bnode, "expected error")
	assert.Equal(t, errors.New("well poop"), err, "incorrect error")
}

func TestCopyNodeFailStoreNode(t *testing.T) {
	owner, _ := auth.NewUser("owner", false)
	
	o, _ := nodestore.NewUser(uuid.New(), "owner")
	
	nid, _ := uuid.Parse("f6029a11-0914-42b3-beea-fed420f75d7d")
	fid := "f6/02/9a/f6029a11-0914-42b3-beea-fed420f75d7d"
	tme, _ := time.Parse("2000-01-01T01:01:01Z01:00", time.RFC3339)
	md5, _ := values.NewMD5("5d838d477ddf355fc15df1db90bee0aa")
	node, _ := nodestore.NewNode(nid, *o, 12, *md5, tme)

	newnid, _ := uuid.Parse("b6f2d8b7-429e-4639-b2d9-c619e4e9f4e1")
	newfid := "b6/f2/d8/b6f2d8b7-429e-4639-b2d9-c619e4e9f4e1"
	fsmock := new(fsmocks.FileStore)
	
	nsmock := new(nsmocks.NodeStore)
	uuidmock := new(cmocks.UUIDGen)
	bs := NewWithUUIDGen(fsmock, nsmock, uuidmock)

	storedtime := time.Now()
	nsmock.On("GetUser", "owner").Return(o, nil)
	nsmock.On("GetNode", nid).Return(node, nil)
	uuidmock.On("GetUUID").Return(newnid)
	md5fake, _ := values.NewMD5("4d838d477ddf355fc15df1db90bee0aa")
	fsmock.On("CopyFile", fid, newfid).Return(
		&filestore.FileInfo{
			ID: newfid, Size: 120, Format: "ignored", Filename: "ignored", MD5: *md5fake,
			Stored: storedtime},
		nil,
	)

	newnode, _ := nodestore.NewNode(newnid, *o, 12, *md5, storedtime)
	nsmock.On("StoreNode", newnode).Return(errors.New("some error here"))

	bnode, err := bs.CopyNode(*owner, nid)
	assert.Nil(t, bnode, "expected error")
	assert.Equal(t, errors.New("some error here"), err, "incorrect error")
}