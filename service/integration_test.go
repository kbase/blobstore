package service

import (
	"github.com/sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/google/uuid"
	"io"
	"io/ioutil"
	"strings"
	"net/url"
	"github.com/kbase/blobstore/test/kbaseauthcontroller"
	"github.com/kbase/blobstore/test/miniocontroller"
	"context"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"github.com/kbase/blobstore/test/mongocontroller"
	"github.com/kbase/blobstore/test/testhelpers"
	"github.com/kbase/blobstore/config"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"

	logrust "github.com/sirupsen/logrus/hooks/test"
	"github.com/phayes/freeport"
	"github.com/stretchr/testify/suite"
)

const (
	testDB = "test_blobstore_integration"
	testBucket = "mybukkit"
	blobstoreRole = "BLOBSTORE_ADMIN"
	adminRole = "KBASE_ADMIN"
)

type User struct {
	user string
	token string
}

type TestSuite struct {
	suite.Suite
	s   *http.Server
	url string
	deleteTempDir bool
	mongo *mongocontroller.Controller
	mongoclient *mongo.Client
	minio *miniocontroller.Controller
	auth *kbaseauthcontroller.Controller
	loggerhook *logrust.Hook
	noRole User
	noRole2 User
	noRole3 User
	stdRole User
	kBaseAdmin User
}

func (t *TestSuite) SetupSuite() {
	tcfg, err := testhelpers.GetConfig()
	if err != nil {
		t.Fail(err.Error())
	}
	t.deleteTempDir = tcfg.DeleteTempDir

	t.mongo, t.mongoclient = t.setupMongo(tcfg)
	t.minio = t.setupMinio(tcfg)
	auth, authurl := t.setupAuth(tcfg)
	t.auth = auth
	t.setUpUsersAndRoles()

	roles := []string{adminRole, blobstoreRole}
	serv, err := New(
		&config.Config{
			Host: "foo", // not used
			MongoHost: "localhost:" + strconv.Itoa(t.mongo.GetPort()),
			MongoDatabase: testDB,
			S3Host: "localhost:" + strconv.Itoa(t.minio.GetPort()),
			S3Bucket: testBucket,
			S3AccessKey: "ackey",
			S3AccessSecret: "sooporsecret",
			S3Region: "us-west-1",
			S3DisableSSL: true,
			AuthURL: &authurl,
			AuthAdminRoles: &roles,

		},
		ServerStaticConf{
			ServerName:          "servn",
			ServerVersion:       "servver",
			ID:                  "shockyshock",
			ServerVersionCompat: "sver",
			DeprecationWarning:  "I shall deprecate the whold world! MuhahahahHAHA",
	})
	if err != nil {
		t.FailNow(err.Error())
	}

	port, err := freeport.GetFreePort()
	if err != nil {
		t.FailNow(err.Error())
	}

	t.url = "http://localhost:" + strconv.Itoa(port)
	fmt.Println("server url: " + t.url)
	t.s = &http.Server{
		Addr:    "localhost:" + strconv.Itoa(port),
		Handler: serv,
	}

	go func() {

		if err := t.s.ListenAndServe(); err != nil {
			t.FailNow(err.Error())
		}
	}()
	time.Sleep(50 * time.Millisecond) // wait for the server to start
	logrus.SetOutput(ioutil.Discard)
	t.loggerhook = logrust.NewGlobal()
}

func (t *TestSuite) setUpUsersAndRoles() {
	t.createTestUser("noroles")
	t.createTestUser("noroles2")
	t.createTestUser("noroles3")
	t.createTestUser("admin_std_role")
	t.createTestUser("admin_kbase")

	t.noRole = User{"noroles", t.createTestToken("noroles")}
	t.noRole2 = User{"noroles2", t.createTestToken("noroles2")}
	t.noRole3 = User{"noroles3", t.createTestToken("noroles3")}
	t.stdRole = User{"admin_std_role", t.createTestToken("admin_std_role")}
	t.kBaseAdmin = User{"admin_kbase", t.createTestToken("admin_kbase")}

	t.createTestRole(blobstoreRole)
	t.createTestRole(adminRole)

	t.addTestRole("admin_std_role", blobstoreRole)
	t.addTestRole("admin_kbase", adminRole)
}

func (t *TestSuite) createTestUser(username string) {
	if err := t.auth.CreateTestUser(username, "displayname"); err != nil {
		t.FailNow(err.Error())
	}
}

func (t *TestSuite) createTestToken(username string) string {
	token, err := t.auth.CreateTestToken(username)
	if err != nil {
		t.FailNow(err.Error())
	}
	return token
}

func (t *TestSuite) createTestRole(role string) {
	if err := t.auth.CreateTestRole(role, "description"); err != nil {
		t.FailNow(err.Error())
	}
}

func (t *TestSuite) addTestRole(username string, role string) {
	r := []string{role}
	if err := t.auth.SetTestUserRoles(username, &r); err != nil {
		t.FailNow(err.Error())
	}
}

func (t *TestSuite) setupAuth(cfg *testhelpers.TestConfig,
) (*kbaseauthcontroller.Controller, url.URL) {
	auth, err := kbaseauthcontroller.New(kbaseauthcontroller.Params{
		JarsDir: cfg.JarsDir,
		MongoHost: "localhost:" + strconv.Itoa(t.mongo.GetPort()),
		MongoDatabase: "test_kb_auth_provider_authdb",
		RootTempDir: cfg.TempDir,
	})
	if err != nil {
		t.FailNow(err.Error())
	}
	u, err := url.Parse("http://localhost:" + strconv.Itoa(auth.GetPort()) + "/testmode/")
	if err != nil {
		t.FailNow(err.Error())
	}
	return auth, *u
}

func (t *TestSuite) setupMinio(cfg *testhelpers.TestConfig) *miniocontroller.Controller {
	minio, err := miniocontroller.New(miniocontroller.Params{
		ExecutablePath: cfg.MinioExePath,
		AccessKey:      "ackey",
		SecretKey:      "sooporsecret",
		RootTempDir:    cfg.TempDir,
		Region:         "us-west-1",
	})
	if err != nil {
		t.FailNow(err.Error())
	}
	return minio
}

func (t *TestSuite) setupMongo(cfg *testhelpers.TestConfig,
) (*mongocontroller.Controller, *mongo.Client) {
	mongoctl, err := mongocontroller.New(mongocontroller.Params{
		ExecutablePath: cfg.MongoExePath,
		UseWiredTiger: cfg.UseWiredTiger,
		RootTempDir: cfg.TempDir,
	})
	if err != nil {
		t.FailNow(err.Error())
	}
	copts := options.ClientOptions{Hosts: []string{
		"localhost:" + strconv.Itoa(mongoctl.GetPort())}}
	err = copts.Validate()
	if err != nil {
		t.FailNow(err.Error())
	}
	client, err := mongo.Connect(context.Background(), &copts)	
	if err != nil {
		t.FailNow(err.Error())
	}
	return mongoctl, client
}

func (t *TestSuite) TearDownSuite() {
	if t.auth != nil {
		t.auth.Destroy(t.deleteTempDir)
	}
	if t.mongo != nil {
		t.mongo.Destroy(t.deleteTempDir)
	}
	if t.minio != nil {
		t.minio.Destroy(t.deleteTempDir)
	}
}

func (t *TestSuite) SetupTest() {
	t.mongoclient.Database(testDB).Drop(context.Background())
	t.minio.Clear(true)
	t.loggerhook.Reset()
}

func TestRunSuite(t *testing.T) {
	suite.Run(t, new(TestSuite))
}

type logEvent struct {
	Level logrus.Level
	Method string
	Path string
	Status int
	User *string
	Message string
	AddlFields map[string]interface{}
	MessageContains bool
}

func (t *TestSuite) checkLogs(events ...logEvent) {
	evs := t.loggerhook.AllEntries()
	t.Equal(len(events), len(evs), "incorrect number of log events")

	for i, expected := range events {
		got := evs[i]
		t.Equal(expected.Level, got.Level, "incorrect level")
		if expected.MessageContains {
			t.True(strings.Contains(got.Message, expected.Message),
				"incorrect message: " + got.Message)
		} else {
			t.Equal(expected.Message, got.Message, "incorrect message")
		}
		fields := map[string]interface{}(got.Data)
		ip := fields["ip"].(string)
		t.True(strings.HasPrefix(ip, "127.0.0.1:"), "incorrect ip") // can't test random port
		delete(fields, "ip")
		requestid := fields["requestid"].(string)
		t.Equal(16, len(requestid), "incorrect request id length")
		_, err := strconv.Atoi(requestid)
		t.Nil(err, "unexpected error coverting requestid to int")
		delete(fields, "requestid")
		var u interface{}
		if expected.User == nil {
			u = nil
		} else {
			u = *expected.User
		}

		expectedfields := map[string]interface{}{
			"method": expected.Method,
			"path": expected.Path,
			"user": u,
			"service": "BlobStore",
			"status": expected.Status,
		}
		for k, v := range expected.AddlFields {
			expectedfields[k] = v
		}
		t.Equal(expectedfields, fields, "incorrect fields")
	}
	t.loggerhook.Reset()
}

func mtmap() map[string]interface{} {
	return map[string]interface{}{}
}

func ptr(s string) *string {
	return &s
}

func (t *TestSuite) checkHeaders(r *http.Response, ctype string, lmin int64, lmax int64,
body map[string]interface{}) {
	t.Equal(ctype, r.Header.Get("content-type"),
		fmt.Sprintf("incorrect content-type for body\n%v\n", body))
	cl := r.ContentLength
	t.True(lmin <= cl, fmt.Sprintf("content-length %v < %v for body\n%v\n", cl, lmin, body))
	t.True(lmax >= cl, fmt.Sprintf("content-length %v > %v for body\n%v\n", cl, lmax, body))
}

func (t *TestSuite) TestRoot() {
	ret, err := http.Get(t.url)
	if err != nil {
		t.Fail(err.Error())
	}
	dec := json.NewDecoder(ret.Body)
	var root map[string]interface{}
	dec.Decode(&root)
	t.checkHeaders(ret, "application/json", 209, 211, root) // allow space for timestamp expansion

	// ugh. go isn't smart enough to use an int where possible
	servertime := root["servertime"].(float64)
	delete(root, "servertime")

	expected := map[string]interface{}{
		"servername":         "servn",
		"serverversion":      "servver",
		"id":                 "shockyshock",
		"version":            "sver",
		"deprecationwarning": "I shall deprecate the whold world! MuhahahahHAHA",
	}

	t.Equal(expected, root, "incorrect root return")

	expectedtime := time.Now().UnixNano() / 1000000

	// testify has comparisons in the works but not released as of this wring
	t.True(float64(expectedtime-1000) < servertime, "servertime earlier than expected")
	t.True(float64(expectedtime+1000) > servertime, "servertime later than expected")

	t.checkLogs(
		logEvent{logrus.InfoLevel, "GET", "/", 200, nil, "request complete", mtmap(), false},
	)
}

// TODO DOCS for store, get, get file
func (t *TestSuite) TestStoreAndGetWithFilename() {
	// check whitespace
	body := t.req("POST", t.url + "/node?filename=%20%20myfile%20%20",
		strings.NewReader("foobarbaz"), "     OAuth    " + t.noRole.token + "      ", 380)

	t.checkLogs(logEvent{logrus.InfoLevel, "POST", "/node", 200, ptr("noroles"),
		"request complete", mtmap(), false},
	)

	data := body["data"].(map[string]interface{})
	time := data["created_on"].(string)
	t.Equal(time, data["last_modified"], "incorrect last mod")
	delete(data, "created_on")
	delete(data, "last_modified")

	id := data["id"].(string)
	delete(data, "id")

	expected := map[string]interface{}{
		"data": map[string]interface{}{
			"attributes": nil,
			"format": "",
			"file": map[string]interface{}{
				"checksum": map[string]interface{}{"md5": "6df23dc03f9b54cc38a0fc1483df6e21"},
				"name": "myfile",
				"size": float64(9),
			},
		},
		"error": nil,
		"status": float64(200),
	}
	t.Equal(expected, body, "incorrect return")

	expected2 := map[string]interface{}{
		"data": map[string]interface{}{
			"attributes": nil,
			"created_on": time,
			"last_modified": time,
			"id": id,
			"format": "",
			"file": map[string]interface{}{
				"checksum": map[string]interface{}{"md5": "6df23dc03f9b54cc38a0fc1483df6e21"},
				"name": "myfile",
				"size": float64(9),
			},
		},
		"error": nil,
		"status": float64(200),
	}
	t.checkNode(id, &t.noRole, 380, expected2)

	path1 := "/node/" + id
	path2 := path1 + "/"
	t.checkFile(t.url + path1 + "?download", path1, &t.noRole, 9, "myfile", []byte("foobarbaz"))
	t.checkFile(t.url + path2 + "?download", path2, &t.noRole, 9, "myfile", []byte("foobarbaz"))
	t.checkFile(t.url + path1 + "?download_raw", path1, &t.noRole, 9, "", []byte("foobarbaz"))
	t.checkFile(t.url + path2 + "?download_raw", path2, &t.noRole, 9, "", []byte("foobarbaz"))
}

func (t *TestSuite) TestGetNodeAsAdminWithFormat() {
	body := t.req("POST", t.url + "/node?format=JSON", strings.NewReader("foobarbaz"),
		"oauth " + t.noRole.token, 378)
	t.checkLogs(logEvent{logrus.InfoLevel, "POST", "/node", 200, ptr("noroles"),
		"request complete", mtmap(), false},
	)

	data := body["data"].(map[string]interface{})
	time := data["created_on"].(string)
	id := data["id"].(string)

	expected := map[string]interface{}{
		"data": map[string]interface{}{
			"attributes": nil,
			"created_on": time,
			"last_modified": time,
			"id": id,
			"format": "JSON",
			"file": map[string]interface{}{
				"checksum": map[string]interface{}{"md5": "6df23dc03f9b54cc38a0fc1483df6e21"},
				"name": "",
				"size": float64(9),
			},
		},
		"error": nil,
		"status": float64(200),
	}
	path := "/node/" + id
	t.checkNode(id, &t.stdRole, 378, expected)
	t.checkFile(t.url + path + "?download", path, &t.stdRole, 9, id, []byte("foobarbaz"))
	t.checkFile(t.url + path + "?download_raw", path, &t.stdRole, 9, "", []byte("foobarbaz"))
	t.checkNode(id, &t.kBaseAdmin, 378, expected)
	t.checkFile(t.url + path + "?download", path, &t.kBaseAdmin, 9, id, []byte("foobarbaz"))
	t.checkFile(t.url + path + "?download_raw", path, &t.kBaseAdmin, 9, "", []byte("foobarbaz"))
}

func (t *TestSuite) TestGetNodeFileACLPublic() {
	// not testing logging here, tested elsewhere
	body := t.req("POST", t.url + "/node", strings.NewReader("foobarbaz"),
		"OAuth " + t.kBaseAdmin.token, 374)
	uid := t.getUserIDFromMongo(t.kBaseAdmin.user)

	data := body["data"].(map[string]interface{})
	time := data["created_on"].(string)
	id := data["id"].(string)

	expected := map[string]interface{}{
		"data": map[string]interface{}{
			"attributes": nil,
			"created_on": time,
			"last_modified": time,
			"id": id,
			"format": "",
			"file": map[string]interface{}{
				"checksum": map[string]interface{}{"md5": "6df23dc03f9b54cc38a0fc1483df6e21"},
				"name": "",
				"size": float64(9),
			},
		},
		"error": nil,
		"status": float64(200),
	}

	expectedacl := map[string]interface{}{
		"data": map[string]interface{}{
			"owner": uid,
			"write": []interface{}{uid},
			"delete": []interface{}{uid},
			"read": []interface{}{uid},
			"public": map[string]interface{}{
				"read": true,
				"write": false,
				"delete": false,
			},
		},
		"error": nil,
		"status": float64(200),
	}

	t.getNodeFailUnauth(id, &t.noRole)

	t.req("PUT", t.url + "/node/" + id + "/acl/public_read", nil, "OAuth " + t.kBaseAdmin.token,
		394)
	t.loggerhook.Reset()

	for _, u := range []*User{&t.noRole, nil} {
		t.checkNode(id, u, 374, expected)
		t.checkACL(id, "", "", u, 394, expectedacl)
		t.checkFile(t.url + "/node/" + id + "?download", "/node/" + id, u, 9, id,
			[]byte("foobarbaz"))
	}

	t.req("DELETE", t.url + "/node/" + id + "/acl/public_read", nil, "OAuth " + t.kBaseAdmin.token,
		395)
	
	t.getNodeFailUnauth(id, &t.noRole)
}

func (t *TestSuite) getNodeFailUnauth(id string, user *User) {
	for _, u := range []*User{user, nil} {
		nodeb := t.get(t.url + "/node/" + id, u, 78)
		t.checkError(nodeb, 401, "User Unauthorized")
		nodeb = t.get(t.url + "/node/" + id + "?download", u, 78)
		t.checkError(nodeb, 401, "User Unauthorized")
		aclb := t.get(t.url + "/node/" + id + "/acl/", u, 78)
		t.checkError(aclb, 401, "User Unauthorized")
		t.loggerhook.Reset()
	}
}

func (t *TestSuite) req(
	method string,
	urell string,
	data io.Reader,
	token string,
	contentLength int64,
) map[string]interface{} {
	req, err := http.NewRequest(method, urell, data)
	t.Nil(err, "unexpected error")
	if token != "" {
		req.Header.Set("authorization", token)
	}
	return t.requestToJSON(req, contentLength)
}

// TODO DOCS document effect of sending large file with incorrect content-length

//TODO TEST check status code
func (t *TestSuite) get(url string, user *User, contentLength int64) map[string]interface{} {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	t.Nil(err, "unexpected error")
	if user != nil {
		req.Header.Set("authorization", "oauth " + user.token)
	}
	return t.requestToJSON(req, contentLength)
}

func (t *TestSuite) requestToJSON(req *http.Request, contentLength int64) map[string]interface{} {
	resp, err := http.DefaultClient.Do(req)
	t.Nil(err, "unexpected error")
	b, err := ioutil.ReadAll(resp.Body)
	// fmt.Println(string(b))
	t.Nil(err, "unexpected error")
	var body map[string]interface{}
	json.Unmarshal(b, &body)
	t.checkHeaders(resp, "application/json", contentLength, contentLength, body)
	return body
}

func (t *TestSuite) checkFile(url string, path string, user *User, size int64, filename string,
expected []byte) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	t.Nil(err, "unexpected error")
	if user != nil {
		req.Header.Set("authorization", "oauth " + user.token)
	}
	resp, err := http.DefaultClient.Do(req)
	t.checkHeaders(resp, "application/octet-stream", size, size,
		map[string]interface{}{"body": "was file"})
	if filename == "" {
		t.Equal("", resp.Header.Get("content-disposition"), "incorrect content-disposition")
	} else {
		t.Equal("attachment; filename=" + filename, resp.Header.Get("content-disposition"),
			"incorrect content-disposition")
	}
	t.Nil(err, "unexpected error")
	b, err := ioutil.ReadAll(resp.Body)
	t.Nil(err, "unexpected error")
	t.Equal(expected, b, "incorrect file")

	t.checkLogs(logEvent{logrus.InfoLevel, "GET", path, 200, getUserName(user),
		"request complete", mtmap(), false},
	)
}

func getUserName(user *User) *string {
	if user != nil {
		return &user.user
	}
	return nil
}

func (t *TestSuite) checkNode(id string, user *User, contentLength int64,
expected map[string]interface{}) {
	body := t.get(t.url + "/node/" + id, user, contentLength)

	t.checkLogs(logEvent{logrus.InfoLevel, "GET", "/node/" + id, 200, getUserName(user),
		"request complete", mtmap(), false},
	)
	t.Equal(expected, body, "incorrect return")
}

func (t *TestSuite) checkError(err map[string]interface{}, code int, errorstr string) {
	expected := map[string]interface{}{
		"data": nil,
		"status": float64(code),
		"error": []interface{}{errorstr},
	}
	t.Equal(expected, err, "incorrect return")
}

func (t *TestSuite) TestBadToken() {
	for _, token := range []string{
			"oauth",
			"oauth   ",
			"oath " + t.noRole.token,
			"oauth bad_token",
			"oauth " + t.noRole.token + " foo"} {
		body := t.req("POST", t.url + "/node", strings.NewReader("foobarbaz"), token, 100)
		t.checkError(body, 400, "Invalid authorization header or content")
		t.checkLogs(logEvent{logrus.ErrorLevel, "POST", "/node", 400, nil,
			"Invalid authorization header or content", mtmap(), false},
		)
	}
}

func (t *TestSuite) TestNoContentLength() {
	req, err := http.NewRequest(http.MethodPost, t.url + "/node", strings.NewReader("foobarbaz"))
	t.Nil(err, "unexpected error")
	req.Header.Set("authorization", "OAuth " + t.noRole.token)
	req.ContentLength = -1
	body := t.requestToJSON(req, 76)

	t.checkError(body, 411, "Length Required")
	t.checkLogs(logEvent{logrus.ErrorLevel, "POST", "/node", 411, &t.noRole.user,
		"Length Required", mtmap(), false},
	)
}

func (t *TestSuite) TestStoreNoUser() {
	body := t.req("POST", t.url + "/node", strings.NewReader("foobarbaz"), "", 77)
	t.checkError(body, 401, "No Authorization")
	t.checkLogs(logEvent{logrus.ErrorLevel, "POST", "/node", 401, nil,
		"No Authorization", mtmap(), false},
	)
}

func (t *TestSuite) TestGetNodeBadID() {
	body := t.get(t.url + "/node/badid", &t.noRole, 75)
	t.checkError(body, 404, "Node not found")
	t.checkLogs(logEvent{logrus.ErrorLevel, "GET", "/node/badid", 404, &t.noRole.user,
		"Node not found", mtmap(), false},
	)

	body2 := t.get(t.url + "/node/badid?download", &t.noRole, 75)
	t.checkError(body2, 404, "Node not found")
	t.checkLogs(logEvent{logrus.ErrorLevel, "GET", "/node/badid", 404, &t.noRole.user,
		"Node not found", mtmap(), false},
	)
	
	uid := uuid.New()
	body3 := t.get(t.url + "/node/" + uid.String(), &t.noRole, 75)
	t.checkError(body3, 404, "Node not found")
	t.checkLogs(logEvent{logrus.ErrorLevel, "GET", "/node/" + uid.String(), 404, &t.noRole.user,
		"Node not found", mtmap(), false},
	)
	
	body4 := t.get(t.url + "/node/" + uid.String() + "?download", &t.noRole, 75)
	t.checkError(body4, 404, "Node not found")
	t.checkLogs(logEvent{logrus.ErrorLevel, "GET", "/node/" + uid.String(), 404, &t.noRole.user,
		"Node not found", mtmap(), false},
	)
}

func (t *TestSuite) TestGetNodeFailPerms() {
	body := t.req("POST", t.url + "/node", strings.NewReader("foobarbaz"),
		"OAuth " + t.kBaseAdmin.token, 374)
	id := (body["data"].(map[string]interface{}))["id"].(string)
	t.checkLogs(logEvent{logrus.InfoLevel, "POST", "/node", 200, &t.kBaseAdmin.user,
		"request complete", mtmap(), false},
	)
	
	nodeb := t.get(t.url + "/node/" + id, &t.noRole, 78)
	t.checkError(nodeb, 401, "User Unauthorized")
	t.checkLogs(logEvent{logrus.ErrorLevel, "GET", "/node/" + id, 401, &t.noRole.user,
		"User Unauthorized", mtmap(), false},
	)
	nodeb2 := t.get(t.url + "/node/" + id, nil, 78)
	t.checkError(nodeb2, 401, "User Unauthorized")
	t.checkLogs(logEvent{logrus.ErrorLevel, "GET", "/node/" + id, 401, nil,
		"User Unauthorized", mtmap(), false},
	)
	nodeb3 := t.get(t.url + "/node/" + id + "?download", &t.noRole, 78)
	t.checkError(nodeb3, 401, "User Unauthorized")
	t.checkLogs(logEvent{logrus.ErrorLevel, "GET", "/node/" + id, 401, &t.noRole.user,
		"User Unauthorized", mtmap(), false},
	)
	nodeb4 := t.get(t.url + "/node/" + id + "?download", nil, 78)
	t.checkError(nodeb4, 401, "User Unauthorized")
	t.checkLogs(logEvent{logrus.ErrorLevel, "GET", "/node/" + id, 401, nil,
		"User Unauthorized", mtmap(), false},
	)
}

func (t *TestSuite) TestUnexpectedError() {
	defer t.createTestBucket()
	body := t.req("POST", t.url + "/node", strings.NewReader("foobarbaz"),
		"OAuth " + t.kBaseAdmin.token, 374)
	id := (body["data"].(map[string]interface{}))["id"].(string)
	t.checkLogs(logEvent{logrus.InfoLevel, "POST", "/node", 200, &t.kBaseAdmin.user,
		"request complete", mtmap(), false},
	)

	t.minio.Clear(false) // delete the file data, but not the node data

	node := t.get(t.url + "/node/" + id + "?download", &t.kBaseAdmin, 185)
	t.Equal(float64(500), node["status"].(float64), "incorrect code")
	t.Nil(node["data"], "expected no data")
	err := node["error"].([]interface{})
	t.Equal(1, len(err), "incorrect error size")
	errmsg := "s3 store get: NoSuchBucket: The specified bucket does not exist\n" +
		"\tstatus code: 404, request id: "
	t.True(strings.HasPrefix(err[0].(string), errmsg))
	t.checkLogs(logEvent{logrus.ErrorLevel, "GET", "/node/" + id, 500, &t.kBaseAdmin.user,
		errmsg, mtmap(), true},
	)
}

func (t *TestSuite) createTestBucket() {
	cli := t.minio.CreateS3Client()
	input := &s3.CreateBucketInput{Bucket: aws.String(testBucket)}
	_, err := cli.CreateBucket(input)
	if err != nil {
		t.FailNow(err.Error())
	}
}

func (t *TestSuite) TestNotFound() {
	body := t.req("POST", t.url + "/nde", strings.NewReader("foobarbaz"),
	"OAuth " + t.kBaseAdmin.token, 70)
	t.checkError(body, 404, "Not Found")
	t.checkLogs(logEvent{logrus.ErrorLevel, "POST", "/nde", 404, nil, "Not Found", mtmap(), false})
}

func (t *TestSuite) TestNotAllowed() {
	body := t.get(t.url + "/node", nil, 79)
	t.checkError(body, 405, "Method Not Allowed")
	t.checkLogs(logEvent{logrus.ErrorLevel, "GET", "/node", 405, nil, "Method Not Allowed",
		mtmap(), false},
	)
}

func (t *TestSuite) TestGetACLs() {
	body := t.req("POST", t.url + "/node", strings.NewReader("foobarbaz"),
		"OAuth " + t.noRole.token, 374)
	t.loggerhook.Reset() // tested this enough already
	id := (body["data"].(map[string]interface{}))["id"].(string)
	// ID gen is random, so we'll just fetch the generated ID from the DB.
	// Cheating kinda
	uid := t.getUserIDFromMongo(t.noRole.user)

	expected := map[string]interface{}{
		"data": map[string]interface{}{
			"owner": uid,
			"write": []interface{}{uid},
			"delete": []interface{}{uid},
			"read": []interface{}{uid},
			"public": map[string]interface{}{
				"read": false,
				"write": false,
				"delete": false,
			},
		},
		"error": nil,
		"status": float64(200),
	}

	for _, urlsuffix := range []string{"", "/owner", "/read", "/write", "/delete",
		"/public_read", "/public_write", "/public_delete"} {

		t.checkACL(id, urlsuffix, "", &t.noRole, 395, expected)
		t.checkACL(id, urlsuffix + "/", "", &t.noRole, 395, expected)
	}
}

// assumes only 1 user in mongo
func (t *TestSuite) getUserIDFromMongo(name string) string {
	muser := t.mongoclient.Database(testDB).Collection("users").FindOne(nil, map[string]string{
		"user": name,
	})
	t.Nil(muser.Err(), "error getting mongo user")
	var udoc map[string]interface{}
	err := muser.Decode(&udoc)
	t.Nil(err, "unexpected error")
	uid, _ := udoc["id"].(string)
	return uid
}

func (t *TestSuite) TestGetACLAsAdminVerbose() {
	body := t.req("POST", t.url + "/node", strings.NewReader("foobarbaz"),
		"OAuth " + t.noRole.token, 374)
	t.loggerhook.Reset() // tested this enough already
	id := (body["data"].(map[string]interface{}))["id"].(string)
	// ID gen is random, so we'll just fetch the generated ID from the DB.
	// Cheating kinda
	uid := t.getUserIDFromMongo(t.noRole.user)

	vuser := map[string]interface{}{"uuid": uid, "username": t.noRole.user}
	expectedverbose := map[string]interface{}{
		"data": map[string]interface{}{
			"owner": vuser,
			"write": []interface{}{vuser},
			"delete": []interface{}{vuser},
			"read": []interface{}{vuser},
			"public": map[string]interface{}{
				"read": false,
				"write": false,
				"delete": false,
			},
		},
		"error": nil,
		"status": float64(200),
	}

	for _, urlsuffix := range []string{"", "/owner", "/read", "/write", "/delete",
		"/public_read", "/public_write", "/public_delete"} {

		t.checkACL(id, urlsuffix, "?verbosity=full", &t.kBaseAdmin, 617, expectedverbose)
		t.checkACL(id, urlsuffix + "/", "?verbosity=full", &t.kBaseAdmin, 617, expectedverbose)
	}
}

func (t *TestSuite) checkACL(id string, urlsuffix string, params string, user *User,
contentLength int64, expected map[string]interface{}) {
	body := t.get(t.url + "/node/" + id + "/acl" + urlsuffix + params, user, contentLength)

	t.checkLogs(logEvent{logrus.InfoLevel, "GET", "/node/" + id + "/acl" + urlsuffix, 200,
		getUserName(user), "request complete", mtmap(), false},
	)
	t.Equal(expected, body, "incorrect return")
}

// TODO TEST need to check errors for logs below this line
func (t *TestSuite) TestGetACLsBadType() {
	body := t.req("POST", t.url + "/node", strings.NewReader("foobarbaz"),
		"OAuth " + t.noRole.token, 374)
	t.loggerhook.Reset() // tested this enough already
	id := (body["data"].(map[string]interface{}))["id"].(string)
	body2 := t.get(t.url + "/node/" + id + "/acl/pubwic_wead", &t.noRole, 77)
	t.checkError(body2, 400, "Invalid acl type")
}

func (t *TestSuite) TestGetACLsBadID() {
	body := t.get(t.url + "/node/badid/acl", &t.noRole, 75)
	t.checkError(body, 404, "Node not found")
	t.checkLogs(logEvent{logrus.ErrorLevel, "GET", "/node/badid/acl", 404, &t.noRole.user,
		"Node not found", mtmap(), false},
	)

	uid := uuid.New()
	body2 := t.get(t.url + "/node/" + uid.String() + "/acl", &t.noRole, 75)
	t.checkError(body2, 404, "Node not found")
	t.checkLogs(logEvent{logrus.ErrorLevel, "GET", "/node/" + uid.String() + "/acl", 404,
		&t.noRole.user, "Node not found", mtmap(), false},
	)
}

func (t *TestSuite) TestGetACLsFailPerms() {
	body := t.req("POST", t.url + "/node", strings.NewReader("foobarbaz"),
		"OAuth " + t.kBaseAdmin.token, 374)
	id := (body["data"].(map[string]interface{}))["id"].(string)
	t.loggerhook.Reset()
	
	nodeb := t.get(t.url + "/node/" + id + "/acl", &t.noRole, 78)
	t.checkError(nodeb, 401, "User Unauthorized")
	t.checkLogs(logEvent{logrus.ErrorLevel, "GET", "/node/" + id + "/acl", 401, &t.noRole.user,
		"User Unauthorized", mtmap(), false},
	)

	nodeb = t.get(t.url + "/node/" + id + "/acl", nil, 78)
	t.checkError(nodeb, 401, "User Unauthorized")
	t.checkLogs(logEvent{logrus.ErrorLevel, "GET", "/node/" + id + "/acl", 401, nil,
		"User Unauthorized", mtmap(), false},
	)
}

func (t *TestSuite) TestSetGlobalACLs() {
	body := t.req("POST", t.url + "/node", strings.NewReader("foobarbaz"),
		"OAuth " + t.noRole.token, 374)
	id := (body["data"].(map[string]interface{}))["id"].(string)
	t.loggerhook.Reset()
	uid := t.getUserIDFromMongo(t.noRole.user)

	type testcase struct {
		method string
		urlsuffix string
		publicread bool
		user User
		verbose bool
		conlen int64
	}

	testcases := []testcase{
		testcase{"PUT", "public_read", true, t.noRole, false, 394},
		testcase{"DELETE", "public_read", false, t.noRole, true, 617},
		testcase{"PUT", "public_read", true, t.kBaseAdmin, true, 616}, // as admin
		testcase{"DELETE", "public_read", false, t.kBaseAdmin, false, 395}, // as admin
		testcase{"PUT", "public_write", false, t.noRole, false, 395}, // silently do nothing
		testcase{"PUT", "public_delete", false, t.noRole, false, 395}, // silently do nothing
		testcase{"DELETE", "public_write", false, t.noRole, false, 395}, // silently do nothing
		testcase{"DELETE", "public_delete", false, t.noRole, false, 395}, // silently do nothing
	}

	for _, tc := range testcases {
		path := "/node/" + id + "/acl/" + tc.urlsuffix
		var owner interface{} = uid

		params := ""
		if tc.verbose {
			params = "?verbosity=full"
			owner = map[string]interface{}{"uuid": uid, "username": t.noRole.user}
		}
		
		expected := map[string]interface{}{
			"data": map[string]interface{}{
				"owner": owner,
				"write": []interface{}{owner},
				"delete": []interface{}{owner},
				"read": []interface{}{owner},
				"public": map[string]interface{}{
					"read": tc.publicread,
					"write": false,
					"delete": false,
				},
			},
			"error": nil,
			"status": float64(200),
		}

		body := t.req(tc.method, t.url + path + params, nil, "OAuth " + tc.user.token, tc.conlen)
		t.checkLogs(logEvent{logrus.InfoLevel, tc.method, path, 200,
			getUserName(&tc.user), "request complete", mtmap(), false},
		)
		t.Equal(expected, body, fmt.Sprintf("incorrect return for case %v", tc))
		t.checkACL(id, "", params, &tc.user, tc.conlen, expected)

		path = path + "/"
		body = t.req(tc.method, t.url + path + params, nil, "OAuth " + tc.user.token, tc.conlen)
		t.checkLogs(logEvent{logrus.InfoLevel, tc.method, path, 200,
			getUserName(&tc.user), "request complete", mtmap(), false},
		)
		t.Equal(expected, body, fmt.Sprintf("incorrect return for trailing slash w/ case %v", tc))
		t.checkACL(id, "", params, &tc.user, tc.conlen, expected)
	}
}

func (t *TestSuite) TestSetGlobalACLsFail() {
	body := t.req("POST", t.url + "/node", strings.NewReader("foobarbaz"),
		"OAuth " + t.kBaseAdmin.token, 374)
	id := (body["data"].(map[string]interface{}))["id"].(string)

	type testcase struct {
		method string
		urlsuffix string
		token string
		status int
		errstring string
		conlen int64
	}

	longun := "Users that are not node owners can only delete themselves from ACLs."
	invauth := "Invalid authorization header or content"
	badid := uuid.New().String()
	testcases := []testcase{
		testcase{"PUT", id + "/acl/pubwic_wead", "", 400, "Invalid acl type", 77},
		testcase{"DELETE", id + "/acl/pubwic_dewete", "", 400, "Invalid acl type", 77},
		testcase{"PUT", "/badid/acl/public_read", "", 404, "Node not found", 75},
		testcase{"DELETE", "/worseid/acl/public_write", "", 404, "Node not found", 75},
		testcase{"PUT", id + "/acl/public_read", "", 401, "No Authorization", 77},
		testcase{"DELETE", id + "/acl/public_write", "", 401, "No Authorization", 77},
		testcase{"PUT", id + "/acl/public_read", "oauth badtoken", 400, invauth, 100},
		testcase{"DELETE", id + "/acl/public_read", "oauth badtoken", 400, invauth, 100},
		testcase{"PUT", badid + "/acl/public_read", "Oauth " + t.noRole.token, 404,
			"Node not found", 75},
		testcase{"DELETE", badid + "/acl/public_read", "Oauth " + t.noRole.token, 404,
			"Node not found", 75},
		testcase{"PUT", id + "/acl/public_read", "Oauth " + t.noRole.token, 400, longun, 129},
		testcase{"DELETE", id + "/acl/public_read", "Oauth " + t.noRole.token, 400, longun, 129},
	}

	for _, tc := range testcases {
		body := t.req(tc.method, t.url + "/node/" + tc.urlsuffix, nil, tc.token, tc.conlen)
		t.checkError(body, tc.status, tc.errstring)
	}
}

func (t *TestSuite) TestSetIgnoredACLs() {
	// write and delete acl change requests are silently ignored, since we don't support
	// those acls
	body := t.req("POST", t.url + "/node", strings.NewReader("foobarbaz"),
		"Oauth " + t.noRole.token, 374)
	id := (body["data"].(map[string]interface{}))["id"].(string)
	t.loggerhook.Reset()
	uid := t.getUserIDFromMongo(t.noRole.user)
	type testcase struct {
		method string
		urlsuffix string
		user User
		verbose bool
		conlen int64
	}

	testcases := []testcase{
		testcase{"PUT", "write", t.noRole, false, 395},
		testcase{"DELETE", "write", t.noRole, true, 617},
		testcase{"PUT", "write", t.kBaseAdmin, true, 617}, // as admin
		testcase{"DELETE", "write", t.kBaseAdmin, false, 395}, // as admin
		testcase{"PUT", "delete", t.noRole, false, 395},
		testcase{"DELETE", "delete", t.noRole, false, 395},
	}

	for _, tc := range testcases {
		path := "/node/" + id + "/acl/" + tc.urlsuffix
		var owner interface{} = uid

		params := "?users=" + t.stdRole.user
		if tc.verbose {
			params += ";verbosity=full"
			owner = map[string]interface{}{"uuid": uid, "username": t.noRole.user}
		}
		
		expected := map[string]interface{}{
			"data": map[string]interface{}{
				"owner": owner,
				"write": []interface{}{owner},
				"delete": []interface{}{owner},
				"read": []interface{}{owner},
				"public": map[string]interface{}{
					"read": false,
					"write": false,
					"delete": false,
				},
			},
			"error": nil,
			"status": float64(200),
		}

		body := t.req(tc.method, t.url + path + params, nil, "Oauth " + tc.user.token, tc.conlen)
		t.checkLogs(logEvent{logrus.InfoLevel, tc.method, path, 200,
			getUserName(&tc.user), "request complete", mtmap(), false},
		)
		t.Equal(expected, body, fmt.Sprintf("incorrect return for case %v", tc))
		t.checkACL(id, "", params, &tc.user, tc.conlen, expected)

		path = path + "/"
		body = t.req(tc.method, t.url + path + params, nil, "Oauth " + tc.user.token, tc.conlen)
		t.checkLogs(logEvent{logrus.InfoLevel, tc.method, path, 200,
			getUserName(&tc.user), "request complete", mtmap(), false},
		)
		t.Equal(expected, body, fmt.Sprintf("incorrect return for trailing slash w/ case %v", tc))
		t.checkACL(id, "", params, &tc.user, tc.conlen, expected)
	}
}

func (t *TestSuite) TestSetReadACL() {
	body := t.req("POST", t.url + "/node", strings.NewReader("foobarbaz"),
		"Oauth " + t.noRole.token, 374)
	uid := t.getUserIDFromMongo(t.noRole.user)
	t.loggerhook.Reset()

	data := body["data"].(map[string]interface{})
	time := data["created_on"].(string)
	id := data["id"].(string)
	
	expected := map[string]interface{}{
		"data": map[string]interface{}{
			"attributes": nil,
			"created_on": time,
			"last_modified": time,
			"id": id,
			"format": "",
			"file": map[string]interface{}{
				"checksum": map[string]interface{}{"md5": "6df23dc03f9b54cc38a0fc1483df6e21"},
				"name": "",
				"size": float64(9),
			},
		},
		"error": nil,
		"status": float64(200),
	}

	owner := map[string]interface{}{"uuid": uid, "username": t.noRole.user}

	// check no readers and non-admins can't read
	t.checkACL(id, "", "", &t.noRole, 395, getExpectedACL(owner, []map[string]interface{}{},false))
	t.getNodeFailUnauth(id, &t.noRole2)
	t.getNodeFailUnauth(id, &t.noRole3)
	t.loggerhook.Reset()

	// add readers as owner. Also check whitespace is ignored.
	body = t.req("PUT", t.url + "/node/" + id + "/acl/read?users=%20%20,%20%20%20,%20%20" +
		t.noRole2.user + "%20%20,%20%20" + t.noRole3.user, nil, "Oauth " + t.noRole.token, 487)
	t.checkLogs(logEvent{logrus.InfoLevel, "PUT", "/node/" + id + "/acl/read", 200,
		&t.noRole.user, "request complete", mtmap(), false},
	)
	
	u2 := map[string]interface{}{
		"uuid": t.getUserIDFromMongo(t.noRole2.user),
		"username": t.noRole2.user,
	}
	u3 := map[string]interface{}{
		"uuid": t.getUserIDFromMongo(t.noRole3.user),
		"username": t.noRole3.user,
	}
	expectedACL := getExpectedACL(owner, []map[string]interface{}{u2, u3}, false)
	t.Equal(expectedACL, body, "incorrect acls")

	for _, u := range []*User{&t.noRole2, &t.noRole3} {
		t.checkNode(id, u, 374, expected)
		t.checkACL(id, "", "", u, 487, expectedACL)
		t.checkFile(t.url + "/node/" + id + "?download", "/node/" + id, u, 9, id,
			[]byte("foobarbaz"))
	}
	t.loggerhook.Reset()

	// remove readers as owner with verbose response and trailing slash
	body = t.req("DELETE", t.url + "/node/" + id + "/acl/read/?verbosity=full;users=" +
		t.noRole2.user, nil, "Oauth " + t.noRole.token, 721)
	t.checkLogs(logEvent{logrus.InfoLevel, "DELETE", "/node/" + id + "/acl/read/", 200,
		&t.noRole.user, "request complete", mtmap(), false},
	)
	expectedACL = getExpectedACL(owner, []map[string]interface{}{u3}, true)
	t.Equal(expectedACL, body, "incorrect acls")
	t.getNodeFailUnauth(id, &t.noRole2)
	t.checkNode(id, &t.noRole3, 374, expected)
	t.checkACL(id, "", "?verbosity=full", &t.noRole3, 721, expectedACL)
	t.checkFile(t.url + "/node/" + id + "?download", "/node/" + id, &t.noRole3, 9, id,
		[]byte("foobarbaz"))

	// add readers as admin with verbose response
	body = t.req("PUT", t.url + "/node/" + id + "/acl/read?verbosity=full;users=" +
		t.noRole2.user + "," + t.noRole3.user, nil, "Oauth " + t.stdRole.token, 825)
	t.checkLogs(logEvent{logrus.InfoLevel, "PUT", "/node/" + id + "/acl/read", 200,
		&t.stdRole.user, "request complete", mtmap(), false},
	)

	expectedACL = getExpectedACL(owner, []map[string]interface{}{u3, u2}, true)
	t.Equal(expectedACL, body, "incorrect acls")

	for _, u := range []*User{&t.noRole2, &t.noRole3} {
		t.checkNode(id, u, 374, expected)
		t.checkACL(id, "", "?verbosity=full", u, 825, expectedACL)
		t.checkFile(t.url + "/node/" + id + "?download", "/node/" + id, u, 9, id,
			[]byte("foobarbaz"))
	}
	t.loggerhook.Reset()

	// remove readers as admin with trailing slash, check whitespace is ignored
	body = t.req("DELETE", t.url + "/node/" + id + "/acl/read/?users=%20%20,%20%20,%20" +
		t.noRole2.user + ",%20%20" +  t.noRole3.user, nil, "Oauth " + t.stdRole.token, 395)
	t.checkLogs(logEvent{logrus.InfoLevel, "DELETE", "/node/" + id + "/acl/read/", 200,
		&t.stdRole.user, "request complete", mtmap(), false},
	)
	expectedACL = getExpectedACL(owner, []map[string]interface{}{}, false)
	t.Equal(expectedACL, body, "incorrect acls")
	t.getNodeFailUnauth(id, &t.noRole2)
	t.getNodeFailUnauth(id, &t.noRole3)
}

func (t *TestSuite) TestRemoveSelfFromReadACL() {
	body := t.req("POST", t.url + "/node", strings.NewReader("foobarbaz"),
		"Oauth " + t.noRole.token, 374)
	uid := t.getUserIDFromMongo(t.noRole.user)
	t.loggerhook.Reset()

	data := body["data"].(map[string]interface{})
	time := data["created_on"].(string)
	id := data["id"].(string)
	
	expected := map[string]interface{}{
		"data": map[string]interface{}{
			"attributes": nil,
			"created_on": time,
			"last_modified": time,
			"id": id,
			"format": "",
			"file": map[string]interface{}{
				"checksum": map[string]interface{}{"md5": "6df23dc03f9b54cc38a0fc1483df6e21"},
				"name": "",
				"size": float64(9),
			},
		},
		"error": nil,
		"status": float64(200),
	}

	owner := map[string]interface{}{"uuid": uid, "username": t.noRole.user}

	// check no readers and non-admins can't read
	t.checkACL(id, "", "", &t.noRole, 395, getExpectedACL(owner, []map[string]interface{}{},false))
	t.getNodeFailUnauth(id, &t.noRole2)
	t.loggerhook.Reset()

	// add readers as owner
	body = t.req("PUT", t.url + "/node/" + id + "/acl/read?users=" + t.noRole2.user, nil,
		"Oauth " + t.noRole.token, 441)
	t.checkLogs(logEvent{logrus.InfoLevel, "PUT", "/node/" + id + "/acl/read", 200,
		&t.noRole.user, "request complete", mtmap(), false},
	)
	
	u2 := map[string]interface{}{
		"uuid": t.getUserIDFromMongo(t.noRole2.user),
		"username": t.noRole2.user,
	}
	expectedACL := getExpectedACL(owner, []map[string]interface{}{u2}, false)
	t.Equal(expectedACL, body, "incorrect acls")

	t.checkNode(id, &t.noRole2, 374, expected)
	t.checkACL(id, "", "", &t.noRole2, 441, expectedACL)
	t.checkFile(t.url + "/node/" + id + "?download", "/node/" + id, &t.noRole2, 9, id,
		[]byte("foobarbaz"))

	// remove reader as self with verbose response and trailing slash
	body = t.req("DELETE", t.url + "/node/" + id + "/acl/read/?verbosity=full;users=" +
		t.noRole2.user, nil, "Oauth " + t.noRole2.token, 617)
	t.checkLogs(logEvent{logrus.InfoLevel, "DELETE", "/node/" + id + "/acl/read/", 200,
		&t.noRole2.user, "request complete", mtmap(), false},
	)
	expectedACL = getExpectedACL(owner, []map[string]interface{}{}, true)
	t.Equal(expectedACL, body, "incorrect acls")
	t.getNodeFailUnauth(id, &t.noRole2)
	t.checkACL(id, "", "?verbosity=full", &t.noRole, 617, expectedACL)
}

func getExpectedACL(owner map[string]interface{}, readers []map[string]interface{}, verbose bool,
) map[string]interface{} {
	var ownerdoc interface{}
	var readerdocs []interface{}
	if verbose {
		ownerdoc = owner
		readerdocs = append(readerdocs, owner)
	} else {
		ownerdoc = owner["uuid"]
		readerdocs = append(readerdocs, owner["uuid"])
	}
	for _, r := range readers {
		if verbose {
			readerdocs = append(readerdocs, r)
		} else {
			readerdocs = append(readerdocs, r["uuid"])
		}
	}

	return map[string]interface{}{
		"data": map[string]interface{}{
			"owner": ownerdoc,
			"write": []interface{}{ownerdoc},
			"delete": []interface{}{ownerdoc},
			"read": readerdocs,
			"public": map[string]interface{}{
				"read": false,
				"write": false,
				"delete": false,
			},
		},
		"error": nil,
		"status": float64(200),
	}

}

func (t *TestSuite) TestSetReadACLsFail() {
	body := t.req("POST", t.url + "/node", strings.NewReader("foobarbaz"),
		"Oauth " + t.kBaseAdmin.token, 374)
	id := (body["data"].(map[string]interface{}))["id"].(string)

	type testcase struct {
		method string
		urlsuffix string
		token string
		status int
		errstring string
		conlen int64
	}

	notown := "Users that are not node owners can only delete themselves from ACLs."
	nousers := "Action requires list of comma separated usernames in 'users' parameter"
	invauth := "Invalid authorization header or content"
	badid := uuid.New().String()
	testcases := []testcase{
		testcase{"PUT", id + "/acl/wead", "", 400, "Invalid acl type", 77},
		testcase{"DELETE", id + "/acl/wead/", "", 400, "Invalid acl type", 77},
		testcase{"PUT", "/badid/acl/read/", "", 404, "Node not found", 75},
		testcase{"DELETE", "/worseid/acl/read", "", 404, "Node not found", 75},
		testcase{"PUT", id + "/acl/read", "", 401, "No Authorization", 77},
		testcase{"DELETE", id + "/acl/read/", "", 401, "No Authorization", 77},
		testcase{"PUT", id + "/acl/read/", "oauth badtoken", 400, invauth, 100},
		testcase{"DELETE", id + "/acl/read", "oauth badtoken", 400, invauth, 100},
		testcase{"PUT", id + "/acl/read?users=%20%20,%20%09%20%20,%20", "Oauth " + t.noRole.token,
			400, nousers, 131},
		testcase{"DELETE", id + "/acl/read?users=%20%20,%20%20%20,%09%20",
			"Oauth " + t.noRole.token, 400, nousers, 131},
		testcase{"PUT", id + "/acl/read?users=fakename,fakename2", "Oauth " + t.noRole.token, 400,
			"Invalid users: fakename, fakename2", 95},
		testcase{"DELETE", id + "/acl/read?users=fakename,fakename2", "Oauth " + t.noRole.token,
			400, "Invalid users: fakename, fakename2", 95},
		testcase{"PUT", badid + "/acl/read?users=" + t.noRole2.user, "Oauth " + t.noRole.token,
			404, "Node not found", 75},
		testcase{"DELETE", badid + "/acl/read/?users=" + t.noRole2.user, "Oauth " + t.noRole.token,
			404, "Node not found", 75},
		testcase{"PUT", id + "/acl/read/?users=" + t.noRole2.user, "Oauth " + t.noRole.token, 400,
			notown, 129},
		testcase{"DELETE", id + "/acl/read/?users=" + t.noRole2.user, "Oauth " + t.noRole.token,
			400, notown, 129},
		// fail to delete self
		testcase{"DELETE", id + "/acl/read/?users=" + t.noRole2.user, "Oauth " + t.noRole2.token,
			400, notown, 129},
	}

	for _, tc := range testcases {
		body := t.req(tc.method, t.url + "/node/" + tc.urlsuffix, nil, tc.token, tc.conlen)
		t.checkError(body, tc.status, tc.errstring)
	}
}

func (t *TestSuite) TestChangeOwner() {
	body := t.req("POST", t.url + "/node", strings.NewReader("foobarbaz"),
		"Oauth " + t.noRole.token, 374)
	uid := t.getUserIDFromMongo(t.noRole.user)
	t.loggerhook.Reset()

	data := body["data"].(map[string]interface{})
	time := data["created_on"].(string)
	id := data["id"].(string)
	
	expected := map[string]interface{}{
		"data": map[string]interface{}{
			"attributes": nil,
			"created_on": time,
			"last_modified": time,
			"id": id,
			"format": "",
			"file": map[string]interface{}{
				"checksum": map[string]interface{}{"md5": "6df23dc03f9b54cc38a0fc1483df6e21"},
				"name": "",
				"size": float64(9),
			},
		},
		"error": nil,
		"status": float64(200),
	}

	owner := map[string]interface{}{"uuid": uid, "username": t.noRole.user}

	// check no readers and non-admins can't read
	t.checkACL(id, "", "", &t.noRole, 395, getExpectedACL(owner, []map[string]interface{}{},false))
	t.getNodeFailUnauth(id, &t.noRole2)
	t.loggerhook.Reset()

	// change owner. Also check whitespace is ignored.
	body = t.req("PUT", t.url + "/node/" + id + "/acl/owner?users=%20%20,%20%20%20,%20%20" +
		t.noRole2.user + "%20%20,%20%20", nil, "Oauth " + t.noRole.token, 441)
	t.checkLogs(logEvent{logrus.InfoLevel, "PUT", "/node/" + id + "/acl/owner", 200,
		&t.noRole.user, "request complete", mtmap(), false},
	)
	
	u2 := map[string]interface{}{
		"uuid": t.getUserIDFromMongo(t.noRole2.user),
		"username": t.noRole2.user,
	}
	expectedACL := getExpectedACL(u2, []map[string]interface{}{owner}, false)
	t.Equal(expectedACL, body, "incorrect acls")

	t.checkNode(id, &t.noRole2, 374, expected)
	t.checkACL(id, "", "", &t.noRole2, 441, expectedACL)
	t.checkFile(t.url + "/node/" + id + "?download", "/node/" + id, &t.noRole2, 9, id,
		[]byte("foobarbaz"))
	t.loggerhook.Reset()

	// change owner as admin with verbose response and trailing slash
	body = t.req("PUT", t.url + "/node/" + id + "/acl/owner/?verbosity=full;users=" +
		t.noRole.user, nil, "Oauth " + t.stdRole.token, 721)
	t.checkLogs(logEvent{logrus.InfoLevel, "PUT", "/node/" + id + "/acl/owner/", 200,
		&t.stdRole.user, "request complete", mtmap(), false},
	)
	expectedACL = getExpectedACL(owner, []map[string]interface{}{u2}, true)
	t.Equal(expectedACL, body, "incorrect acls")

	t.checkNode(id, &t.noRole, 374, expected)
	t.checkACL(id, "", "?verbosity=full", &t.noRole, 721, expectedACL)
	t.checkFile(t.url + "/node/" + id + "?download", "/node/" + id, &t.noRole, 9, id,
		[]byte("foobarbaz"))
}

func (t *TestSuite) TestChangeOwnerFail() {
	body := t.req("POST", t.url + "/node", strings.NewReader("foobarbaz"),
		"Oauth " + t.kBaseAdmin.token, 374)
	id := (body["data"].(map[string]interface{}))["id"].(string)

	type testcase struct {
		method string
		urlsuffix string
		token string
		status int
		errstring string
		conlen int64
	}

	notown := "Users that are not node owners can only delete themselves from ACLs."
	nousers := "Action requires list of comma separated usernames in 'users' parameter"
	invauth := "Invalid authorization header or content"
	delown := "Deleting ownership is not a supported request type."
	toomany := "Too many users. Nodes may have only one owner."
	badid := uuid.New().String()
	testcases := []testcase{
		testcase{"PUT", id + "/acl/ownah", "", 400, "Invalid acl type", 77},
		testcase{"DELETE", id + "/acl/ownah", "", 400, "Invalid acl type", 77},
		testcase{"PUT", "/badid/acl/owner/", "", 404, "Node not found", 75},
		testcase{"DELETE", "/worseid/acl/owner", "", 404, "Node not found", 75},
		testcase{"PUT", id + "/acl/owner", "", 401, "No Authorization", 77},
		testcase{"DELETE", id + "/acl/owner/", "", 401, "No Authorization", 77},
		testcase{"PUT", id + "/acl/owner/", "oauth badtoken", 400, invauth, 100},
		testcase{"DELETE", id + "/acl/owner", "oauth badtoken", 400, invauth, 100},
		testcase{"DELETE", id + "/acl/owner", "Oauth " + t.noRole.token, 400, delown, 112},
		testcase{"PUT", id + "/acl/owner?users=%20%20,%20%09%20%20,%20",
			"Oauth " + t.noRole.token, 400, nousers, 131},
		testcase{"PUT", id + "/acl/owner?users=" + t.noRole2.user + "," + t.noRole3.user,
			"Oauth " + t.noRole.token, 400, toomany, 107},
		testcase{"PUT", id + "/acl/read?users=fakename", "Oauth " + t.noRole.token, 400,
			"Invalid users: fakename", 84},
		testcase{"PUT", badid + "/acl/owner?users=" + t.noRole2.user,
			"Oauth " + t.noRole.token, 404, "Node not found", 75},
		testcase{"PUT", id + "/acl/owner/?users=" + t.noRole2.user, "Oauth " + t.noRole.token, 400,
			notown, 129},
	}

	for _, tc := range testcases {
		body := t.req(tc.method, t.url + "/node/" + tc.urlsuffix, nil, tc.token, tc.conlen)
		t.checkError(body, tc.status, tc.errstring)
	}
}