package service

import (
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

	"github.com/phayes/freeport"
	"github.com/stretchr/testify/suite"
)

const (
	testDB = "test_blobstore_integration"
	blobstoreRole = "BLOBSTORE_ADMIN"
	adminRole = "KBASE_ADMIN"
)

type TestSuite struct {
	suite.Suite
	s   *http.Server
	url string
	deleteTempDir bool
	mongo *mongocontroller.Controller
	mongoclient *mongo.Client
	minio *miniocontroller.Controller
	auth *kbaseauthcontroller.Controller
	tokenNoRole string
	tokenStdRole string
	tokenKBaseAdmin string
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
			S3Bucket: "mybukkit",
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
}

func (t *TestSuite) setUpUsersAndRoles() {
	t.createTestUser("noroles")
	t.createTestUser("admin_std_role")
	t.createTestUser("admin_kbase")

	t.tokenNoRole = t.createTestToken("noroles")
	t.tokenStdRole = t.createTestToken("admin_std_role")
	t.tokenKBaseAdmin = t.createTestToken("admin_kbase")

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
}

func TestRunSuite(t *testing.T) {
	suite.Run(t, new(TestSuite))
}

func (t *TestSuite) TestRoot() {
	ret, err := http.Get(t.url)
	if err != nil {
		t.Fail(err.Error())
	}
	dec := json.NewDecoder(ret.Body)
	var root map[string]interface{}
	dec.Decode(&root)

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
}

// TODO DOCS for store, get, get file
func (t *TestSuite) TestStoreAndGetBasic() {
	req, err := http.NewRequest(http.MethodPost, t.url + "/node", strings.NewReader("foobarbaz"))
	t.Nil(err, "unexpected error")
	req.Header.Set("authorization", t.tokenNoRole)
	resp, err := http.DefaultClient.Do(req)
	t.Nil(err, "unexpected error")
	b, err := ioutil.ReadAll(resp.Body)
	t.Nil(err, "unexpected error")
	var body map[string]interface{}
	json.Unmarshal(b, &body)

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
				"name": "",
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
				"name": "",
				"size": float64(9),
			},
		},
		"error": nil,
		"status": float64(200),
	}
	t.checkNode(t.url + "/node/" + id, expected2)

	// TODO TEST check download header
	t.checkFile(t.url + "/node/" + id + "?download", 9, []byte("foobarbaz"))
	t.checkFile(t.url + "/node/" + id + "/?download", 9, []byte("foobarbaz"))
	t.checkFile(t.url + "/node/" + id + "?download_raw", 9, []byte("foobarbaz"))
	t.checkFile(t.url + "/node/" + id + "/?download_raw", 9, []byte("foobarbaz"))
}

func (t *TestSuite) checkFile(url string, size int64, expected []byte) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	t.Nil(err, "unexpected error")
	req.Header.Set("authorization", t.tokenNoRole)
	resp, err := http.DefaultClient.Do(req)
	t.Nil(err, "unexpected error")
	b, err := ioutil.ReadAll(resp.Body)
	t.Nil(err, "unexpected error")
	t.Equal(size, resp.ContentLength, "incorrect content length")
	t.Equal(expected, b, "incorrect file")
}

func (t *TestSuite) checkNode(url string, expected map[string]interface{}) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	t.Nil(err, "unexpected error")
	req.Header.Set("authorization", t.tokenNoRole)
	resp, err := http.DefaultClient.Do(req)
	t.Nil(err, "unexpected error")
	b, err := ioutil.ReadAll(resp.Body)
	t.Nil(err, "unexpected error")
	var body map[string]interface{}
	json.Unmarshal(b, &body)

	t.Equal(expected, body, "incorrect return")
}
