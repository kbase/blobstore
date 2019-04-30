package service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/phayes/freeport"
	"github.com/stretchr/testify/suite"
)

type TestSuite struct {
	suite.Suite
	s   *http.Server
	url string
}

func (t *TestSuite) SetupSuite() {
	serv := New(ServerStaticConf{
		ServerName:          "servn",
		ServerVersion:       "servver",
		ID:                  "shockyshock",
		ServerVersionCompat: "sver",
		DeprecationWarning:  "I shall deprecate the whold world! MuhahahahHAHA",
	})

	port, err := freeport.GetFreePort()
	if err != nil {
		t.Fail(err.Error())
	}

	t.url = "http://localhost:" + strconv.Itoa(port)
	fmt.Println("server url: " + t.url)
	t.s = &http.Server{
		Addr:    "localhost:" + strconv.Itoa(port),
		Handler: serv,
	}

	go func() {

		if err := t.s.ListenAndServe(); err != nil {
			t.Fail(err.Error())
		}
	}()
	time.Sleep(50 * time.Millisecond) // wait for the server to start
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
