package service

// tests the getIP() method thoroughly. The integration tests just do basic tests.

import (
	"net/http"
	"testing"
	"io/ioutil"
	"github.com/stretchr/testify/suite"
	"github.com/sirupsen/logrus"
	logrust "github.com/sirupsen/logrus/hooks/test"
)

type TestSuiteIP struct {
	suite.Suite
	loggerhook *logrust.Hook
}

func (t *TestSuiteIP) SetupSuite() {
	logrus.SetOutput(ioutil.Discard)
	t.loggerhook = logrust.NewGlobal()
}

func (t *TestSuiteIP) SetupTest() {
	t.loggerhook.Reset()
}

func TestRunSuiteIP(t *testing.T) {
	suite.Run(t, new(TestSuiteIP))
}

func (t *TestSuiteIP) TestIgnoreXIPHeaders() {
	r := http.Request{}
	r.RemoteAddr = "123.456.789.123"
	r.Header = make(http.Header)
	r.Header.Set("x-forwarded-for", "321.654.987.321, 456.789.123.456")
	r.Header.Set("x-real-Ip", "789.123.456.789")

	t.Equal("123.456.789.123", getIP(logrus.WithFields(logrus.Fields{}), &r, true), "incorrect ip")
	t.confirmNoLogs()
}

func (t *TestSuiteIP) confirmNoLogs() {
	t.Equal(0, len(t.loggerhook.AllEntries()), "incorrect log entry count")
}

func (t *TestSuiteIP) TestNoXIPHeaders() {
	r := http.Request{}
	r.RemoteAddr = "123.456.789.123"
	r.Header = make(http.Header)
	r.Header.Set("x-forwarded-for", "   ,     321.654.987.321, 456.789.123.456")
	r.Header.Set("x-real-Ip", "     ")

	t.Equal("123.456.789.123", getIP(logrus.WithFields(logrus.Fields{}), &r, false),
		"incorrect ip")
	t.confirmNoLogs()
}

func (t *TestSuiteIP) TestXFFHeader() {
	r := http.Request{}
	r.RemoteAddr = "123.456.789.123"
	r.Header = make(http.Header)
	r.Header.Set("x-forwarded-for", "   321.654.987.321   ,    456.789.123.456    ")
	r.Header.Set("x-real-Ip", "789.123.456.789")

	t.Equal("321.654.987.321", getIP(logrus.WithFields(logrus.Fields{}), &r, false),
		"incorrect ip")
	t.confirmLog("   321.654.987.321   ,    456.789.123.456    ",
		"789.123.456.789", "123.456.789.123", "321.654.987.321")
}

func (t *TestSuiteIP) TestXFFHeaderWithNoComma() {
	r := http.Request{}
	r.RemoteAddr = "123.456.789.123"
	r.Header = make(http.Header)
	r.Header.Set("x-forwarded-for", "   321.654.987.321   ")
	r.Header.Set("x-real-Ip", "789.123.456.789")

	t.Equal("321.654.987.321", getIP(logrus.WithFields(logrus.Fields{}), &r, false),
		"incorrect ip")
	t.confirmLog("   321.654.987.321   ", "789.123.456.789", "123.456.789.123", "321.654.987.321")
}

func (t *TestSuiteIP) TestXRIPHeader() {
	r := http.Request{}
	r.RemoteAddr = "123.456.789.123"
	r.Header = make(http.Header)
	r.Header.Set("x-forwarded-for", "      ,    456.789.123.456    ")
	r.Header.Set("x-real-Ip", "     789.123.456.789     ")

	t.Equal( "789.123.456.789", getIP(logrus.WithFields(logrus.Fields{}), &r, false),
		"incorrect ip")
	t.confirmLog("      ,    456.789.123.456    ",
	"     789.123.456.789     ", "123.456.789.123", "789.123.456.789")
}

func (t *TestSuiteIP) confirmLog(xFF, xRIP, RemoteAddr, IP string) {
	t.Equal(1, len(t.loggerhook.AllEntries()), "incorrect log entry count")

	got := t.loggerhook.AllEntries()[0]
	t.Equal(logrus.InfoLevel, got.Level, "incorrect level")
	t.Equal("logging ip information", got.Message, "incorrect message")
	
	expectedfields := map[string]interface{}{
		"X-Forwarded-For": xFF,
		"X-Real-IP": xRIP,
		"RemoteAddr": RemoteAddr,
		"ip": IP,
	}
	t.Equal(expectedfields, map[string]interface{}(got.Data), "incorrect fields")
}
