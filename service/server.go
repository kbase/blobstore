package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/google/uuid"

	"github.com/kbase/blobstore/core"

	"github.com/kbase/blobstore/auth"

	"github.com/kbase/blobstore/config"

	"github.com/gorilla/mux"
)

// TODO LOG log or ignore X-IP headers
// TODO LOG insecure urls

const (
	service = "BlobStore"
)

// ServerStaticConf Static configuration items for the Server.
type ServerStaticConf struct {
	// ServerName the name of the server, servername in the JSON output.
	ServerName string
	// ServerVersion the version of the server, serverversion in the JSON output.
	ServerVersion string
	// ID The ID of the server. This is provided for backwards compatibility with Shock. Deprecated.
	// id in the JSON output
	ID string
	// ServerVersionCompat The version of the shock server for which this server provides some
	// level of compatibility. Deprecated. version in the JSON output
	ServerVersionCompat string
	// DeprecationWarning A deprecation warning for users regarding the ID and ServerVersionCompat
	// fields.
	DeprecationWarning string
}

// Server the blobstore server
type Server struct {
	mux        *mux.Router
	staticconf ServerStaticConf
	auth       auth.Provider
	store      *core.BlobStore
}

// New create a new server.
func New(cfg *config.Config, sconf ServerStaticConf) (*Server, error) {
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetOutput(os.Stdout)
	deps, err := constructDependencies(cfg)
	if err != nil {
		return nil, err // this is a pain to test
	}
	router := mux.NewRouter()
	router.NotFoundHandler = http.HandlerFunc(notFoundHandler)
	router.MethodNotAllowedHandler = http.HandlerFunc(notAllowedHandler)
	// router.StrictSlash(true) // doesn't seem to have an effect
	s := &Server{mux: router, staticconf: sconf, auth: deps.AuthProvider, store: deps.BlobStore}
	router.HandleFunc("/", s.rootHandler).Methods(http.MethodGet)
	router.Use(s.authLogMiddleWare)
	router.HandleFunc("/node", s.createNode).Methods(http.MethodPost, http.MethodPut)
	router.HandleFunc("/node/{id}", s.getNode).Methods(http.MethodGet)
	router.HandleFunc("/node/{id}/", s.getNode).Methods(http.MethodGet)
	//TODO DELETE handle node delete
	//TODO ACLs handle node acls (verbosity)
	// TODO ACLS chown node
	// TODO ACLS public read
	// TODO HANG figure out a way to stop minio hanging when contentlength > file
	// TODO TEST content-type and content-length headers
	return s, nil
}

// ServeHTTP implementation of the http.Handler interface
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

type servkey struct {
	k string
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	writeErrorWithCode(initLogger(r), "Not Found", 404, w)
}

func notAllowedHandler(w http.ResponseWriter, r *http.Request) {
	writeErrorWithCode(initLogger(r), "Method Not Allowed", 405, w)
}

func initLogger(r *http.Request) *logrus.Entry {
	//TODO LOG get correct ip taking X-* headers into account
	return logrus.WithFields(logrus.Fields{
		"ip": r.RemoteAddr,
		// at some point return rid to the user
		"requestid": fmt.Sprintf("%016d", rand.Intn(10000000000000000)),
		"service":   service,
		"path":      r.URL.EscapedPath(),
		"method":    r.Method,
		"user":      nil,
	})
}

func getUser(r *http.Request) *auth.User {
	if user, ok := r.Context().Value(servkey{"user"}).(*auth.User); ok {
		return user
	}
	return nil
}
func getLogger(r *http.Request) *logrus.Entry {
	return r.Context().Value(servkey{"log"}).(*logrus.Entry)
}

func (s *Server) authLogMiddleWare(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// would like to split out the log middleware, but no way to pass the user up the stack
		le := initLogger(r)

		token := r.Header.Get("authorization")
		var user *auth.User
		if token != "" {
			var err error
			user, err = s.auth.GetUser(token)
			if err != nil {
				writeError(le, err, w)
				return
			}
			le = le.WithField("user", user.GetUserName())
		}
		//TODO ACLs GetNode and GetFile will need to handle nil/ public users
		r = r.WithContext(context.WithValue(r.Context(), servkey{"user"}, user))
		r = r.WithContext(context.WithValue(r.Context(), servkey{"log"}, le))
		rec := statusRecorder{w, 200}
		next.ServeHTTP(&rec, r)
		if rec.status < 400 {
			// if there was an error a log should've already occurred
			le.WithField("status", rec.status).Info("request complete")
		}
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (rec *statusRecorder) WriteHeader(code int) {
	rec.status = code
	rec.ResponseWriter.WriteHeader(code)
}

func writeError(logentry *logrus.Entry, err error, w http.ResponseWriter) {
	code, errstr := translateError(err)
	writeErrorWithCode(logentry, errstr, code, w)
}

func writeErrorWithCode(logentry *logrus.Entry, err string, code int, w http.ResponseWriter) {
	logentry.WithField("status", code).Error(err)
	ret := map[string]interface{}{
		"data":   nil,
		"error":  [1]string{err},
		"status": code,
	}
	w.WriteHeader(code)
	encodeToJSON(w, &ret)
}

func (s *Server) rootHandler(w http.ResponseWriter, r *http.Request) {
	ret := map[string]interface{}{
		"servername":         s.staticconf.ServerName,
		"serverversion":      s.staticconf.ServerVersion,
		"id":                 s.staticconf.ID,
		"version":            s.staticconf.ServerVersionCompat,
		"deprecationwarning": s.staticconf.DeprecationWarning,
		"servertime":         time.Now().UnixNano() / 1000000,
		//TODO SERV git commit hash
	}
	encodeToJSON(w, &ret)
}

func encodeToJSON(w http.ResponseWriter, data *map[string]interface{}) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(data) // assume no errors here
}

func (s *Server) createNode(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	le := getLogger(r)
	if r.ContentLength < 0 {
		writeErrorWithCode(le, "Length Required", http.StatusLengthRequired, w)
		return
	}
	user := getUser(r)
	if user == nil {
		// shock compatibility here
		writeErrorWithCode(le, "No Authorization", http.StatusUnauthorized, w)
		return
	}
	// TODO CREATE handle filename and format
	//TODO CREATE handle copy
	node, err := s.store.Store(*user, r.Body, r.ContentLength, "", "")
	if err != nil {
		// can't figure out how to easily test this case.
		// the only triggerable error in the blobstore code is a bad content length,
		// but the server complains before we even get here for small data.
		writeError(le, err, w)
		return
	}
	writeNode(w, node)
}

func writeNode(w http.ResponseWriter, node *core.BlobNode) {
	ret := map[string]interface{}{
		"status": 200,
		"error":  nil,
		"data":   fromNode(node),
	}
	encodeToJSON(w, &ret)
}

func (s *Server) getNode(w http.ResponseWriter, r *http.Request) {
	le := getLogger(r)
	putativeid := mux.Vars(r)["id"]
	id, err := uuid.Parse(putativeid)
	if err != nil {
		// crappy error message, but compatible with Shock
		writeErrorWithCode(le, "Node not found", 404, w)
		return
	}
	user := getUser(r)
	// TODO AUTH handle nil user
	// TODO DOWNLOAD add special header for download
	if download(r.URL) {
		datareader, size, _, err := s.store.GetFile(*user, id)
		if err != nil {
			writeError(le, err, w)
			return
		}
		defer datareader.Close()
		w.Header().Set("content-length", strconv.FormatInt(size, 10))
		io.Copy(w, datareader)
	} else {
		node, err := s.store.Get(*user, id)
		if err != nil {
			writeError(le, err, w)
			return
		}
		writeNode(w, node)
	}
}

func download(u *url.URL) bool {
	if _, ok := u.Query()["download"]; ok {
		return true
	}
	if _, ok := u.Query()["download_raw"]; ok {
		return true
	}
	return false
}

func fromNode(node *core.BlobNode) map[string]interface{} {
	return map[string]interface{}{
		"id":            node.ID.String(),
		"format":        node.Format,
		"attributes":    nil, //deprecated
		"created_on":    formatTime(node.Stored),
		"last_modified": formatTime(node.Stored),
		"file": map[string]interface{}{
			"name":     node.Filename,
			"size":     node.Size,
			"checksum": map[string]string{"md5": node.MD5},
		},
	}
}

const timeFormat = "2006-01-02T15:04:05.000Z"

func formatTime(t time.Time) string {
	return t.Format(timeFormat)
}
