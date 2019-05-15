package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/kbase/blobstore/core"

	"github.com/kbase/blobstore/auth"

	"github.com/kbase/blobstore/config"

	"github.com/gorilla/mux"
)

// TODO LOG log or ignore X-IP headers
// TODO LOG insecure urls

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
	router.Use(s.authMiddleWare)
	// TODO API is there a way to return a custom body for a 405?
	router.HandleFunc("/node", s.createNode).Methods(http.MethodPost, http.MethodPut)
	router.HandleFunc("/node/{id}", s.getNode).Methods(http.MethodGet)
	router.HandleFunc("/node/{id}/", s.getNode).Methods(http.MethodGet)
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
	writeErrorWithCode("Not Found", 404, w)
}

func notAllowedHandler(w http.ResponseWriter, r *http.Request) {
	writeErrorWithCode("Method Not Allowed", 405, w)
}

func (s *Server) authMiddleWare(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("authorization")
		var user *auth.User
		if token != "" {
			var err error
			user, err = s.auth.GetUser(token)
			if err != nil {
				writeError(err, w)
				return
			}
		}
		//TODO ACLs GetNode and GetFile will need to handle nil/ public users
		r = r.WithContext(context.WithValue(r.Context(), servkey{"user"}, user))
		// TODO LOG user
		next.ServeHTTP(w, r)
	})
}

func writeError(err error, w http.ResponseWriter) {
	code := 500 //TODO ERROR correct code
	writeErrorWithCode(err.Error(), code, w)
}

func writeErrorWithCode(err string, code int, w http.ResponseWriter) {
	//TODO LOG log error
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
		//TODO git commit hash
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
	if r.ContentLength < 0 {
		writeError(errors.New("Missing content-length header"), w) //TODO ERROR 400 code
		return
	}
	user := r.Context().Value(servkey{"user"}).(*auth.User)
	if user == nil {
		writeError(errors.New("Unauthorized"), w) // TODO ERROR correct error
		return
	}
	// TODO CREATE handle filename and format
	//TODO CREATE handle copy
	node, err := s.store.Store(*user, r.Body, r.ContentLength, "", "")
	if err != nil {
		// can't figure out how to easily test this case.
		// the only triggerable error in the blobstore code is a bad content length,
		// but the server complains before we even get here for small data.
		writeError(err, w)
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
	putativeid := mux.Vars(r)["id"]
	id, err := uuid.Parse(putativeid)
	if err != nil {
		// crappy error message, but compatible with Shock
		writeError(errors.New("Node not found"), w) //TODO ERROR needs a 404
		return
	}
	user := r.Context().Value(servkey{"user"}).(*auth.User)
	// TODO AUTH handle nil user
	// TODO add special header for download
	if download(r.URL) {
		datareader, size, err := s.store.GetFile(*user, id)
		if err != nil {
			writeError(err, w) //TODO ERROR code
			return
		}
		defer datareader.Close()
		w.Header().Set("content-length", strconv.FormatInt(size, 10))
		io.Copy(w, datareader)
	} else {
		node, err := s.store.Get(*user, id)
		if err != nil {
			writeError(err, w) //TODO ERROR code
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
