package service

import (
	"time"
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
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
	mux *mux.Router
	staticconf ServerStaticConf
}

// New create a new server.
func New(sconf ServerStaticConf) (*Server) {
	router := mux.NewRouter()
	s := &Server{mux: router, staticconf: sconf}
	// r.Use(loggingMiddleWare)
	router.HandleFunc("/", s.rootHandler)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) rootHandler(w http.ResponseWriter, r *http.Request) {
	ret := map[string]interface{}{
		"servername": s.staticconf.ServerName,
		"serverversion": s.staticconf.ServerVersion,
		"id": s.staticconf.ID,
		"version": s.staticconf.ServerVersionCompat,
		"deprecationwarning": s.staticconf.DeprecationWarning,
		"servertime": time.Now().UnixNano() / 1000000,
		//TODO git commit hash
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(ret)
}