package service

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

// Server the blobstore server
type Server struct {
	mux *mux.Router
}

// New create a new server.
func New() (*Server) {
	router := mux.NewRouter()
	// r.Use(loggingMiddleWare)
	router.HandleFunc("/", rootHandler)
	s := &Server{mux: router}
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	//TODO return info about server
	fmt.Fprintf(w, "Hello there!\n")
}