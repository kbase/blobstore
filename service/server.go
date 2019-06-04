package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
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
// TODO TIMING vs shock & experimental server

const (
	service      = "BlobStore"
	formCopyData = "copy_data"
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
	auth       *auth.Cache
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
	// router.StrictSlash(true) // doesn't seem to have an effect...?
	s := &Server{mux: router, staticconf: sconf, auth: deps.AuthCache, store: deps.BlobStore}
	router.Use(s.authLogMiddleWare)

	router.HandleFunc("/", s.rootHandler).Methods(http.MethodGet)

	router.HandleFunc("/node", s.createNode).Methods(http.MethodPost, http.MethodPut)
	router.HandleFunc("/node/", s.createNode).Methods(http.MethodPost, http.MethodPut)

	router.HandleFunc("/node/{id}", s.getNode).Methods(http.MethodGet)
	router.HandleFunc("/node/{id}/", s.getNode).Methods(http.MethodGet)

	router.HandleFunc("/node/{id}", s.deleteNode).Methods(http.MethodDelete)
	router.HandleFunc("/node/{id}/", s.deleteNode).Methods(http.MethodDelete)

	router.HandleFunc("/node/{id}/acl", s.getACL).Methods(http.MethodGet)
	router.HandleFunc("/node/{id}/acl/", s.getACL).Methods(http.MethodGet)
	router.HandleFunc("/node/{id}/acl/{acltype}", s.getACL).Methods(http.MethodGet)
	router.HandleFunc("/node/{id}/acl/{acltype}/", s.getACL).Methods(http.MethodGet)
	router.HandleFunc("/node/{id}/acl/{acltype}", s.addNodeACL).Methods(http.MethodPut)
	router.HandleFunc("/node/{id}/acl/{acltype}/", s.addNodeACL).Methods(http.MethodPut)
	router.HandleFunc("/node/{id}/acl/{acltype}", s.removeNodeACL).Methods(http.MethodDelete)
	router.HandleFunc("/node/{id}/acl/{acltype}/", s.removeNodeACL).Methods(http.MethodDelete)
	// TODO CONVERT script from shock -> bs, key off minio files
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

func getToken(r *http.Request) string {
	return r.Context().Value(servkey{"token"}).(string)
}

func getLogger(r *http.Request) *logrus.Entry {
	return r.Context().Value(servkey{"log"}).(*logrus.Entry)
}

func getTokenFromHeader(r *http.Request) (string, error) {
	tokenh := r.Header.Get("authorization")
	if strings.TrimSpace(tokenh) == "" {
		return "", nil
	}
	tokenparts := strings.Fields(tokenh)
	if len(tokenparts) != 2 {
		return "", errors.New(invalidAuthHeader)
	}
	if strings.ToLower(tokenparts[0]) != "oauth" {
		return "", errors.New(invalidAuthHeader)
	}
	return tokenparts[1], nil

}

func (s *Server) authLogMiddleWare(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// would like to split out the log middleware, but no way to pass the user up the stack
		le := initLogger(r)

		token, err := getTokenFromHeader(r)
		if err != nil {
			writeErrorWithCode(le, err.Error(), 400, w)
			return
		}
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
		r = r.WithContext(context.WithValue(r.Context(), servkey{"user"}, user))
		r = r.WithContext(context.WithValue(r.Context(), servkey{"log"}, le))
		r = r.WithContext(context.WithValue(r.Context(), servkey{"token"}, token))
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
	encodeToJSON(w, code, &ret)
}

func encodeToJSON(w http.ResponseWriter, code int, data *map[string]interface{}) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(data) // assume no errors here
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
	encodeToJSON(w, 200, &ret)
}

func (s *Server) createNode(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	le := getLogger(r)
	if r.ContentLength < 0 {
		writeErrorWithCode(le, "Length Required", http.StatusLengthRequired, w)
		return
	}
	user, err := getUserRequired(le, w, r)
	if err != nil {
		return
	}
	form, err := r.MultipartReader()
	if err != nil {
		if err == http.ErrNotMultipart {
			s.createNodeFromBody(le, w, r, user)
			return
		}
		writeErrorWithCode(le, err.Error(), 400, w)
		return
	}
	if r.Method != http.MethodPost {
		writeErrorWithCode(le, http.StatusText(405), 405, w)
		return
	}
	s.createNodeFromForm(le, w, r, form, user)
}

// caller is expected to close the reader
func (s *Server) createNodeFromForm(
	le *logrus.Entry,
	w http.ResponseWriter,
	r *http.Request,
	form *multipart.Reader,
	user *auth.User,
) {
	part, err := form.NextPart()
	if err != nil {
		errstr := err.Error()
		if err == io.EOF {
			errstr = "Expected " + formCopyData + " form name"
		}
		writeErrorWithCode(le, errstr, 400, w)
		return
	}
	defer part.Close()
	if part.FormName() != formCopyData {
		writeErrorWithCode(le, "Unexpected form name: "+part.FormName(), 400, w)
		return
	}
	// uuid is 36 ascii chars. We leave a few extra to throw errors if the submitted uuid is
	// too long, rather than ignoring the extra chars.
	buffer := make([]byte, 40)
	n, err := part.Read(buffer)
	if err != nil && err != io.EOF {
		// dunno how to test this
		writeErrorWithCode(le, err.Error(), 400, w)
		return
	}
	cid, err := uuid.Parse(string(buffer[:n]))
	if err != nil {
		writeErrorWithCode(le, "Invalid "+formCopyData+": "+err.Error(), 400, w)
		return
	}
	node, err := s.store.CopyNode(*user, cid)
	if err != nil {
		writeError(le, err, w)
		return
	}
	writeNode(w, node)
}

func (s *Server) createNodeFromBody(
	le *logrus.Entry,
	w http.ResponseWriter,
	r *http.Request,
	user *auth.User,
) {
	filename := getQuery(r.URL, "filename")
	format := getQuery(r.URL, "format")
	node, err := s.store.Store(*user, r.Body, r.ContentLength, filename, format)
	if err != nil {
		// can't figure out how to easily test this case.
		// the only triggerable error in the blobstore code is a bad content length,
		// but the client complains before we even get here for small data.
		writeError(le, err, w)
		return
	}
	writeNode(w, node)
}

func getQuery(u *url.URL, param string) string {
	s := u.Query()[param]
	if len(s) > 0 {
		return strings.TrimSpace(s[0])
	}
	return ""
}

func writeNode(w http.ResponseWriter, node *core.BlobNode) {
	ret := map[string]interface{}{
		"status": 200,
		"error":  nil,
		"data":   fromNodeToNode(node),
	}
	encodeToJSON(w, 200, &ret)
}

func getNodeID(le *logrus.Entry, w http.ResponseWriter, r *http.Request) (*uuid.UUID, error) {
	putativeid := mux.Vars(r)["id"]
	id, err := uuid.Parse(putativeid)
	if err != nil {
		// crappy error message, but compatible with Shock
		writeErrorWithCode(le, "Node not found", 404, w)
		return nil, err
	}
	return &id, nil
}

func (s *Server) getNode(w http.ResponseWriter, r *http.Request) {
	le := getLogger(r)
	id, err := getNodeID(le, w, r)
	if err != nil {
		return
	}
	user := getUser(r)
	download := download(r.URL)
	if download != "" {
		datareader, size, filename, err := s.store.GetFile(user, *id)
		if err != nil {
			writeError(le, err, w)
			return
		}
		defer datareader.Close()
		if download == "yes" {
			if filename == "" {
				filename = id.String()
			}
			w.Header().Set("content-disposition", "attachment; filename="+filename)
		}
		w.Header().Set("content-length", strconv.FormatInt(size, 10))
		w.Header().Set("content-type", "application/octet-stream")
		io.Copy(w, datareader)
	} else {
		node, err := s.store.Get(user, *id)
		if err != nil {
			writeError(le, err, w)
			return
		}
		writeNode(w, node)
	}
}

func download(u *url.URL) string {
	if _, ok := u.Query()["download"]; ok {
		return "yes"
	}
	if _, ok := u.Query()["download_raw"]; ok {
		return "raw"
	}
	return ""
}

func fromNodeToNode(node *core.BlobNode) map[string]interface{} {
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

func (s *Server) deleteNode(w http.ResponseWriter, r *http.Request) {
	le := getLogger(r)
	id, err := getNodeID(le, w, r)
	if err != nil {
		return
	}
	user, err := getUserRequired(le, w, r)
	if err != nil {
		return
	}
	err = s.store.DeleteNode(*user, *id)
	if err != nil {
		writeError(le, err, w)
		return
	}
	ret := map[string]interface{}{
		"status": 200,
		"error":  nil,
		"data":   nil,
	}
	encodeToJSON(w, 200, &ret)
}

var aclTypes = map[string]struct{}{
	"":              struct{}{},
	"owner":         struct{}{},
	"read":          struct{}{},
	"write":         struct{}{},
	"delete":        struct{}{},
	"public_read":   struct{}{},
	"public_write":  struct{}{},
	"public_delete": struct{}{},
}

func getACLType(le *logrus.Entry, w http.ResponseWriter, r *http.Request) (string, error) {
	acltype := mux.Vars(r)["acltype"]
	if _, ok := aclTypes[acltype]; !ok {
		// compatible with shock
		writeErrorWithCode(le, "Invalid acl type", 400, w)
		return "", errors.New("Invalid acl type")
	}
	return acltype, nil
}

func getACLParams(le *logrus.Entry, w http.ResponseWriter, r *http.Request,
) (*uuid.UUID, string, error) {
	aclType, err := getACLType(le, w, r)
	if err != nil {
		return nil, "", err
	}
	id, err := getNodeID(le, w, r)
	if err != nil {
		return nil, "", err
	}
	return id, aclType, nil
}

func (s *Server) getACL(w http.ResponseWriter, r *http.Request) {
	le := getLogger(r)
	id, _, err := getACLParams(le, w, r)
	if err != nil {
		return
	}
	user := getUser(r)
	s.getAndWriteACL(le, w, r, user, *id)
}

func (s *Server) addNodeACL(w http.ResponseWriter, r *http.Request) {
	s.setNodeACL(w, r, true)
}

func (s *Server) removeNodeACL(w http.ResponseWriter, r *http.Request) {
	s.setNodeACL(w, r, false)
}

// maybe break this up. not hard to read though.
func (s *Server) setNodeACL(w http.ResponseWriter, r *http.Request, add bool) {
	le := getLogger(r)
	id, acltype, err := getACLParams(le, w, r)
	if err != nil {
		return
	}
	user, err := getUserRequired(le, w, r)
	if err != nil {
		return
	}
	var node *core.BlobNode
	if acltype == "public_read" {
		node, err = s.store.SetNodePublic(*user, *id, add)
		if err != nil {
			writeError(le, err, w)
			return
		}
	} else if acltype == "read" {
		users, err := s.getUserList(le, w, r, false)
		if err != nil {
			return
		}
		if add {
			node, err = s.store.AddReaders(*user, *id, *users)
		} else {
			node, err = s.store.RemoveReaders(*user, *id, *users)
		}
		if err != nil {
			writeError(le, err, w)
			return
		}
	} else if acltype == "owner" {
		if !add {
			writeErrorWithCode(le, "Deleting ownership is not a supported request type.", 400, w)
			return
		}
		users, err := s.getUserList(le, w, r, true)
		if err != nil {
			return
		}
		node, err = s.store.ChangeOwner(*user, *id, (*users)[0])
		if err != nil {
			writeError(le, err, w)
			return
		}
	}
	if node == nil {
		s.getAndWriteACL(le, w, r, user, *id)
	} else {
		s.writeACL(w, r, node)
	}
}

func getUserRequired(le *logrus.Entry, w http.ResponseWriter, r *http.Request,
) (*auth.User, error) {
	user := getUser(r)
	if user == nil {
		// shock compatibility here
		writeErrorWithCode(le, "No Authorization", http.StatusUnauthorized, w)
		return nil, errors.New("No authorization")
	}
	return user, nil
}

const noUsersError = "Action requires list of comma separated usernames in 'users' parameter"
const tooManyUsersError = "Too many users. Nodes may have only one owner."

func (s *Server) getUserList(
	le *logrus.Entry,
	w http.ResponseWriter,
	r *http.Request,
	singleUser bool,
) (*[]string, error) {
	ul := getQuery(r.URL, "users")
	uls := strings.Split(ul, ",")
	ulst := []string{}
	for _, s := range uls {
		s = strings.TrimSpace(s)
		if s != "" {
			ulst = append(ulst, s)
		}
	}
	if len(ulst) < 1 {
		writeErrorWithCode(le, noUsersError, 400, w)
		return nil, errors.New(noUsersError)
	}
	if singleUser && len(ulst) > 1 {
		writeErrorWithCode(le, tooManyUsersError, 400, w)
		return nil, errors.New(tooManyUsersError)
	}
	err := s.auth.ValidateUserNames(&ulst, getToken(r))
	if err != nil {
		writeError(le, err, w)
		return nil, err
	}
	return &ulst, nil
}

func (s *Server) getAndWriteACL(
	le *logrus.Entry,
	w http.ResponseWriter,
	r *http.Request,
	user *auth.User,
	id uuid.UUID,
) {
	node, err := s.store.Get(user, id)
	if err != nil {
		writeError(le, err, w)
		return
	}
	s.writeACL(w, r, node)
}

func (s *Server) writeACL(w http.ResponseWriter, r *http.Request, node *core.BlobNode) {
	verbose := getQuery(r.URL, "verbosity") == "full"
	ret := map[string]interface{}{
		"status": 200,
		"error":  nil,
		"data":   fromNodeToACL(node, verbose),
	}
	encodeToJSON(w, 200, &ret)
}

func fromNodeToACL(node *core.BlobNode, verbose bool) map[string]interface{} {
	o := toUser(node.Owner, verbose)
	return map[string]interface{}{
		"owner":  o,
		"delete": []interface{}{o},
		"write":  []interface{}{o},
		"read":   toUsers(node.Readers, verbose),
		"public": map[string]bool{
			"write":  false,
			"delete": false,
			"read":   node.Public,
		},
	}
}

func toUsers(users *[]core.User, verbose bool) []interface{} {
	ulist := &[]interface{}{}
	for _, u := range *users {
		*ulist = append(*ulist, toUser(u, verbose))
	}
	return *ulist
}

func toUser(user core.User, verbose bool) interface{} {
	if verbose {
		return map[string]string{
			"uuid":     user.ID.String(),
			"username": user.AccountName,
		}
	}
	return user.ID.String()
}
