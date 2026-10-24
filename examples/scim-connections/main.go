// Command scim-connections lets each customer connect their own identity
// provider: the owner of an organization creates a SCIM connection for it
// from the app's settings page, gets a token shown once, rotates and revokes
// tokens, reads the connection's event log, and finally retires the
// connection, which stops its tokens and deactivates the users it provisioned.
//
//	AUTH_SECRET=$(openssl rand -hex 32) go run ./scim-connections
//
// Give the IdP the base URL http://localhost:8081/scim/v2 and the token the
// create call answers. Mail is printed to the log instead of sent.
package main

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/scim"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "scim-connections.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// scimPrefix is the SCIM base URL's path, the one every customer's IdP
	// is given; the token tells the connections apart.
	scimPrefix = "/scim/v2"
	// envSecret is the app's secret; managed tokens are stored as HMAC
	// digests under a key derived from it. There is no default: a secret in
	// the source would be a secret on GitHub.
	envSecret = "AUTH_SECRET"
	// maxBodyBytes caps the app's settings bodies, which hold an id or two.
	maxBodyBytes = 1 << 16
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
)

// Path wildcards of the app's settings routes.
const (
	pathOrgParam  = "org"
	pathConnParam = "conn"
	pathCredParam = "cred"
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set, so
	// two examples can run side by side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the server listens: this machine only, for development.
	// Use ":" + port to accept connections from the network.
	addr = "localhost:" + port
	// baseURL is the app's public URL; its origin is the only one allowed to
	// send cookie-authenticated POSTs, and mailed links point at it.
	baseURL = "http://localhost:" + port
)

// sqlitePragmas are the settings every SQLite connection needs: WAL so readers
// do not block the writer, and a busy timeout instead of an immediate
// "database is locked".
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// sqliteDSN builds the SQLite URI for a database file, escaping only the path
// so a "#" or "?" in it cannot start the URI's fragment or query.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

func main() {
	secret := []byte(os.Getenv(envSecret))
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	sp := newSCIM(logGroups{})
	a, err := newAuth(db, secret, logMailer{}, sp)
	if err != nil {
		log.Fatal(err) // a missing or short AUTH_SECRET fails here
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}
	h, err := newHandler(a, sp)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("SCIM base URL %s%s", baseURL, scimPrefix)
	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// newSCIM builds the SCIM plugin with no connection in code: every
// connection is a managed one, created at run time per customer, with its
// tokens stored only as HMAC digests. Groups go to groups, the app's model.
//
//ds:def id=scimconn-newscim-3w8kq5nv
func newSCIM(groups scim.GroupMapper) *scim.Plugin {
	return scim.New(
		scim.ManagedConnections(),
		scim.WithGroupMapper(groups),
	)
}

// plugins is the plugin list: email (SCIM needs it: a provisioned user's
// primary email becomes an email identity), passwords, organizations (the
// customers) and SCIM. The test's harness wires the same list.
func plugins(m email.Mailer, sp *scim.Plugin) []auth.Plugin {
	return []auth.Plugin{
		email.New(email.Login(), email.Recover(), email.WithMailer(m)),
		password.New(),
		organization.New(),
		sp,
	}
}

// newAuth wires the library over the database and the app's secret.
func newAuth(db *sql.DB, secret []byte, m email.Mailer, sp *scim.Plugin) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithSecret(secret),
		auth.WithPlugins(plugins(m, sp)...),
	)
}

// newHandler mounts the library's routes, the SCIM endpoints, the settings
// routes an organization's owner manages its connections with, and a JSON
// page only a signed-in user may see. Each connection's provisioning domain
// is the organization's id, so one customer can never name another's
// connection: the plugin answers scim.connection_not_found.
//
//ds:def id=scimconn-newhandler-7d2xr4mh
func newHandler(a *auth.Auth, sp *scim.Plugin) (http.Handler, error) {
	orgs, err := auth.PluginOf[*organization.Plugin](a)
	if err != nil {
		return nil, err
	}
	mw := authhttp.Middleware(a)
	owner := func(h http.Handler) http.Handler {
		return mw(orgs.RequireRole(orgInPath, organization.RoleOwner)(h))
	}
	s := settings{a: a, sp: sp}
	base := "/orgs/{" + pathOrgParam + "}/scim/connections"
	conn := base + "/{" + pathConnParam + "}"
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle(scimPrefix+"/", http.StripPrefix(scimPrefix, sp.Handler()))
	mux.Handle("GET "+base, owner(http.HandlerFunc(s.list)))
	mux.Handle("POST "+base, owner(s.post(s.create)))
	mux.Handle("GET "+conn+"/events", owner(http.HandlerFunc(s.events)))
	mux.Handle("POST "+conn+"/rotate", owner(s.post(s.rotate)))
	mux.Handle("POST "+conn+"/credentials/{"+pathCredParam+"}/revoke", owner(s.post(s.revoke)))
	mux.Handle("POST "+conn+"/decommission", owner(s.post(s.decommission)))
	mux.Handle("/me", mw(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux, nil
}

// orgInPath reads the organization id from the route, for RequireRole and as
// the connection's provisioning domain.
func orgInPath(r *http.Request) string { return r.PathValue(pathOrgParam) }

// settings is the app's connection settings: thin HTTP over the plugin's
// managed-connection API, which is Go only.
type settings struct {
	a  *auth.Auth
	sp *scim.Plugin
}

// post refuses a POST from another site before h runs: the library checks
// the origin on its own routes, these are the app's, and the session cookie
// would be sent from anywhere.
func (s settings) post(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.a.TrustsOrigin(authhttp.RequestOf(r).Client.Origin) {
			authhttp.WriteError(w, auth.ErrOriginNotTrusted)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		h(w, r)
	})
}

// createRequest is the body of the create call. RequestID is chosen by the
// page once per form (16 to 255 characters), so a double click or a retry
// after a timeout cannot create two connections: the second answers
// scim.creation_request_conflict.
type createRequest struct {
	RequestID string `json:"requestId"`
}

// issuedResponse answers create and rotate. Token is shown this once; the
// plugin keeps only its digest, so a lost token is replaced by rotating.
type issuedResponse struct {
	Connection   scim.ManagedConnection `json:"connection"`
	CredentialID string                 `json:"credentialId"`
	Token        string                 `json:"token"`
}

// issued turns the plugin's answer into the page's, revealing the token.
func issued(c scim.IssuedCredential) issuedResponse {
	return issuedResponse{Connection: c.Connection, CredentialID: c.Credential.ID, Token: c.Token.Reveal()}
}

// create makes the organization a connection with one credential that may
// do everything (no scopes). The signed-in owner is recorded as the actor in
// the event log.
//
//ds:def id=scimconn-create-5p9tn2wq
func (s settings) create(w http.ResponseWriter, r *http.Request) {
	var in createRequest
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		authhttp.WriteError(w, auth.ErrBadRequest)
		return
	}
	out, err := s.sp.CreateManagedConnection(r.Context(), scim.CreateManagedRequest{
		CreationRequestID:    in.RequestID,
		ProvisioningDomainID: orgInPath(r),
		ActorID:              authhttp.MustUser(r).ID,
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, issued(out))
}

// rotate adds a second credential beside the active ones, so the customer
// pastes the new token into the IdP before revoking the old one and no
// request fails in between.
//
//ds:def id=scimconn-rotate-8h3mv6xz
func (s settings) rotate(w http.ResponseWriter, r *http.Request) {
	out, err := s.sp.RotateCredential(r.Context(), r.PathValue(pathConnParam), orgInPath(r), authhttp.MustUser(r).ID, nil, nil)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, issued(out))
}

// okResponse answers a call with nothing else to say.
type okResponse struct {
	OK bool `json:"ok"`
}

// revoke ends one credential at once; the IdP's next request with it is 401.
func (s settings) revoke(w http.ResponseWriter, r *http.Request) {
	if err := s.sp.RevokeCredential(r.Context(), r.PathValue(pathConnParam), orgInPath(r), r.PathValue(pathCredParam), authhttp.MustUser(r).ID); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, okResponse{OK: true})
}

// list answers the organization's connections with their credentials, never
// a token.
func (s settings) list(w http.ResponseWriter, r *http.Request) {
	cs, err := s.sp.ManagedConnections(r.Context(), orgInPath(r))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, cs)
}

// events answers the connection's audit trail: who created it, issued,
// rotated and revoked which credential, and when it was retired.
func (s settings) events(w http.ResponseWriter, r *http.Request) {
	es, err := s.sp.ConnectionEvents(r.Context(), r.PathValue(pathConnParam), orgInPath(r))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, es)
}

// decommissionResponse is the page's view of scim.DecommissionResult.
type decommissionResponse struct {
	Status          scim.DecommissionStatus `json:"status"`
	ReconciledUsers int64                   `json:"reconciledUsers"`
}

// decommission retires the connection for good: its tokens stop at once,
// the users it provisioned are deactivated (unless another connection still
// provisions them) and signed out, and the GroupMapper hears its groups are
// gone. It runs to completion here; a large directory would pass MaxBatches
// and call again from a worker until the status is complete.
//
//ds:def id=scimconn-decommission-6r4yk8cs
func (s settings) decommission(w http.ResponseWriter, r *http.Request) {
	res, err := s.sp.DecommissionConnection(r.Context(), scim.DecommissionRequest{
		ConnectionID:         r.PathValue(pathConnParam),
		ProvisioningDomainID: orgInPath(r),
		ActorID:              authhttp.MustUser(r).ID,
	})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, decommissionResponse{Status: res.Status, ReconciledUsers: res.ReconciledUsers})
}

// fail answers err; anything that is not a library error is logged, because
// the client sees only a 500 with no detail.
func fail(w http.ResponseWriter, err error) {
	var ae *auth.Error
	if !errors.As(err, &ae) {
		log.Printf("scim settings: %v", err)
	}
	authhttp.WriteError(w, err)
}

// answer is every JSON shape the app's own routes write.
type answer interface {
	issuedResponse | okResponse | []scim.ManagedConnection | []scim.Event | decommissionResponse | meResponse
}

// writeJSON writes v as the JSON answer with status.
func writeJSON[T answer](w http.ResponseWriter, status int, v T) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v) // a client that hung up cannot be told
}

// meResponse is what /me answers.
type meResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// me is an app handler: RequireUser has already refused anyone signed out,
// including a user whose connection was retired.
func me(w http.ResponseWriter, r *http.Request) {
	u := authhttp.MustUser(r)
	writeJSON(w, http.StatusOK, meResponse{ID: u.ID, Name: u.Name})
}

// logGroups is the GroupMapper; an app maps a group to a team or a role
// here. This one logs, so a decommission shows its groups going away.
type logGroups struct{}

// SyncGroup logs the group's members.
func (logGroups) SyncGroup(_ context.Context, g scim.GroupState) error {
	log.Printf("group %q (%s): members %v", g.DisplayName, g.ConnectionID, g.UserIDs)
	return nil
}

// DeleteGroup logs the deletion.
func (logGroups) DeleteGroup(_ context.Context, connection, groupID string) error {
	log.Printf("group %s (%s) deleted", groupID, connection)
	return nil
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
