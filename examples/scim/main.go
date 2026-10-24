// Command scim lets a customer's identity provider (Okta, Entra ID, Google
// Workspace, JumpCloud) create, update and deactivate the app's users over
// SCIM 2.0, next to email and password sign-in, and stores everything in a
// SQLite file.
//
//	SCIM_TOKEN=$(openssl rand -hex 32) go run ./scim
//
// Give the IdP the base URL http://localhost:8081/scim/v2 and the token.
// Mail is printed to the log instead of sent.
package main

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/scim"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "scim.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// scimPrefix is the SCIM base URL's path, the one the IdP is given.
	scimPrefix = "/scim/v2"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
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

const (
	// envToken is the bearer token the IdP sends. There is no default: a
	// token in the source would be a token on GitHub.
	envToken = "SCIM_TOKEN"
	// connectionID names the one customer tenant this example serves; it
	// scopes every user and group that tenant creates.
	connectionID = "acme"
	// credentialID names the token, so a rotation can add the next one beside it.
	credentialID = "2026-10"
)

func main() {
	token := os.Getenv(envToken)
	if token == "" {
		log.Fatalf("%s is not set: generate one with openssl rand -hex 32 and give it to the IdP", envToken)
	}
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	sp := newSCIM(token, logGroups{})
	a, err := newAuth(db, logMailer{}, sp)
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	log.Printf("SCIM base URL %s%s (connection %s)", baseURL, scimPrefix, connectionID)
	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a, sp), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// newSCIM builds the SCIM service provider for one connection. TrustEmails
// creates provisioned addresses verified, so a new hire can set a password
// through the forgot flow on day one; use it only when the IdP manages
// addresses in domains the customer owns, because an IdP can assert any
// address. Groups go to groups, the app's own model.
//
//ds:def id=scim-example-newscim-5r2wk8qp
func newSCIM(token string, groups scim.GroupMapper) *scim.Plugin {
	return scim.New(
		scim.Connections(scim.Connection{ID: connectionID, Credentials: []scim.Credential{{ID: credentialID, Token: token}}}),
		scim.TrustEmails(),
		scim.WithGroupMapper(groups),
	)
}

// newAuth wires the library: email addresses (SCIM needs them: a
// provisioned user's primary email becomes an email identity), passwords,
// and the SCIM plugin.
func newAuth(db *sql.DB, m email.Mailer, sp *scim.Plugin) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			sp,
		),
	)
}

// newHandler mounts the library's routes, the SCIM endpoints, and a JSON
// page only a signed-in user may see. SCIM has its own media type, verbs and
// error schema, so it is served by the plugin's own handler.
//
//ds:def id=scim-example-newhandler-9m4tq7vx
func newHandler(a *auth.Auth, sp *scim.Plugin) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle(scimPrefix+"/", http.StripPrefix(scimPrefix, sp.Handler()))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux
}

// meResponse is what /me answers.
type meResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// me is an app handler: RequireUser has already refused anyone signed out,
// including a user the IdP deactivated.
func me(w http.ResponseWriter, r *http.Request) {
	u := authhttp.MustUser(r)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meResponse{ID: u.ID, Name: u.Name}) // a client that hung up cannot be told
}

// logGroups is the GroupMapper: it is told every group's full membership,
// as library user ids, inside the SCIM request's transaction. An app maps a
// group to an organization, a team or a role there; this one logs it.
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
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, strings.TrimSpace(m.Text))
	return nil
}
