// Command organizations adds teams to an email and password app: a user
// creates an organization, invites a colleague by email, the colleague
// accepts once their address is verified, and the app's own routes are
// guarded by the caller's role in the organization named in the URL.
//
//	go run ./organizations
//
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
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "organizations.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// pathOrgParam is the path wildcard that names the organization in the
	// app's own routes.
	pathOrgParam = "org"
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
	// baseURL is the app's public URL. Its origin is the only one allowed to
	// send cookie-authenticated POSTs, and links in mail point at it.
	baseURL = "http://localhost:" + port
)

// sqlitePragmas are the settings every SQLite connection needs: WAL so readers
// do not block the writer, a busy timeout instead of an immediate "database is
// locked", and foreign keys, which SQLite leaves off and the library's cascades
// depend on.
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// sqliteDSN builds the SQLite URI for a database file. It escapes the path
// instead of concatenating "file:"+path, because a "#" or "?" in a path would
// otherwise start the URI's fragment or query and open a different file. It
// escapes only the path, never building a url.URL with a scheme, because Go
// writes a relative path such as "auth.db" as "file://auth.db", which SQLite
// reads as a host.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

// The invitation mail. The organization plugin sends it through the email
// plugin with purpose organization.PurposeInvite and a link to the app's
// invitations page; the words are the app's.
const (
	inviteSubject = "You are invited to join a team"
	inviteText    = "You were invited to join an organization. Sign in with this address, verify it if you have not, and accept the invitation here:\n\n"
)

func main() {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, err := newAuth(db, logMailer{})
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}
	h, err := newHandler(a)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// newAuth wires the library. The organization plugin requires the email
// plugin: an invitation is addressed to an email, and only a verified one
// can accept it.
//
//ds:def id=newauth-yt5aa3nm owner=@khanakia stability=stable
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m), email.Templates(mailTemplates)),
			password.New(),
			organization.New(),
		),
	)
}

// mailTemplates words the invitation and leaves every other message to the
// email plugin's defaults.
//
//ds:def id=mailtemplates-6y8uywp9 owner=@khanakia stability=stable
func mailTemplates(m auth.Message) (subject, text string) {
	if m.Purpose == organization.PurposeInvite {
		return inviteSubject, inviteText + m.Link
	}
	return email.DefaultTemplates(m)
}

// newHandler mounts the library's routes (create, invite, accept, members
// and more under /auth/organization/) and two pages of the app's own, each
// guarded by the caller's role in the organization the path names:
// a dashboard for every member, billing for admins and owners.
//
//ds:def id=newhandler-kn3pd8s3 owner=@khanakia stability=stable
func newHandler(a *auth.Auth) (http.Handler, error) {
	orgs, err := auth.PluginOf[*organization.Plugin](a)
	if err != nil {
		return nil, err
	}
	mw := authhttp.Middleware(a)
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("GET /orgs/{"+pathOrgParam+"}/dashboard", mw(orgs.RequireRole(orgInPath, organization.RoleMember)(page("dashboard"))))
	mux.Handle("GET /orgs/{"+pathOrgParam+"}/billing", mw(orgs.RequireRole(orgInPath, organization.RoleAdmin)(page("billing"))))
	return mux, nil
}

// orgInPath reads the organization id from the route, for RequireRole. An
// app could read it from a subdomain or a header instead.
//
//ds:def id=orginpath-kmt4xuts owner=@khanakia stability=stable
func orgInPath(r *http.Request) string { return r.PathValue(pathOrgParam) }

// pageResponse is what the app's guarded pages answer.
type pageResponse struct {
	Page  string `json:"page"`
	OrgID string `json:"orgId"`
	User  string `json:"user"`
}

// page answers which page the caller reached, for which organization. By the
// time it runs, RequireRole has checked the role.
func page(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pageResponse{Page: name, OrgID: orgInPath(r), User: authhttp.MustUser(r).Name}) // a client that hung up cannot be told
	}
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
