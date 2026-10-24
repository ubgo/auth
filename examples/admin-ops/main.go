// Command admin-ops is the admin plugin end to end: the first admin is granted
// from a subcommand, then over HTTP an admin finds a user, creates one, sets a
// password, grants and removes admin rights, ends a user's sessions, bans a
// user who then reads why at sign-in, acts as a user for support within the
// limits the library enforces and comes back to their own session, and reads
// the audit log of all of it.
//
//	go run ./admin-ops                          serve on localhost:8081
//	go run ./admin-ops grant alice@example.com  make the first admin
//	go run ./admin-ops auth admin grant --email alice@example.com   the same through authcli
//	echo "$PW" | go run ./admin-ops auth admin create --email root@example.com --name Root --password-stdin
//
// Mail is printed to the log instead of sent.
package main

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authcli"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/audit"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "admin-ops.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
	// grantCommand is the subcommand that makes the first admin. Admins grant
	// each other over HTTP afterwards; the first one has to come from code.
	grantCommand = "grant"
	// authCommand hands the rest of the command line to authcli, whose
	// `admin grant` and `admin create` do the same job for any app without
	// a grantByEmail of its own.
	authCommand = "auth"
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

func main() {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, ad, err := newAuth(db, logMailer{})
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	ctx := context.Background()
	if _, err := a.Migrate(ctx); err != nil {
		log.Fatal(err)
	}

	if len(os.Args) > 1 && os.Args[1] == authCommand {
		code := authcli.Main(ctx, a, os.Args[2:], os.Stdout, os.Stderr)
		_ = a.Close() // os.Exit skips the deferred calls
		os.Exit(code)
	}
	if len(os.Args) == 3 && os.Args[1] == grantCommand {
		id, err := grantByEmail(ctx, a, ad, os.Args[2])
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s (%s) is an admin\n", os.Args[2], id)
		return
	}

	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// newAuth wires the library with the admin and audit plugins and returns the
// admin plugin for the grant command. The test builds the app with this same
// function.
//
//ds:def id=newauth-tj6fup6p owner=@khanakia stability=stable
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, *admin.Plugin, error) {
	ad := admin.New(admin.BannedMessage(bannedMessage))
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(m)), password.New(), ad, audit.New()),
	)
	return a, ad, err
}

// bannedMessage is what a banned user reads at sign-in: the reason the admin
// gave, and until when for a temporary ban. It runs only after the credential
// was proven, so it tells a stranger nothing.
//
//ds:def id=bannedmessage-mz3a85wp owner=@khanakia stability=stable
func bannedMessage(_ context.Context, b admin.Ban) string {
	msg := "Your account is suspended"
	if b.Reason != "" {
		msg += ": " + b.Reason
	}
	if b.ExpiresAt != nil {
		msg += " (until " + b.ExpiresAt.Format(time.RFC1123) + ")"
	}
	return msg + "."
}

// grantByEmail makes the owner of a verified address an admin. Only a
// verified address counts: admin rights for whoever typed an address first
// would be a takeover.
//
//ds:def id=grantbyemail-2uubrheb owner=@khanakia stability=stable
func grantByEmail(ctx context.Context, a *auth.Auth, ad *admin.Plugin, address string) (string, error) {
	idn, err := a.FindIdentity(ctx, email.KindEmail, address, true)
	if err != nil {
		return "", fmt.Errorf("find a verified %s: %w", address, err)
	}
	return idn.UserID, ad.Grant(ctx, idn.UserID)
}

// newHandler mounts the library's routes, the admin plugin's among them, and
// one page that says who the session belongs to, which is how an admin sees
// that an impersonation worked.
//
//ds:def id=newhandler-vte4bmzn owner=@khanakia stability=stable
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("GET /me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux
}

// meResponse is what GET /me answers.
type meResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// me answers the user of the session, whoever opened it.
func me(w http.ResponseWriter, r *http.Request) {
	u := authhttp.MustUser(r)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meResponse{ID: u.ID, Name: u.Name}) // a client that hung up cannot be told
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
