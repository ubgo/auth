// Command ldap-sign-in signs people in with their directory username and
// password: the app stores no password, the directory checks it. The first
// sign-in links the directory account to the user holding its email
// address, or creates one.
//
//	go run ./ldap-sign-in
//
// Without LDAP_URL it uses a one-user demo directory (ada / correct horse
// battery staple). With LDAP_URL it talks to a real directory:
//
//	LDAP_URL=ldaps://ldap.example.com LDAP_BASE_DN=ou=people,dc=example,dc=com \
//	LDAP_BIND_DN=cn=svc,dc=example,dc=com LDAP_BIND_PASSWORD=… go run ./ldap-sign-in
package main

import (
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/subtle"
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
	"github.com/ubgo/auth/plugin/ldap"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "ldap-sign-in.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers.
	readHeaderTimeout = 5 * time.Second
)

var (
	// port is 8081, or $PORT when it is set, so two examples can run side by
	// side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the server listens: this machine only, for development.
	addr = "localhost:" + port
	// baseURL is the app's public URL.
	baseURL = "http://localhost:" + port
)

// sqlitePragmas: WAL so readers do not block the writer, and a busy timeout
// instead of an immediate "database is locked".
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// sqliteDSN builds the SQLite URI for a database file, escaping the path.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

func main() {
	dir, err := newDirectory()
	if err != nil {
		log.Fatal(err)
	}
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	a, err := auth.New(auth.WithDB(db, sqlb.SQLiteDialect{}), auth.WithBaseURL(baseURL), auth.WithPlugins(plugins(dir)...))
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// newDirectory is the real directory when LDAP_URL is set, else the demo
// one. NewClient refuses an ldap:// URL without StartTLS: the password would
// cross the network in clear text.
//
//ds:def id=ldap-example-newdirectory-5r8w2k6n
func newDirectory() (ldap.Directory, error) {
	if os.Getenv("LDAP_URL") == "" {
		return demoDirectory(), nil
	}
	return ldap.NewClient(ldap.Config{
		URL:          os.Getenv("LDAP_URL"),
		StartTLS:     os.Getenv("LDAP_START_TLS") == "true",
		BindDN:       os.Getenv("LDAP_BIND_DN"),
		BindPassword: os.Getenv("LDAP_BIND_PASSWORD"),
		BaseDN:       os.Getenv("LDAP_BASE_DN"),
	})
}

// plugins is the app's plugin list; the tests wire the same list with a
// directory of their own. The email plugin holds the directory's address,
// which is what links a directory account to a user who signed up another
// way. MapAttributes reads the subject from entryUUID, which survives a
// renamed entry; the DN would not.
//
//ds:def id=ldap-example-plugins-7m3q9x2v
func plugins(dir ldap.Directory, opts ...ldap.Option) []auth.Plugin {
	return []auth.Plugin{
		email.New(email.Login(), email.Recover(), email.WithMailer(email.MailerFunc(logMail))),
		ldap.New(append([]ldap.Option{ldap.WithDirectory(dir), ldap.MapAttributes(ldap.AttributeMap{Subject: "entryUUID"})}, opts...)...),
	}
}

// newHandler mounts the library's routes and /me.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux
}

// meResponse is what /me answers.
type meResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func me(w http.ResponseWriter, r *http.Request) {
	u := authhttp.MustUser(r)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meResponse{ID: u.ID, Name: u.Name}) // a client that hung up cannot be told
}

// logMail prints mail instead of sending it.
func logMail(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}

// memoryDirectory is a directory held in memory: the demo's, and the tests'.
// It keeps the Directory contract the way a real one must: an unknown user
// and a wrong password answer the same error after the same comparison.
type memoryDirectory struct {
	users map[string]memoryUser
	// down makes every call fail as an unreachable server would.
	down bool
}

// memoryUser is one entry and the SHA-256 of its password.
type memoryUser struct {
	entry ldap.Entry
	hash  [sha256.Size]byte
}

// decoyHash is compared against for an unknown user, so that path does the
// same work as a wrong password.
var decoyHash = sha256.Sum256([]byte("decoy"))

func demoDirectory() *memoryDirectory {
	d := &memoryDirectory{users: map[string]memoryUser{}}
	d.add("ada", "correct horse battery staple", ldap.Entry{DN: "uid=ada,ou=people,dc=example,dc=com", Attributes: map[string][]string{
		"cn": {"Ada Lovelace"}, "mail": {"ada@example.com"}, "entryUUID": {"9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"},
	}})
	return d
}

func (d *memoryDirectory) add(username, password string, e ldap.Entry) {
	d.users[username] = memoryUser{entry: e, hash: sha256.Sum256([]byte(password))}
}

// errDirectoryDown is what a directory that cannot be reached answers.
var errDirectoryDown = errors.New("ldap: dial: connection refused")

// Authenticate compares the password's hash in constant time.
func (d *memoryDirectory) Authenticate(_ context.Context, username, password string) (ldap.Entry, error) {
	if d.down {
		return ldap.Entry{}, errDirectoryDown
	}
	if password == "" {
		return ldap.Entry{}, ldap.ErrInvalidCredentials
	}
	u, known := d.users[username]
	want := decoyHash
	if known {
		want = u.hash
	}
	got := sha256.Sum256([]byte(password))
	if subtle.ConstantTimeCompare(got[:], want[:]) != 1 || !known {
		return ldap.Entry{}, ldap.ErrInvalidCredentials
	}
	return u.entry, nil
}
