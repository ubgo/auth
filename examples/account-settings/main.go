// Command account-settings is the backend of an app's "account settings"
// page, on email and password sign-in: edit your own profile fields, keep
// several accounts signed in on one browser and switch between them, see and
// end your other sessions with a kept history of the ended ones, and delete
// your account, which needs a recent sign-in and, optionally, a mailed
// confirmation link.
//
//	go run ./account-settings
//	DELETE_CONFIRM=link go run ./account-settings
//
// Mail is printed to the log instead of sent; plug an SMTP or API client
// into logMailer's place.
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
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "account-settings.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
	// deleteConfirmEnv picks how account deletion is confirmed when the
	// program starts: unset deletes at once, deleteConfirmLink mails a link.
	deleteConfirmEnv = "DELETE_CONFIRM"
	// deleteConfirmLink is the deleteConfirmEnv value that turns on the
	// mailed confirmation link.
	deleteConfirmLink = "link"
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

	deletion := deleteAtOnce
	if os.Getenv(deleteConfirmEnv) == deleteConfirmLink {
		deletion = deleteByLink
	}
	a, err := newAuth(db, logMailer{}, deletion)
	if err != nil {
		log.Fatal(err) // a broken plugin combination fails here, not in production
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// Names of the app's own columns on auth_user.
const (
	// colTimezone is the user's display time zone, which they edit
	// themselves on the settings page.
	colTimezone = "app_timezone"
	// colPlan is the user's billing plan. The app writes it from its own
	// billing code; the user must never set it, so it is declared but not
	// listed in WithProfileFields.
	colPlan = "app_plan"
	// defaultTimezone and defaultPlan are what an existing row, and a new
	// account, get until someone writes the column.
	defaultTimezone = "UTC"
	defaultPlan     = "free"
)

// appColumns are the app's columns on auth_user, migrated by the library
// like a plugin's. Both are NOT NULL with a default, so rows that existed
// before the column are filled.
//
//ds:def id=account-settings-app-columns-dsxpnus2
var appColumns = []auth.ColumnExtension{
	{Name: colTimezone, Type: auth.ColumnText, Default: "'" + defaultTimezone + "'"},
	{Name: colPlan, Type: auth.ColumnText, Default: "'" + defaultPlan + "'"},
}

// Timezone and Plan are the typed expressions of the app's columns, for
// reading them back (LoadUserColumns) with their Go type checked.
var (
	Timezone = sqlb.Col[string](auth.TableUser, colTimezone)
	Plan     = sqlb.Col[string](auth.TableUser, colPlan)
)

// Account-settings policy.
//
//ds:def id=account-settings-policy-constants-h83tmkp6
const (
	// maxDeviceAccounts is how many accounts one browser may hold at once,
	// the active one included. Three is below the library's default of five
	// (auth.DefaultMaxDeviceSessions) so the walkthrough reaches the cap.
	maxDeviceAccounts = 3
	// freshWindow is how recent a sign-in must be to delete the account.
	// Shorter than the library's default ten minutes (auth.DefaultFreshWindow):
	// deleting cannot be undone, so a laptop left open for a coffee break
	// must not be enough.
	freshWindow = 5 * time.Minute
)

// deleteAtOnce and deleteByLink are the two ways to confirm a deletion.
// deleteAtOnce deletes on the call, which already needs a fresh sign-in;
// deleteByLink mails a link to the verified address first, for apps whose
// users sign in through a provider and have no password to re-enter.
//
//ds:def id=account-settings-deletion-modes-hvnphstm
var (
	deleteAtOnce = auth.AccountDeletion{}
	deleteByLink = auth.AccountDeletion{ConfirmByLink: true}
)

// newAuth wires email and password sign-in plus every account-settings
// feature. deletion picks how deleting is confirmed; extra lets the test add
// a clock. main and the test build the app with this one function.
//
//ds:def id=account-settings-newauth-xtsn886m
func newAuth(db *sql.DB, m email.Mailer, deletion auth.AccountDeletion, extra ...auth.Option) (*auth.Auth, error) {
	opts := []auth.Option{
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
		),
		auth.WithUserColumns(appColumns...),
		auth.WithProfileFields(colTimezone),
		auth.WithMultiSession(maxDeviceAccounts),
		auth.WithSessionArchive(),
		auth.WithFreshWindow(freshWindow),
		auth.WithAccountDeletion(deletion),
	}
	return auth.New(append(opts, extra...)...)
}

// Routes of the app's own pages.
const (
	// mePath answers who is signed in, with the app's columns.
	mePath = "/me"
	// signedOutPath lists the user's ended sessions from the archive.
	signedOutPath = "/account/signed-out"
)

// newHandler mounts the library's routes, the app's pages that read the
// signed-in user, and the page a deletion link opens.
//
//ds:def id=account-settings-newhandler-y95cbzf2
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	signedIn := func(h func(*auth.Auth, http.ResponseWriter, *http.Request)) http.Handler {
		return authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h(a, w, r) })))
	}
	mux.Handle("GET "+mePath, signedIn(me))
	mux.Handle("GET "+signedOutPath, signedIn(signedOut))
	mux.HandleFunc("GET "+auth.DefaultDeleteAccountPage, deletePage)
	return mux
}

// meResponse is what /me answers: the user and the app's columns.
type meResponse struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Timezone string `json:"timezone"`
	Plan     string `json:"plan"`
}

// me reads the app's columns of the signed-in user in one query, typed by
// the column expressions. RequireUser has already refused anyone signed out.
//
//ds:def id=account-settings-me-handler-3nycxnut
func me(a *auth.Auth, w http.ResponseWriter, r *http.Request) {
	u := authhttp.MustUser(r)
	out := meResponse{ID: u.ID, Name: u.Name}
	if err := a.LoadUserColumns(r.Context(), u.ID, sqlb.Bind(Timezone, &out.Timezone), sqlb.Bind(Plan, &out.Plan)); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	writeJSON(w, out)
}

// endedSession is one row of the signed-out history.
type endedSession struct {
	ID        string    `json:"id"`
	UserAgent string    `json:"userAgent"`
	CreatedAt time.Time `json:"createdAt"`
	RevokedAt time.Time `json:"revokedAt"`
}

// signedOutResponse is what /account/signed-out answers.
type signedOutResponse struct {
	Sessions []endedSession `json:"sessions"`
}

// signedOut lists the signed-in user's ended sessions, newest first: the
// rows WithSessionArchive kept instead of deleting. A support page or a
// "recent activity" panel reads the same list.
//
//ds:def id=account-settings-signed-out-history-u88ydvjz
func signedOut(a *auth.Auth, w http.ResponseWriter, r *http.Request) {
	list, err := a.RevokedSessions(r.Context(), authhttp.MustUser(r).ID)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	out := signedOutResponse{Sessions: make([]endedSession, 0, len(list))}
	for _, s := range list {
		// RevokedSessions returns only rows with RevokedAt set.
		out.Sessions = append(out.Sessions, endedSession{ID: s.ID, UserAgent: s.UserAgent, CreatedAt: s.CreatedAt, RevokedAt: *s.RevokedAt})
	}
	writeJSON(w, out)
}

// writeJSON answers v as JSON.
func writeJSON[T any](w http.ResponseWriter, v T) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v) // a client that hung up cannot be told
}

// deletePageHTML is the page a deletion link opens. It does not delete on
// load: mail scanners open every link to preview it, and a GET that deleted
// would remove the account before its owner decided. The button POSTs the
// token from the address bar to the confirm route.
//
//ds:def id=account-settings-delete-page-8dn8gur2
const deletePageHTML = `<!doctype html>
<meta charset="utf-8">
<title>Delete your account</title>
<p>This deletes your account and everything in it. It cannot be undone.</p>
<button id="go">Delete my account</button>
<pre id="out"></pre>
<script>
document.getElementById("go").onclick = async () => {
  const token = new URLSearchParams(location.search).get("token");
  const res = await fetch("` + authPrefix + `/account/delete/confirm", {
    method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({token}),
  });
  document.getElementById("out").textContent = res.ok ? "Your account is deleted." : (await res.json()).error.message;
};
</script>
`

// deletePage serves deletePageHTML.
func deletePage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(deletePageHTML)) // a client that hung up cannot be told
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
