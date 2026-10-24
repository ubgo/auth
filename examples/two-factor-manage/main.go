// Command two-factor-manage is the "manage two-factor" page of an app on
// email and password with an authenticator app: show the QR code again, show
// the recovery codes again, turn two-factor off, the two calls a support
// desk needs when a user is locked out or lost both phone and codes, and the
// admin plugin's routes over another user's factor (see, pause, switch back
// on, reset).
//
//	AUTH_SECRET=$(openssl rand -base64 32) STAFF_USER_IDS=usr_… go run ./two-factor-manage
//
// Mail is printed to the log instead of sent.
package main

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"maps"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/twofactor"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "two-factor-manage.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
	// envStaff names the variable listing the support staff's user ids,
	// comma-separated. Who may act for another user is the app's rule: the
	// support routes check this list themselves, and the same ids are the
	// admin plugin's admins (admin.AdminIDs), whose default roles grant the
	// two-factor routes. A real app asks its own roles or its authorizer
	// (admin.WithAuthorizer).
	envStaff = "STAFF_USER_IDS"
)

// The second-factor settings. Each is a product decision.
const (
	// maxWrongCodes wrong codes in a row lock the factor for lockFor.
	maxWrongCodes = 3
	// lockFor is how long a locked factor refuses every code; support's
	// unlock ends it early.
	lockFor = 15 * time.Minute
)

// Support routes, behind the app's own staff check: the library gives Reset
// and Unlock no route because only the app knows who may call them.
const (
	supportResetPath  = "POST /support/two-factor/reset"
	supportUnlockPath = "POST /support/two-factor/unlock"
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set, so
	// two examples can run side by side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the server listens: this machine only, for development.
	addr = "localhost:" + port
	// baseURL is the app's public URL. Its origin is the only one allowed to
	// send cookie-authenticated POSTs.
	baseURL = "http://localhost:" + port
)

// sqlitePragmas are the settings every SQLite connection needs: WAL so readers
// do not block the writer, and a busy timeout instead of an immediate
// "database is locked".
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// sqliteDSN builds the SQLite URI for a database file. It escapes the path
// instead of concatenating "file:"+path, because a "#" or "?" in a path would
// otherwise start the URI's fragment or query and open a different file.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

func main() {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// The factor's secret and the sealed recovery codes use keys derived
	// from the secret, so both survive a restart only with the same secret.
	staff := parseStaff(os.Getenv(envStaff))
	a, tf, err := newAuth(db, []byte(os.Getenv(auth.EnvSecret)), logMailer{}, slices.Collect(maps.Keys(staff))...)
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a, tf, staff), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// newAuth wires email and password sign-in, an authenticator-app second
// factor whose QR code and recovery codes can be shown again, and the admin
// plugin, whose two-factor routes find the factor plugin by itself; admins
// are the users admin.AdminIDs names. It returns the factor plugin too, for
// the support calls. The test builds the app with the same function.
//
//ds:def id=two-factor-manage-newauth-8pk3vn6w
func newAuth(db *sql.DB, secret []byte, m email.Mailer, admins ...string) (*auth.Auth, *twofactor.Plugin, error) {
	tf := twofactor.New(
		twofactor.ReadableTOTPURI(),                             // POST /auth/twofactor/totp-uri
		twofactor.RecoveryCodeStorage(twofactor.StoreEncrypted), // POST /auth/twofactor/recovery-codes/view
		twofactor.Lockout(maxWrongCodes, lockFor),
	)
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithSecret(secret), // seals the TOTP secret and the recovery codes
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			tf,
			// GET /auth/admin/two-factor, POST /auth/admin/disable-two-factor,
			// /enable-two-factor and /reset-two-factor.
			admin.New(admin.AdminIDs(admins...)),
		),
	)
	return a, tf, err
}

// staffList is the set of user ids allowed to call the support routes.
type staffList map[string]bool

// parseStaff reads a comma-separated list of user ids.
func parseStaff(raw string) staffList {
	out := staffList{}
	for _, id := range strings.Split(raw, ",") {
		if id = strings.TrimSpace(id); id != "" {
			out[id] = true
		}
	}
	return out
}

// errNotStaff refuses a support call from someone who is not staff.
var errNotStaff = auth.NewError("app.not_staff", http.StatusForbidden, "Only support staff can do this.")

// newHandler mounts the library's routes, the app's /me page and the two
// support routes.
func newHandler(a *auth.Auth, tf *twofactor.Plugin, staff staffList) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	signedIn := func(h http.Handler) http.Handler { return authhttp.Middleware(a)(authhttp.RequireUser(h)) }
	mux.Handle("GET /me", signedIn(meHandler(a)))
	mux.Handle(supportResetPath, signedIn(supportHandler(staff, tf.Reset)))
	mux.Handle(supportUnlockPath, signedIn(supportHandler(staff, tf.Unlock)))
	return mux
}

// supportRequest names the user support acts for.
type supportRequest struct {
	UserID string `json:"userId"`
}

// supportHandler runs act (tf.Reset or tf.Unlock) for the user in the body,
// after the app's own staff check. Reset leaves sessions alone; an app that
// suspects the account was taken also calls a.DeleteUserSessions.
//
//ds:def id=two-factor-manage-support-6tq2wk9m
func supportHandler(staff staffList, act func(ctx context.Context, userID string) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !staff[authhttp.MustUser(r).ID] {
			authhttp.WriteError(w, errNotStaff)
			return
		}
		var in supportRequest
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.UserID == "" {
			authhttp.WriteError(w, auth.ErrBadRequest)
			return
		}
		if err := act(r.Context(), in.UserID); err != nil {
			// twofactor.not_enrolled for a user with no factor, so a
			// mistyped id shows up instead of passing silently.
			authhttp.WriteError(w, err)
			return
		}
		writeJSON(w, auth.Done{OK: true})
	})
}

// meResponse is what /me answers.
type meResponse struct {
	ID               string `json:"id"`
	TwoFactorEnabled bool   `json:"twoFactorEnabled"`
}

// meHandler reports whether the user has two-factor on, from the flat column
// the plugin adds to auth_user.
func meHandler(a *auth.Auth) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := authhttp.MustUser(r)
		var cols twofactor.TwoFactorColumns
		if err := a.LoadUserColumns(r.Context(), u.ID, twofactor.Bindings(&cols)...); err != nil {
			authhttp.WriteError(w, err)
			return
		}
		writeJSON(w, meResponse{ID: u.ID, TwoFactorEnabled: cols.TwoFactorEnabled})
	})
}

// writeJSON answers v as JSON.
func writeJSON[T any](w http.ResponseWriter, v T) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v) // a client that hung up cannot be told
}

// logMailer prints mail instead of sending it.
type logMailer struct{}

// Send logs the message.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
