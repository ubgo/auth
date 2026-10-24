// Command session-data keeps app data with each session, both ways the
// library offers: inline on the session (the active workspace, read with no
// query on every request) and in the sessiondata plugin's own table (the
// device the sign-in came from, written once at sign-in). /me shows both;
// /workspace changes the inline value.
//
//	go run ./session-data
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
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/sessiondata"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "session-data.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers.
	readHeaderTimeout = 5 * time.Second
	// defaultWorkspace is where a new session starts.
	defaultWorkspace = "personal"
	// maxBodyBytes bounds a /workspace request body.
	maxBodyBytes = 1 << 10
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set, so
	// two examples can run side by side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the server listens: this machine only, for development.
	addr = "localhost:" + port
	// baseURL is the app's public URL. Its origin is the only one allowed to
	// send cookie-authenticated POSTs, and links in mail point at it.
	baseURL = "http://localhost:" + port
)

// sqlitePragmas are the settings every SQLite connection needs: WAL and a
// busy timeout.
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

	a, sd, err := newAuth(db, logMailer{})
	if err != nil {
		log.Fatal(err) // a broken plugin combination fails here, not in production
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a, sd), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// prefs is what the app keeps inline on every session: the Go type the
// generic accessors read and write. Keep it small; it travels with the
// session into every cache and, in stateless mode, into the cookie.
//
//ds:def id=prefs-3mk8wq2n
type prefs struct {
	Workspace string `json:"workspace"`
}

// device is what the app keeps in the plugin's table: written once at
// sign-in, read when a page needs it, never carried in a token.
//
//ds:def id=device-7pq4nx3r
type device struct {
	UserAgent  string    `json:"userAgent"`
	SignedInAt time.Time `json:"signedInAt"`
}

// newAuth wires email, passwords and both kinds of session data. The hook
// gives every new session its inline starting value; the plugin records the
// device of every sign-in. The test builds the app with the same function.
//
//ds:def id=newauth-5wn2kq8m
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, *sessiondata.Plugin, error) {
	sd := sessiondata.New(sessiondata.WithInitial(func(_ context.Context, s auth.Session) (any, error) {
		return device{UserAgent: s.UserAgent, SignedInAt: s.CreatedAt}, nil
	}))
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			sd,
		),
		auth.WithDataHooks(auth.DataHooks{Session: auth.TableHooks[auth.Session]{
			BeforeCreate: func(_ context.Context, _ sqlb.DBTX, s *auth.Session) (err error) {
				s.Data, err = auth.EncodeSessionData(prefs{Workspace: defaultWorkspace})
				return err
			},
		}}),
	)
	return a, sd, err
}

// newHandler mounts the library's routes, /me and /workspace.
func newHandler(a *auth.Auth, sd *sessiondata.Plugin) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	signedIn := func(h http.HandlerFunc) http.Handler { return authhttp.Middleware(a)(authhttp.RequireUser(h)) }
	mux.Handle("GET /me", signedIn(me(sd)))
	mux.Handle("POST /workspace", signedIn(setWorkspace(a)))
	return mux
}

// meResponse is what /me answers: the inline value and the plugin's row.
//
//ds:def id=meresponse-8rk3vq6t
type meResponse struct {
	ID        string  `json:"id"`
	Workspace string  `json:"workspace"`
	Device    *device `json:"device"`
}

// me reads the inline data with no query (it came with the session) and the
// device through the plugin (one query). RequireUser has already refused
// anyone signed out.
//
//ds:def id=me-2nq9wk4p
func me(sd *sessiondata.Plugin) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := authhttp.MustUser(r)
		p, _, err := auth.SessionData[prefs](r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		d, ok, err := sessiondata.Get[device](r.Context(), sd)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out := meResponse{ID: u.ID, Workspace: p.Workspace}
		if ok {
			out.Device = &d
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out) // a client that hung up cannot be told
	}
}

// workspaceRequest is the body of POST /workspace.
type workspaceRequest struct {
	Workspace string `json:"workspace"`
}

// setWorkspace replaces the session's inline data. The middleware has
// resolved the session, so SetSessionData knows which row to write; the
// effects it records (a new token in stateless mode, a cleared cache) are
// applied by the middleware when the handler returns.
//
//ds:def id=setworkspace-6tm4xq9w
func setWorkspace(a *auth.Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in workspaceRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&in); err != nil || in.Workspace == "" {
			http.Error(w, "workspace required", http.StatusBadRequest)
			return
		}
		if err := auth.SetSessionData(r.Context(), a, prefs(in)); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(auth.Done{OK: true}) // a client that hung up cannot be told
	}
}

// logMailer prints mail instead of sending it.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
