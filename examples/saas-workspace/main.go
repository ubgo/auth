// Command saas-workspace signs a user up and creates their workspace in one
// transaction: if the workspace cannot be created, the user does not exist
// either, and no verification mail goes out.
//
//	go run ./saas-workspace
//
// Mail is printed to the log instead of sent.
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
	"strings"
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
	dbFile = "saas-workspace.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
	// maxBodyBytes caps the sign-up body, which holds four short strings.
	maxBodyBytes = 1 << 16
	// workspaceIDPrefix makes a workspace id recognisable in logs, as the
	// library's "usr_" does for users.
	workspaceIDPrefix = "ws"
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
// locked", and foreign keys, which SQLite leaves off and the cascade below
// depends on.
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

// appSchema is the app's own table. Its owner column holds a user id with no
// foreign key: the library creates none either (tables are plain storage), and
// a deleted owner's workspaces are removed by the app's BeforeDelete hook.
// Reads of the auth tables are open to the app; only writes go through the
// library. A workspace name is unique, which is the failure this example
// demonstrates.
const appSchema = `CREATE TABLE IF NOT EXISTS workspace (
	id       TEXT NOT NULL PRIMARY KEY,
	name     TEXT NOT NULL UNIQUE,
	owner_id TEXT NOT NULL
)`

// Statements the app runs itself, inside the library's transaction.
const (
	insertWorkspace = `INSERT INTO workspace (id, name, owner_id) VALUES (?, ?, ?)`
	selectOwned     = `SELECT id, name FROM workspace WHERE owner_id = ? ORDER BY name`
	deleteOwned     = `DELETE FROM workspace WHERE owner_id = ?`
)

// deleteWorkspaces is the app's User.BeforeDelete hook: a deleted owner's
// workspaces go with the owner, through tx, the deleting transaction.
func deleteWorkspaces(ctx context.Context, tx sqlb.DBTX, u *auth.User) error {
	_, err := tx.ExecContext(ctx, deleteOwned, u.ID)
	return err
}

// Errors the app's sign-up answers, in the library's error JSON so a client
// handles one shape.
var (
	errWorkspaceTaken = auth.NewError("workspace.name_taken", http.StatusConflict, "A workspace with this name already exists.")
	errWorkspaceName  = auth.NewError("workspace.name_required", http.StatusBadRequest, "Name your workspace.")
)

func main() {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, pw, err := newAuth(db, logMailer{})
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	if err := migrate(context.Background(), a); err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a, pw), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// newAuth wires the library and returns the password plugin too, because the
// app's sign-up calls it directly. The test builds the app with this same
// function.
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, *password.Plugin, error) {
	pw := password.New()
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(m)), pw),
		auth.WithDataHooks(auth.DataHooks{User: auth.TableHooks[auth.User]{BeforeDelete: deleteWorkspaces}}),
	)
	return a, pw, err
}

// migrate creates the library's tables, then the app's.
func migrate(ctx context.Context, a *auth.Auth) error {
	if _, err := a.Migrate(ctx); err != nil {
		return err
	}
	_, err := a.DB().ExecContext(ctx, appSchema)
	return err
}

// newHandler mounts the library's routes (sign-in, verify, sign-out, …), the
// app's own sign-up and a page listing the user's workspaces.
func newHandler(a *auth.Auth, pw *password.Plugin) http.Handler {
	mw := authhttp.Middleware(a)
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("POST /signup", mw(signupHandler(a, pw)))
	mux.Handle("GET /workspaces", mw(authhttp.RequireUser(workspacesHandler(a))))
	return mux
}

// signupRequest is the app's sign-up form. Password is password.Secret so a
// logged request prints "[redacted]"; it decodes from JSON like a string.
type signupRequest struct {
	Email     string          `json:"email"`
	Password  password.Secret `json:"password"`
	Name      string          `json:"name"`
	Workspace string          `json:"workspace"`
}

// Workspace is one row of the app's table.
type Workspace struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// signupResponse is what POST /signup answers.
type signupResponse struct {
	User      auth.UserView `json:"user"`
	Workspace Workspace     `json:"workspace"`
}

// signup creates the account and the workspace in one transaction. Every
// library call made with the ctx that Tx passes joins it; the app writes its
// row with tx. The verify mail is queued by the library and sent only after
// the commit, so a rolled-back sign-up sends nothing.
//
//ds:def id=saas-signup-nw9pz4mq owner=@khanakia stability=stable
func signup(ctx context.Context, a *auth.Auth, pw *password.Plugin, in signupRequest) (signupResponse, error) {
	name := strings.TrimSpace(in.Workspace)
	if name == "" {
		return signupResponse{}, errWorkspaceName
	}
	var out signupResponse
	err := a.Tx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		res, err := pw.SignUp(ctx, password.SignUpRequest{Identifier: in.Email, Password: in.Password, Name: in.Name})
		if err != nil {
			return err
		}
		id, err := a.NewID(workspaceIDPrefix)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, insertWorkspace, id, name, res.User.ID); err != nil {
			if auth.IsUniqueViolation(err) {
				return errWorkspaceTaken
			}
			return err
		}
		out = signupResponse{User: res.User, Workspace: Workspace{ID: id, Name: name}}
		return nil
	})
	return out, err
}

// signupHandler is the HTTP side of signup. It checks the origin itself: a
// sign-up carries no session cookie, so the library's cookie-based origin
// check does not cover it, and a cross-site form could otherwise sign a
// visitor into an account the attacker controls.
//
//ds:def id=saas-signuphandler-88qakgg4 owner=@khanakia stability=stable
func signupHandler(a *auth.Auth, pw *password.Plugin) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.TrustsOrigin(authhttp.RequestOf(r).Client.Origin) {
			authhttp.WriteError(w, auth.ErrOriginNotTrusted)
			return
		}
		var in signupRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&in); err != nil {
			authhttp.WriteError(w, auth.ErrBadRequest)
			return
		}
		out, err := signup(r.Context(), a, pw, in)
		if err != nil {
			var ae *auth.Error
			if !errors.As(err, &ae) {
				log.Printf("signup: %v", err)
			}
			authhttp.WriteError(w, err)
			return
		}
		writeJSON(w, out)
	})
}

// workspacesResponse is what GET /workspaces answers.
type workspacesResponse struct {
	Workspaces []Workspace `json:"workspaces"`
}

// workspacesHandler lists the signed-in user's workspaces: the app reads its
// own table keyed by the library's user id.
func workspacesHandler(a *auth.Auth) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rows, err := a.DB().QueryContext(r.Context(), selectOwned, authhttp.MustUser(r).ID)
		if err != nil {
			authhttp.WriteError(w, err)
			return
		}
		defer rows.Close()
		out := workspacesResponse{Workspaces: []Workspace{}}
		for rows.Next() {
			var ws Workspace
			if err := rows.Scan(&ws.ID, &ws.Name); err != nil {
				authhttp.WriteError(w, err)
				return
			}
			out.Workspaces = append(out.Workspaces, ws)
		}
		if err := rows.Err(); err != nil {
			authhttp.WriteError(w, err)
			return
		}
		writeJSON(w, out)
	})
}

// writeJSON answers v with 200. Generic so each handler passes its own
// response type rather than an untyped value.
func writeJSON[T any](w http.ResponseWriter, v T) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v) // a client that hung up cannot be told
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
