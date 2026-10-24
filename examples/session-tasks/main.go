// Command session-tasks makes a new session finish a task before it is
// usable: here, a user who has not chosen a workspace yet must choose one.
//
//	go run ./session-tasks
//
// A small app plugin implements auth.SessionTasker. When a session is created
// it asks whether the user has a workspace; if not, the session carries the
// task "choose-workspace". Until the task is done, the session reaches only
// GET /auth/session (which lists the task), sign-out, and the one operation
// the task allows, POST /auth/workspace/choose; every other operation and
// every route behind authhttp.RequireUser answers 403
// auth.session_task_pending. Choosing a workspace completes the task with
// auth.CompleteSessionTask, which hands the client a new token for an
// ordinary session. plugin/twofactor's RequireEnrolment uses the same
// mechanism for auth.TaskSetupMFA. Mail is printed to the log.
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
	"sync"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database the example creates next to it.
	dbFile = "session-tasks.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers.
	readHeaderTimeout = 5 * time.Second
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr listens on this machine only, for development.
	addr = "localhost:" + port
	// baseURL is the app's public URL: the one origin allowed to send
	// cookie-authenticated POSTs.
	baseURL = "http://" + addr
)

// sqlitePragmas are the settings every SQLite connection needs: WAL so readers
// do not block the writer, and a busy timeout instead of an immediate
// "database is locked".
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// sqliteDSN builds the SQLite URI for a database file, escaping the path so a
// "#" or "?" in it cannot start the URI's fragment or query.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

func main() {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	a, err := newAuth(db, newWorkspaces(), nil)
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

// newAuth wires email addresses, passwords and the workspace plugin, then
// any extra plugins and options (a test's).
func newAuth(db *sql.DB, ws *workspaces, extra []auth.Plugin, opts ...auth.Option) (*auth.Auth, error) {
	plugins := append([]auth.Plugin{
		email.New(email.Login(), email.Recover(), email.WithMailer(email.MailerFunc(logMail))),
		password.New(),
		ws,
	}, extra...)
	return auth.New(append([]auth.Option{
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(plugins...),
	}, opts...)...)
}

// newHandler mounts the library's routes and /me, an app route that only a
// usable session reaches.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux
}

// me answers the signed-in user's id.
func me(w http.ResponseWriter, r *http.Request) {
	u, _ := auth.CurrentUser(r.Context()) // RequireUser let only a user through
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"id": u.ID})
}

// logMail prints a message instead of sending it.
func logMail(_ context.Context, m email.Mail) error {
	log.Printf("mail to %s: %s", m.To, m.Subject)
	return nil
}

// The workspace plugin's names.
const (
	// pluginName is the route prefix: /auth/workspace/...
	pluginName = "workspace"
	// taskChooseWorkspace is the session task this plugin requires.
	taskChooseWorkspace auth.SessionTaskID = "choose-workspace"
	// endpointChoose is the operation that completes it.
	endpointChoose auth.EndpointID = "workspace.choose"
	// maxWorkspaceName bounds the name a user types.
	maxWorkspaceName = 64
)

// errWorkspaceName refuses an empty or overlong workspace name.
var errWorkspaceName = auth.NewError("workspace.name_invalid", http.StatusBadRequest, "Give the workspace a name of 1 to 64 characters.")

// ChooseRequest is the input of workspace.choose.
type ChooseRequest struct {
	Name string `json:"name"`
}

// ChooseResult is its output.
type ChooseResult struct {
	Workspace string `json:"workspace"`
}

// workspaces is the app plugin: which workspace each user chose. A real app
// keeps this in its own table; a map keeps the example short.
//
//ds:def id=sessiontasks-plugin-6mw3kq8v
type workspaces struct {
	mu     sync.Mutex
	byUser map[string]string
	choose *auth.Op[ChooseRequest, ChooseResult]
}

// newWorkspaces builds the plugin and its one operation.
func newWorkspaces() *workspaces {
	ws := &workspaces{byUser: map[string]string{}}
	ws.choose = auth.Define(auth.OpInfo{ID: endpointChoose, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/choose"}, ws.doChoose)
	return ws
}

// Name is the plugin's route prefix.
func (*workspaces) Name() string { return pluginName }

// Operations serves workspace.choose.
func (ws *workspaces) Operations() []auth.Operation { return []auth.Operation{ws.choose} }

// SessionTasks declares the task and the one operation that serves it.
func (*workspaces) SessionTasks() []auth.SessionTask {
	return []auth.SessionTask{{ID: taskChooseWorkspace, Allow: []auth.EndpointID{endpointChoose}}}
}

// SessionTasksFor asks a user without a workspace to choose one.
func (ws *workspaces) SessionTasksFor(_ context.Context, in auth.SignInAttempt) ([]auth.SessionTaskID, error) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	if _, ok := ws.byUser[in.UserID]; ok {
		return nil, nil
	}
	return []auth.SessionTaskID{taskChooseWorkspace}, nil
}

// doChoose records the workspace, then completes the task on the caller's
// own session. CompleteSessionTask is a no-op for a session without the
// task, so the same operation also serves a user switching workspaces.
func (ws *workspaces) doChoose(ctx context.Context, c *auth.Call, in ChooseRequest) (ChooseResult, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > maxWorkspaceName {
		return ChooseResult{}, errWorkspaceName
	}
	ws.mu.Lock()
	ws.byUser[c.User.ID] = name
	ws.mu.Unlock()
	if _, err := c.Auth.CompleteSessionTask(ctx, c, taskChooseWorkspace); err != nil {
		return ChooseResult{}, err
	}
	return ChooseResult{Workspace: name}, nil
}

var (
	_ auth.SessionTasker     = (*workspaces)(nil)
	_ auth.OperationProvider = (*workspaces)(nil)
)
