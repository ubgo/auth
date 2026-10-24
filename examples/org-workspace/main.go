// Command org-workspace keeps the app's own data beside each organization:
// a project table keyed by the organization's id, whose first row is written
// in the same transaction that creates the organization, whose rows go with
// the organization when it is deleted, and which an import fills together
// with the organization or not at all.
//
//	go run ./org-workspace
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
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "org-workspace.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// pathOrgParam is the path wildcard that names the organization in the
	// app's own routes.
	pathOrgParam = "org"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
	// maxBodyBytes caps a create-project body, which holds one short name.
	maxBodyBytes = 1 << 16
	// projectIDPrefix makes a project id recognisable in logs, as the
	// library's "usr_" and "org_" do.
	projectIDPrefix = "prj"
	// defaultProject is the project every new organization starts with, so
	// its first page is never empty.
	defaultProject = "General"
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
// do not block the writer, and a busy timeout instead of an immediate
// "database is locked".
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// sqliteDSN builds the SQLite URI for a database file, escaping only the path
// so a "#" or "?" in it cannot start the URI's fragment or query.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

// appSchema is the app's own table. org_id holds auth_org.id the way a
// user's rows hold auth_user.id, with no foreign key: the library creates
// none (its tables are plain storage), so the delete hook removes the rows.
// A project name is unique within its organization, which is the failure
// the import demonstrates.
const appSchema = `CREATE TABLE IF NOT EXISTS project (
	id     TEXT NOT NULL PRIMARY KEY,
	org_id TEXT NOT NULL,
	name   TEXT NOT NULL,
	UNIQUE (org_id, name)
)`

// Statements the app runs itself, always on the connection a.Conn returns,
// so inside an operation they join its transaction.
const (
	insertProject  = `INSERT INTO project (id, org_id, name) VALUES (?, ?, ?)`
	selectProjects = `SELECT id, name FROM project WHERE org_id = ? ORDER BY name`
	deleteProjects = `DELETE FROM project WHERE org_id = ?`
)

// Errors the app's routes answer, in the library's error JSON so a client
// handles one shape. Declared once so each code is registered once.
var (
	errProjectTaken = auth.NewError("project.name_taken", http.StatusConflict, "A project with this name already exists.")
	errProjectName  = auth.NewError("project.name_required", http.StatusBadRequest, "Name your project.")
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
	if err := migrate(context.Background(), a); err != nil {
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

// addProject inserts one project on a.Conn(ctx): inside an operation or
// a.Tx that is the open transaction, so the row commits or rolls back with
// it. The unique index's refusal becomes the app's own error.
func addProject(ctx context.Context, a *auth.Auth, orgID, name string) (Project, error) {
	conn, err := a.Conn(ctx)
	if err != nil {
		return Project{}, err
	}
	id, err := a.NewID(projectIDPrefix)
	if err != nil {
		return Project{}, err
	}
	if _, err := conn.ExecContext(ctx, insertProject, id, orgID, name); err != nil {
		if auth.IsUniqueViolation(err) {
			return Project{}, errProjectTaken
		}
		return Project{}, err
	}
	return Project{ID: id, Name: name}, nil
}

// hooks writes the app's rows inside the organization plugin's own
// transactions: every organization, created over HTTP or from Go, starts
// with a project, and a deleted one takes its projects along. Either hook's
// error rolls the whole operation back, so the two tables never disagree.
// organization.WithHooksFrom calls it with the *auth.Auth once auth.New has
// built it, and a.Conn(ctx) inside a hook is the operation's transaction.
//
//ds:def id=orgworkspace-hooks-4k8wq2vn
func hooks(a *auth.Auth) organization.Hooks {
	return organization.Hooks{
		AfterCreateOrg: func(ctx context.Context, org organization.Org, _ auth.User) error {
			_, err := addProject(ctx, a, org.ID, defaultProject)
			return err
		},
		BeforeDeleteOrg: func(ctx context.Context, org organization.Org) error {
			conn, err := a.Conn(ctx)
			if err != nil {
				return err
			}
			_, err = conn.ExecContext(ctx, deleteProjects, org.ID)
			return err
		},
	}
}

// plugins is the plugin list, shared with the test's harness so both run
// the same wiring with their own mailer.
func plugins(m email.Mailer) []auth.Plugin {
	return []auth.Plugin{
		email.New(email.Login(), email.Recover(), email.WithMailer(m)),
		password.New(),
		organization.New(organization.WithHooksFrom(hooks)),
	}
}

// newAuth wires the library.
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(plugins(m)...),
	)
}

// migrate creates the library's tables, then the app's.
func migrate(ctx context.Context, a *auth.Auth) error {
	if _, err := a.Migrate(ctx); err != nil {
		return err
	}
	_, err := a.DB().ExecContext(ctx, appSchema)
	return err
}

// ImportRequest is one workspace brought over from another system: the
// organization and the projects it already had.
type ImportRequest struct {
	OwnerID  string
	Name     string
	Slug     string
	Projects []string
}

// importWorkspace creates the organization and its projects in one
// transaction. CreateFor joins the Tx (and runs the hook, which adds the
// default project); a project that cannot be written rolls back the
// organization too, so a failed import leaves nothing to clean up.
//
//ds:def id=orgworkspace-import-7n3vx5qe
func importWorkspace(ctx context.Context, a *auth.Auth, orgs *organization.Plugin, in ImportRequest) (organization.Org, error) {
	var org organization.Org
	err := a.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		var err error
		if org, err = orgs.CreateFor(ctx, in.OwnerID, organization.CreateRequest{Name: in.Name, Slug: in.Slug}); err != nil {
			return err
		}
		for _, name := range in.Projects {
			if _, err := addProject(ctx, a, org.ID, name); err != nil {
				return err
			}
		}
		return nil
	})
	return org, err
}

// newHandler mounts the library's routes and the app's project pages, each
// guarded by the caller's role in the organization the path names: members
// read, admins and owners create.
func newHandler(a *auth.Auth) (http.Handler, error) {
	orgs, err := auth.PluginOf[*organization.Plugin](a)
	if err != nil {
		return nil, err
	}
	mw := authhttp.Middleware(a)
	route := "/orgs/{" + pathOrgParam + "}/projects"
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("GET "+route, mw(orgs.RequireRole(orgInPath, organization.RoleMember)(listHandler(a))))
	mux.Handle("POST "+route, mw(orgs.RequireRole(orgInPath, organization.RoleAdmin)(createHandler(a))))
	return mux, nil
}

// orgInPath reads the organization id from the route, for RequireRole.
func orgInPath(r *http.Request) string { return r.PathValue(pathOrgParam) }

// Project is one row of the app's table.
type Project struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// listResponse is what GET /orgs/{org}/projects answers.
type listResponse struct {
	OrgID    string    `json:"orgId"`
	Projects []Project `json:"projects"`
}

// listProjects reads an organization's projects. Reading is open to the app;
// it could join auth_org (organization.OrgID) the same way.
func listProjects(ctx context.Context, a *auth.Auth, orgID string) ([]Project, error) {
	rows, err := a.DB().QueryContext(ctx, selectProjects, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Project{}
	for rows.Next() {
		var p Project
		if err := rows.Scan(&p.ID, &p.Name); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// listHandler answers the organization's projects; RequireRole has already
// refused a non-member with organization.not_member.
func listHandler(a *auth.Auth) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ps, err := listProjects(r.Context(), a, orgInPath(r))
		if err != nil {
			log.Printf("projects: %v", err)
			authhttp.WriteError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, listResponse{OrgID: orgInPath(r), Projects: ps})
	})
}

// createRequest is the create-project form.
type createRequest struct {
	Name string `json:"name"`
}

// createHandler adds a project. It checks the origin itself: the library
// checks it on its own routes, but this is the app's route, and a
// cookie-authenticated POST from another site would otherwise be accepted.
func createHandler(a *auth.Auth) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.TrustsOrigin(authhttp.RequestOf(r).Client.Origin) {
			authhttp.WriteError(w, auth.ErrOriginNotTrusted)
			return
		}
		var in createRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&in); err != nil {
			authhttp.WriteError(w, auth.ErrBadRequest)
			return
		}
		name := strings.TrimSpace(in.Name)
		if name == "" {
			authhttp.WriteError(w, errProjectName)
			return
		}
		p, err := addProject(r.Context(), a, orgInPath(r), name)
		if err != nil {
			var ae *auth.Error
			if !errors.As(err, &ae) {
				log.Printf("create project: %v", err)
			}
			authhttp.WriteError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, p)
	})
}

// writeJSON writes the JSON answer with status. The answer types are the
// app's own (listResponse, Project), so the encoder takes them as they are.
func writeJSON[T listResponse | Project](w http.ResponseWriter, status int, v T) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
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
