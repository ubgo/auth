// Command admin-plan is an admin page of users with their plan and project
// count, newest first, in one query that joins the app's own tables to the
// library's, with typed columns on both sides. Banning, unbanning and making
// admins are the admin plugin's routes.
//
//	go run ./admin-plan                         serve on localhost:8081
//	go run ./admin-plan grant alice@example.com make the first admin
//
// Mail is printed to the log instead of sent.
package main

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "admin-plan.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
	// maxBodyBytes caps the app's JSON bodies, which hold one short string.
	maxBodyBytes = 1 << 12
	// grantCommand is the subcommand that makes the first admin. Admins grant
	// each other over HTTP afterwards; the first one has to come from code.
	grantCommand = "grant"
	// projectIDPrefix makes a project id recognisable, as "usr_" does users.
	projectIDPrefix = "prj"
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

// Paging of the admin list: a page an admin screen can show, and a cap so one
// request cannot read the whole table.
const (
	defaultPageSize = 50
	maxPageSize     = 200
)

// Query parameters of GET /admin/users.
const (
	paramPage  = "page"
	paramLimit = "limit"
)

// sqlitePragmas are the settings every SQLite connection needs: WAL so readers
// do not block the writer, a busy timeout instead of an immediate "database is
// locked", and foreign keys, which SQLite leaves off and the cascades below
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

// Plan is the app's billing plan, a closed set.
type Plan string

// The plans a user can be on.
const (
	PlanFree Plan = "free"
	PlanPro  Plan = "pro"
)

// planValues is the canonical list, for validation.
var planValues = []Plan{PlanFree, PlanPro}

// appSchema is the app's own tables. Both hold a user id and no foreign key:
// the library creates none either (tables are plain storage), and the rows a
// deleted user leaves are removed by the app's BeforeDelete hook below, inside
// the deleting transaction.
var appSchema = []string{
	`CREATE TABLE IF NOT EXISTS app_plan (
		user_id TEXT NOT NULL PRIMARY KEY,
		plan    TEXT NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS app_project (
		id       TEXT NOT NULL PRIMARY KEY,
		owner_id TEXT NOT NULL
	)`,
}

// deleteAppRows is the app's User.BeforeDelete hook: it removes the user's
// plan and projects through tx, the deleting transaction, so a failure rolls
// the user back with them.
func deleteAppRows(ctx context.Context, tx sqlb.DBTX, u *auth.User) error {
	for _, q := range []string{`DELETE FROM app_plan WHERE user_id = ?`, `DELETE FROM app_project WHERE owner_id = ?`} {
		if _, err := tx.ExecContext(ctx, q, u.ID); err != nil {
			return err
		}
	}
	return nil
}

// The app's tables as typed sqlb columns. The aliases must not be one of
// auth.ReservedAliases.
var (
	TablePlan    = sqlb.Table{Name: "app_plan", Alias: "pl"}
	PlanUserID   = sqlb.Col[string](TablePlan, "user_id")
	PlanName     = sqlb.Col[Plan](TablePlan, "plan")
	TableProject = sqlb.Table{Name: "app_project", Alias: "pj"}
	ProjectID    = sqlb.Col[string](TableProject, "id")
	ProjectOwner = sqlb.Col[string](TableProject, "owner_id")
)

// Statements the app writes to its own tables.
const (
	upsertPlan    = `INSERT INTO app_plan (user_id, plan) VALUES (?, ?) ON CONFLICT (user_id) DO UPDATE SET plan = excluded.plan`
	insertProject = `INSERT INTO app_project (id, owner_id) VALUES (?, ?)`
)

// errBadPlan answers a plan outside planValues.
var errBadPlan = auth.NewError("plan.unknown", http.StatusBadRequest, "There is no such plan.")

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
	if err := migrate(ctx, a); err != nil {
		log.Fatal(err)
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

// newAuth wires the library with the admin plugin, and returns the plugin for
// the grant command. The test builds the app with this same function.
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, *admin.Plugin, error) {
	ad := admin.New()
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(m)), password.New(), ad),
		auth.WithDataHooks(auth.DataHooks{User: auth.TableHooks[auth.User]{BeforeDelete: deleteAppRows}}),
	)
	return a, ad, err
}

// migrate creates the library's tables, then the app's.
func migrate(ctx context.Context, a *auth.Auth) error {
	if _, err := a.Migrate(ctx); err != nil {
		return err
	}
	for _, st := range appSchema {
		if _, err := a.DB().ExecContext(ctx, st); err != nil {
			return err
		}
	}
	return nil
}

// grantByEmail makes the owner of a verified address an admin. Only a
// verified address counts: admin rights for whoever typed an address first
// would be a takeover.
func grantByEmail(ctx context.Context, a *auth.Auth, ad *admin.Plugin, address string) (string, error) {
	idn, err := a.FindIdentity(ctx, email.KindEmail, address, true)
	if err != nil {
		return "", fmt.Errorf("find a verified %s: %w", address, err)
	}
	return idn.UserID, ad.Grant(ctx, idn.UserID)
}

// newHandler mounts the library's routes (the admin plugin's among them), the
// app's own plan and project routes, and the app's admin list.
func newHandler(a *auth.Auth) http.Handler {
	signedIn := func(h http.Handler) http.Handler { return authhttp.Middleware(a)(authhttp.RequireUser(h)) }
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("POST /plan", signedIn(planHandler(a)))
	mux.Handle("POST /projects", signedIn(projectHandler(a)))
	mux.Handle("GET /admin/users", signedIn(authhttp.RequireFunc(requireAdmin(a))(adminUsersHandler(a))))
	return mux
}

// requireAdmin is the app's authorization rule as a check: the admin plugin's
// column, read like any other column of the user.
func requireAdmin(a *auth.Auth) func(r *http.Request) error {
	return func(r *http.Request) error {
		var cols admin.AdminColumns
		if err := a.LoadUserColumns(r.Context(), authhttp.MustUser(r).ID, admin.Bindings(&cols)...); err != nil {
			return err
		}
		if cols.AdminGrantedAt == nil {
			return admin.ErrForbidden
		}
		return nil
	}
}

// planRequest is the body of POST /plan.
type planRequest struct {
	Plan Plan `json:"plan"`
}

// planHandler sets the signed-in user's plan, in the app's own table. In a
// real app a billing webhook does this.
func planHandler(a *auth.Auth) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in planRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&in); err != nil {
			authhttp.WriteError(w, auth.ErrBadRequest)
			return
		}
		if !validPlan(in.Plan) {
			authhttp.WriteError(w, errBadPlan)
			return
		}
		if _, err := a.DB().ExecContext(r.Context(), upsertPlan, authhttp.MustUser(r).ID, in.Plan); err != nil {
			authhttp.WriteError(w, err)
			return
		}
		writeJSON(w, in)
	})
}

// validPlan reports whether p is one of planValues.
func validPlan(p Plan) bool {
	for _, v := range planValues {
		if p == v {
			return true
		}
	}
	return false
}

// projectResponse is what POST /projects answers.
type projectResponse struct {
	ID string `json:"id"`
}

// projectHandler creates a project owned by the signed-in user.
func projectHandler(a *auth.Auth) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := a.NewID(projectIDPrefix)
		if err != nil {
			authhttp.WriteError(w, err)
			return
		}
		if _, err := a.DB().ExecContext(r.Context(), insertProject, id, authhttp.MustUser(r).ID); err != nil {
			authhttp.WriteError(w, err)
			return
		}
		writeJSON(w, projectResponse{ID: id})
	})
}

// UserRow is one row of the admin list: library columns and app columns side
// by side. Plan is nil for a user with no row in app_plan.
type UserRow struct {
	ID        string    `json:"id"`
	Email     *string   `json:"email"`
	CreatedAt time.Time `json:"createdAt"`
	Banned    bool      `json:"banned"`
	Plan      *Plan     `json:"plan"`
	Projects  int64     `json:"projects"`
}

// UsersPage is one page of the admin list.
type UsersPage struct {
	Users []UserRow `json:"users"`
	Page  int       `json:"page"`
	Limit int       `json:"limit"`
}

// userScan is where one result row lands: the row itself, and the ban
// timestamp that becomes UserRow.Banned.
type userScan struct {
	row      UserRow
	bannedAt *time.Time
}

// usersQuery is the one query: auth_user joined to the app's plan and project
// tables, newest first. Every column is typed, so comparing created_at with a
// string, or scanning the plan into an int, does not compile.
func usersQuery(a *auth.Auth, dst *userScan, page, limit int) (sqlb.Query, error) {
	plan := sqlb.Nullable(PlanName) // null for a user without a plan row
	return a.Select().
		Columns(
			sqlb.Bind(auth.UserID, &dst.row.ID),
			sqlb.Bind(email.PrimaryEmail, &dst.row.Email),
			sqlb.Bind(auth.UserCreatedAt, &dst.row.CreatedAt),
			sqlb.Bind(admin.BannedAt, &dst.bannedAt),
			sqlb.Bind(plan, &dst.row.Plan),
			sqlb.Bind(sqlb.CountOf(ProjectID), &dst.row.Projects),
		).
		From(auth.TableUser).
		Join(
			sqlb.Join{Type: sqlb.JoinLeft, Table: TablePlan, On: []sqlb.Predicate{sqlb.EqExpr(PlanUserID, auth.UserID)}},
			sqlb.Join{Type: sqlb.JoinLeft, Table: TableProject, On: []sqlb.Predicate{sqlb.EqExpr(ProjectOwner, auth.UserID)}},
		).
		GroupBy(auth.UserID, email.PrimaryEmail, auth.UserCreatedAt, admin.BannedAt, plan).
		Order(sqlb.OrderBy(auth.UserCreatedAt, sqlb.SortDesc), sqlb.OrderBy(auth.UserID, sqlb.SortAsc)).
		Limit(limit).
		Offset((page - 1) * limit).
		Build()
}

// listUsers runs usersQuery and collects one page.
func listUsers(ctx context.Context, a *auth.Auth, page, limit int) (UsersPage, error) {
	var dst userScan
	q, err := usersQuery(a, &dst, page, limit)
	if err != nil {
		return UsersPage{}, err
	}
	out := UsersPage{Users: []UserRow{}, Page: page, Limit: limit}
	err = sqlb.Each(ctx, a.DB(), q, func() error {
		r := dst.row // the targets are reused for every row
		r.Banned = dst.bannedAt != nil
		out.Users = append(out.Users, r)
		return nil
	})
	return out, err
}

// adminUsersHandler serves one page of listUsers, with ?page= and ?limit=.
func adminUsersHandler(a *auth.Auth) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page, limit, err := paging(r)
		if err != nil {
			authhttp.WriteError(w, err)
			return
		}
		out, err := listUsers(r.Context(), a, page, limit)
		if err != nil {
			authhttp.WriteError(w, err)
			return
		}
		writeJSON(w, out)
	})
}

// paging reads ?page= (from 1) and ?limit= (clamped to maxPageSize).
func paging(r *http.Request) (page, limit int, err error) {
	page, limit = 1, defaultPageSize
	if v := r.URL.Query().Get(paramPage); v != "" {
		if page, err = strconv.Atoi(v); err != nil || page < 1 {
			return 0, 0, errors.Join(auth.ErrBadRequest, err)
		}
	}
	if v := r.URL.Query().Get(paramLimit); v != "" {
		if limit, err = strconv.Atoi(v); err != nil || limit < 1 {
			return 0, 0, errors.Join(auth.ErrBadRequest, err)
		}
	}
	return page, min(limit, maxPageSize), nil
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
