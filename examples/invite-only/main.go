// Command invite-only runs an app nobody can join without an invite. The
// owner is created from Go at start-up, which Required never refuses; every
// other account comes from an invite link, and the role the invite carries
// lands in the app's own member table in the same transaction as the sign-up.
//
//	go run ./invite-only
//
// Mail is printed to the log instead of sent; plug an SMTP or API client
// into logMailer's place.
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
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/invite"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "invite-only.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set, so
	// two examples can run side by side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the server listens: this machine only, for development.
	addr = "localhost:" + port
	// baseURL is the app's public URL. Its origin is the only one allowed to
	// send cookie-authenticated POSTs, and invite links point at it.
	baseURL = "http://localhost:" + port
)

// The owner the app creates at start-up, the only account that does not come
// from an invite. A real app reads these from its environment or a CLI flag.
const (
	ownerName     = "Ada"
	ownerEmail    = "ada@example.com"
	ownerPassword = "correct horse battery staple"
)

// Role is a member's role in this app. The invite plugin stores the string
// and hands it back; what a role means is the app's decision.
type Role string

// The roles this app knows.
const (
	// RoleOwner may invite with any role.
	RoleOwner Role = "owner"
	// RoleEditor and RoleMember are roles an owner may give in an invite.
	RoleEditor Role = "editor"
	RoleMember Role = "member"
)

// grantable is the set of roles an invite may carry. The owner role is never
// handed out by a link.
var grantable = map[Role]bool{RoleEditor: true, RoleMember: true}

// memberSchema is the app's own table: one row per member with the role the
// invite gave. It is not an auth table, so the app writes it freely.
const memberSchema = `CREATE TABLE IF NOT EXISTS app_member (
	user_id    TEXT PRIMARY KEY,
	role       TEXT NOT NULL,
	invited_by TEXT NOT NULL DEFAULT ''
)`

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
	ctx := context.Background()
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, memberSchema); err != nil {
		log.Fatal(err)
	}

	app, err := newApp(db, logMailer{})
	if err != nil {
		log.Fatal(err)
	}
	defer app.auth.Close()
	if _, err := app.auth.Migrate(ctx); err != nil {
		log.Fatal(err)
	}
	if err := app.seedOwner(ctx); err != nil && !errors.Is(err, auth.ErrIdentityTaken) {
		log.Fatal(err)
	}

	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: app.handler(), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// app holds the library and the two plugins the app calls from Go.
type app struct {
	db       *sql.DB
	auth     *auth.Auth
	password *password.Plugin
	invites  *invite.Plugin
}

// newApp wires email, passwords and invites. Required makes every client
// sign-up bring a valid invite; CanCreate decides who may hand out which role;
// OnAccepted writes the role in the same transaction as the use, so a failed
// write undoes the sign-up too. The test builds the app with the same
// function.
//
//ds:def id=newapp-aq3mycn4 owner=@khanakia stability=stable
func newApp(db *sql.DB, m email.Mailer) (*app, error) {
	x := &app{db: db, password: password.New()}
	x.invites = invite.New(
		invite.Required(),
		invite.CanCreate(x.canCreate),
		invite.OnAccepted(x.onAccepted),
	)
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(m)), x.password, x.invites),
	)
	x.auth = a
	return x, err
}

// canCreate lets every member create an invite with no role, and only the
// owner one that carries a role. Returning invite.ErrForbidden answers 403
// invite.forbidden.
//
//ds:def id=app-cancreate-9sdhf92a owner=@khanakia stability=stable
func (x *app) canCreate(ctx context.Context, inviter auth.User, in invite.Request) error {
	if in.Role == "" {
		return nil
	}
	if !grantable[Role(in.Role)] {
		return invite.ErrForbidden
	}
	role, err := x.roleOf(ctx, inviter.ID)
	if err != nil {
		return err
	}
	if role != RoleOwner {
		return invite.ErrForbidden
	}
	return nil
}

// onAccepted records the invite's role for the user who used it. It writes
// on auth.Conn(ctx), the transaction that records the use, never on the
// plain *sql.DB: a write there would survive a rollback of the sign-up. An
// existing member who uses a second invite keeps the first role.
//
//ds:def id=app-onaccepted-k24c93ra owner=@khanakia stability=stable
func (x *app) onAccepted(ctx context.Context, acc invite.Accepted) error {
	conn, err := x.auth.Conn(ctx)
	if err != nil {
		return err
	}
	role := cmp.Or(Role(acc.Role), RoleMember)
	_, err = conn.ExecContext(ctx,
		`INSERT INTO app_member (user_id, role, invited_by) VALUES (?, ?, ?) ON CONFLICT (user_id) DO NOTHING`,
		acc.UserID, string(role), acc.CreatedBy)
	return err
}

// roleOf reads a member's role; a user with no row has none.
func (x *app) roleOf(ctx context.Context, userID string) (Role, error) {
	var role string
	err := x.db.QueryRowContext(ctx, `SELECT role FROM app_member WHERE user_id = ?`, userID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return Role(role), err
}

// seedOwner creates the owner from Go: a user, a verified address, a password
// and the owner row, in one transaction. Required refuses only a client's
// sign-up, so this is how an invite-only app gets its first account.
//
//ds:def id=app-seedowner-jwm9s54q owner=@khanakia stability=stable
func (x *app) seedOwner(ctx context.Context) error {
	return x.auth.Tx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		u, err := x.auth.CreateUser(ctx, auth.NewUser{Name: ownerName})
		if err != nil {
			return err
		}
		if _, err := x.auth.CreateIdentity(ctx, auth.NewIdentity{UserID: u.ID, Kind: email.KindEmail, Raw: ownerEmail, Verified: true, Primary: true}); err != nil {
			return err
		}
		if err := x.password.SetPassword(ctx, u.ID, password.Secret(ownerPassword)); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO app_member (user_id, role) VALUES (?, ?)`, u.ID, string(RoleOwner))
		return err
	})
}

// handler mounts the library's routes, the page an invite link opens, and the
// app's /me page, which shows the caller's role.
//
//ds:def id=app-handler-ppk4r4z7 owner=@khanakia stability=stable
func (x *app) handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(x.auth, authhttp.Prefix(authPrefix)))
	mux.HandleFunc("GET "+invite.DefaultPage, invitePage)
	mux.Handle("GET /me", authhttp.Middleware(x.auth)(authhttp.RequireUser(http.HandlerFunc(x.me))))
	return mux
}

// invitePageHTML is the page an invite link opens. It shows the invite, then
// activates it on a click: a signed-in visitor uses it at once, a signed-out
// one keeps it in a cookie that the sign-up form's request then carries.
//
//ds:def id=invitepagehtml-2kr6tty7 owner=@khanakia stability=stable
const invitePageHTML = `<!doctype html>
<meta charset="utf-8">
<title>Invitation</title>
<pre id="out"></pre>
<button id="go">Accept</button>
<script>
const token = new URLSearchParams(location.search).get("token");
const out = document.getElementById("out");
fetch("` + authPrefix + `/invite/get?token=" + encodeURIComponent(token))
  .then(r => r.json()).then(v => { out.textContent = v.error ? v.error.message : (v.inviterName || "Someone") + " invited you."; });
document.getElementById("go").onclick = async () => {
  const res = await fetch("` + authPrefix + `/invite/activate", {
    method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({token}),
  });
  const v = await res.json();
  if (!res.ok) { out.textContent = v.error.message; return; }
  location.href = v.action === "accepted" ? "/me" : "/sign-up";
};
</script>
`

// invitePage serves invitePageHTML.
func invitePage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(invitePageHTML)) // a client that hung up cannot be told
}

// meResponse is what /me answers.
type meResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Role Role   `json:"role"`
}

// me answers the caller's id, name and role in this app.
func (x *app) me(w http.ResponseWriter, r *http.Request) {
	u := authhttp.MustUser(r)
	role, err := x.roleOf(r.Context(), u.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meResponse{ID: u.ID, Name: u.Name, Role: role}) // a client that hung up cannot be told
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including the invite link, so you can open it by
// hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
