// Command org-teams runs organizations the way a team product uses them:
// teams inside each organization, the session's active organization and
// team, roles an organization defines for itself at run time, typed
// lifecycle hooks, and invitations sent by email or by text message.
//
//	go run ./org-teams
//
// Mail and text messages are printed to the log instead of sent.
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
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/phone"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "org-teams.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
)

// The limits this product sets. Each is a business decision, so it is named
// here rather than buried in the option call.
const (
	// maxTeams is how many teams one organization may have.
	maxTeams = 10
	// maxMembersPerTeam is how many members one team may have.
	maxMembersPerTeam = 50
	// maxCustomRoles is how many roles one organization may define itself.
	maxCustomRoles = 5
)

// reservedTeamName is a team name the app keeps for itself: its UI shows a
// virtual "everyone" team, so a real team of that name would be ambiguous.
const reservedTeamName = "everyone"

// ErrReservedTeamName is the app's own error, returned by a Before hook. The
// library answers it with this code and status like any of its own errors.
var ErrReservedTeamName = auth.NewError("app.team_name_reserved", http.StatusBadRequest, "That team name is reserved.")

var (
	// port is the port the app listens on: 8081, or $PORT when it is set, so
	// two examples can run side by side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the server listens: this machine only, for development.
	addr = "localhost:" + port
	// baseURL is the app's public URL. Its origin is the only one allowed to
	// send cookie-authenticated POSTs, and invitation links point at it.
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

func main() {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, err := newAuth(db, logMailer{}, logSMS{}, logJoins)
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
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

// newAuth wires email and phone numbers as identifiers, passwords, and the
// organization plugin with teams, run-time roles, hooks, and invitations
// addressed to an email or a phone number. joined is told about every new
// member, after the membership is written and inside its transaction.
//
//ds:def id=orgteams-newauth-4w7nq2xk
func newAuth(db *sql.DB, m email.Mailer, sms phone.SMSSender, joined func(organization.MemberChange)) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			phone.New(phone.WithSMS(sms)),
			password.New(),
			organization.New(
				organization.Teams(organization.TeamsConfig{MaxTeams: maxTeams, MaxMembersPerTeam: maxMembersPerTeam}),
				organization.DynamicRoles(organization.DynamicRolesConfig{MaxRoles: maxCustomRoles}),
				organization.InviteBy(email.KindEmail, phone.KindPhone),
				organization.WithHooks(hooks(joined)),
			),
		),
	)
}

// hooks are the app's organization lifecycle hooks. BeforeCreateTeam refuses
// the reserved name with the app's own error; AfterAddMember reports a new
// member. Both run inside the operation's transaction, so a refusal or an
// error from either undoes the whole operation.
//
//ds:def id=orgteams-hooks-8m2kx5vd
func hooks(joined func(organization.MemberChange)) organization.Hooks {
	return organization.Hooks{
		BeforeCreateTeam: func(_ context.Context, team *organization.Team) error {
			if strings.EqualFold(strings.TrimSpace(team.Name), reservedTeamName) {
				return ErrReservedTeamName
			}
			return nil
		},
		AfterAddMember: func(_ context.Context, m organization.MemberChange) error {
			joined(m)
			return nil
		},
	}
}

// newHandler mounts the library's routes and /workspace, an app page that
// scopes itself to the session's active organization and team.
func newHandler(a *auth.Auth) (http.Handler, error) {
	orgs, err := auth.PluginOf[*organization.Plugin](a)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("GET /workspace", authhttp.Middleware(a)(authhttp.RequireUser(workspace(orgs))))
	return mux, nil
}

// workspaceResponse is what /workspace answers.
type workspaceResponse struct {
	OrgID  string `json:"orgId"`
	TeamID string `json:"teamId,omitempty"`
}

// errNoWorkspace is /workspace's answer when the session selected none.
var errNoWorkspace = auth.NewError("app.no_workspace", http.StatusConflict, "Choose a workspace first.")

// workspace answers the active organization and team of the caller's
// session: the ids an app route would scope its own queries to. A route that
// needs only the organization can call orgs.ActiveOrgID instead.
//
//ds:def id=orgteams-workspace-6t3hs8qe
func workspace(orgs *organization.Plugin) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		active, err := orgs.Active(r.Context())
		if err != nil {
			authhttp.WriteError(w, err)
			return
		}
		if active.OrgID == nil {
			authhttp.WriteError(w, errNoWorkspace)
			return
		}
		out := workspaceResponse{OrgID: *active.OrgID}
		if active.TeamID != nil {
			out.TeamID = *active.TeamID
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out) // a client that hung up cannot be told
	}
}

// logJoins prints every new member; a real app would write its own audit
// row or start onboarding.
func logJoins(m organization.MemberChange) {
	log.Printf("member joined org=%s user=%s role=%s", m.OrgID, m.UserID, m.Role)
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}

// logSMS prints text messages instead of sending them. Replace it with an
// SMS provider.
type logSMS struct{}

// Send logs the text.
func (logSMS) Send(_ context.Context, to, text string) error {
	log.Printf("sms to=%s\n%s", to, text)
	return nil
}
