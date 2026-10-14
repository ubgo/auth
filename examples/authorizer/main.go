// Command authorizer decides permissions with models of the app's choosing
// instead of the plugins' built-in roles. The organization plugin asks a
// policy of the app's own: a table of (role, resource, action) lines plus an
// attribute rule, the shape a Casbin model or an OPA policy has, written as a
// small Go function so the example needs no policy engine. The admin plugin
// asks the accessadmin adapter, which adds a "support" role that may look
// users up but not ban them. The apikey plugin checks key permissions against
// the app's own vocabulary through the accessapikey adapter, and an app route
// accepts only a key allowed to deploy.
//
//	go run ./authorizer
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
	"slices"
	"sync"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/access"
	"github.com/ubgo/auth/plugin/access/accessadmin"
	"github.com/ubgo/auth/plugin/access/accessapikey"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/apikey"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "authorizer.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
	// deployKeyHeader carries the API key a deploy script presents to
	// /deploy. It is not Authorization, so the key does not sign the script
	// in as its owner: the route asks only what the key itself allows.
	deployKeyHeader = "Deploy-Key"
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

// sqlitePragmas are the settings every SQLite connection needs: WAL so readers
// do not block the writer, and a busy timeout instead of an immediate
// "database is locked".
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// sqliteDSN builds the SQLite URI for a database file, escaping only the path
// so a "#" or "?" in it cannot start the URI's fragment or query.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

// The vocabulary of the app's API keys: what a key may be allowed to do.
const (
	resourceProject = "project"
	actionRead      = "read"
	actionDeploy    = "deploy"
)

// keyAccess declares every permission an API key may carry. A key minted
// with anything else is refused with apikey.ErrBadPermissions.
//
//ds:def id=authz-keyaccess-5n8wq2tc
var keyAccess = access.MustNew(access.Statements{resourceProject: {actionRead, actionDeploy}})

// roleSupport is the admin role the app adds for its support desk.
const roleSupport = "support"

// adminAuthorizer is the admin plugin's model: better-auth's admin roles from
// the access module, plus support, which may list and read users and their
// sessions and nothing else.
//
//ds:def id=authz-adminauthorizer-2k7xv9pm
func adminAuthorizer() *accessadmin.Authorizer {
	ac := accessadmin.DefaultAccessControl
	support := ac.MustRole(access.Permissions{
		admin.ResourceUser:    {admin.ActionList, admin.ActionGet},
		admin.ResourceSession: {admin.ActionList},
	})
	return accessadmin.MustNew(ac, map[string]access.Role{roleSupport: support})
}

// wildcard in a policy line matches any resource or action.
const wildcard = "*"

// policyLine is one line of the organization policy: members holding Role may
// do Action on Resource. It is a Casbin "p, sub, obj, act" line.
type policyLine struct {
	Role     organization.Role
	Resource string
	Action   string
}

// orgPolicy is the app's organization policy. Unlike the built-in roles, a
// plain member may invite people.
//
//ds:def id=authz-orgpolicy-9h4mt6rw
var orgPolicy = []policyLine{
	{organization.RoleOwner, wildcard, wildcard},
	{organization.RoleAdmin, organization.ResourceMember, wildcard},
	{organization.RoleAdmin, organization.ResourceInvitation, wildcard},
	{organization.RoleAdmin, organization.ResourceOrganization, organization.ActionUpdate},
	{organization.RoleMember, organization.ResourceInvitation, organization.ActionCreate},
	{organization.RoleMember, organization.ResourceAC, organization.ActionRead},
}

// frozenOrgs is the attribute the policy reads besides the role: an
// organization frozen for non-payment may still be read, but nobody in it may
// change anything until it is unfrozen.
type frozenOrgs struct {
	mu  sync.Mutex
	ids map[string]bool
}

// Freeze marks orgID frozen.
func (f *frozenOrgs) Freeze(orgID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ids == nil {
		f.ids = map[string]bool{}
	}
	f.ids[orgID] = true
}

// frozen reports whether orgID is frozen.
func (f *frozenOrgs) frozen(orgID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ids[orgID]
}

// orgAuthorizer decides every organization permission: refused in a frozen
// organization, otherwise allowed when a policy line of one of the member's
// roles covers each action asked for. Per resource the request says whether
// every action (access.All) or one (access.Any) is needed; across resources
// req.Connector says whether every resource or one is. With Casbin, allows
// would call enforcer.Enforce(role, resource, action) instead.
//
//ds:def id=authz-orgauthorizer-7c3ny5kd
func orgAuthorizer(policy []policyLine, frozen *frozenOrgs) organization.AuthorizerFunc {
	allows := func(roles []organization.Role, resource, action string) bool {
		return slices.ContainsFunc(policy, func(l policyLine) bool {
			return slices.Contains(roles, l.Role) &&
				(l.Resource == wildcard || l.Resource == resource) &&
				(l.Action == wildcard || l.Action == action)
		})
	}
	return func(_ context.Context, req organization.AccessRequest) (bool, error) {
		if len(req.Request) == 0 || frozen.frozen(req.OrgID) {
			return false, nil
		}
		roles := req.Role.Parts()
		anyResource := false
		for resource, want := range req.Request {
			ok := len(want.Actions) > 0
			for _, action := range want.Actions {
				has := allows(roles, resource, action)
				if want.Connector == access.Or && has {
					ok = true
					break
				}
				ok = ok && has
			}
			if !ok && req.Connector != access.Or {
				return false, nil
			}
			anyResource = anyResource || ok
		}
		return anyResource, nil
	}
}

func main() {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, err := newAuth(db, logMailer{}, &frozenOrgs{})
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

// newAuth wires each plugin to the model that decides its permissions: the
// accessadmin roles for admin, the app's policy for organizations, and the
// app's key vocabulary for API keys.
//
//ds:def id=authz-newauth-3r6kp8ve
func newAuth(db *sql.DB, m email.Mailer, frozen *frozenOrgs) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			admin.New(admin.WithAuthorizer(adminAuthorizer())),
			organization.New(organization.WithAuthorizer(orgAuthorizer(orgPolicy, frozen))),
			apikey.New(apikey.WithPermissions(accessapikey.New(keyAccess))),
		),
	)
}

// newHandler mounts the library's routes and /deploy, which a deploy script
// calls with an API key.
func newHandler(a *auth.Auth) (http.Handler, error) {
	keys, err := auth.PluginOf[*apikey.Plugin](a)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("POST /deploy", deploy(keys))
	return mux, nil
}

// deployResponse is what /deploy answers.
type deployResponse struct {
	Deployed bool   `json:"deployed"`
	By       string `json:"by"`
}

// deploy accepts a request only with a key whose permissions grant
// project:deploy. VerifyPermissions counts the use against the key's rate
// limit and quota, and answers a bad key and a key without the permission as
// a Verification with Valid false; its error is only a failure to check.
//
//ds:def id=authz-deploy-8f2qz4lu
func deploy(keys *apikey.Plugin) http.HandlerFunc {
	want := apikey.Permissions{resourceProject: {actionDeploy}}
	return func(w http.ResponseWriter, r *http.Request) {
		v, err := keys.VerifyPermissions(r.Context(), r.Header.Get(deployKeyHeader), want)
		if err != nil {
			authhttp.WriteError(w, err)
			return
		}
		if !v.Valid {
			authhttp.WriteError(w, v.Reason)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(deployResponse{Deployed: true, By: v.UserID}) // a client that hung up cannot be told
	}
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
