// Command sso-domains connects a customer's SAML identity provider to their
// organization the way a B2B product does: the customer's owner registers
// the provider for the organization, proves they own the email domain with a
// DNS TXT record before anyone can sign in through it, the company's people
// join the organization on their first sign-in, and signing out ends the
// session at the IdP too (SAML single logout), in both directions.
//
//	AUTH_SECRET=$(openssl rand -base64 32) go run ./sso-domains
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
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/sso"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "sso-domains.db"
	// authPrefix is where the library's routes are mounted. The sso plugin's
	// default callback, ACS and SLO URLs assume sso.DefaultMountPrefix.
	authPrefix = sso.DefaultMountPrefix
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
	// baseURL is the app's public URL. The SAML ACS and SLO URLs every
	// provider is given are built from it.
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

	// A nil resolver is net.DefaultResolver: the real DNS.
	a, err := newAuth(db, []byte(os.Getenv(auth.EnvSecret)), logMailer{}, nil)
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

// newAuth wires email, passwords for the people who set SSO up, the
// organization plugin, and SSO with three things on: domain verification
// through resolver (nil is the real DNS; the test passes a fake one),
// organizations through orgAdapter, and SAML single logout.
//
//ds:def id=ssodomains-newauth-6p3kw8zn
func newAuth(db *sql.DB, secret []byte, m email.Mailer, resolver sso.TXTResolver) (*auth.Auth, error) {
	orgs := organization.New()
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithSecret(secret),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			orgs,
			sso.New(
				sso.WithDomainVerification(sso.DomainVerification{Resolver: resolver}),
				sso.WithOrganizations(orgAdapter{orgs: orgs, db: db}, sso.OrganizationProvisioning{}),
				sso.WithSAMLOptions(sso.SAMLOptions{EnableSingleLogout: true}),
			),
		),
	)
}

// orgAdapter answers the sso plugin's questions about organizations from
// plugin/organization. The sso plugin names no organization module, so an
// app on its own workspace model writes these three methods over that.
type orgAdapter struct {
	orgs *organization.Plugin
	db   *sql.DB
}

// Role returns userID's role in orgID; ok is false for a non-member. The
// sso plugin asks it before registering a provider for an organization:
// only its owner or admin may.
//
//ds:def id=ssodomains-role-5j8rv3kc
func (o orgAdapter) Role(ctx context.Context, orgID, userID string) (string, bool, error) {
	role, err := o.orgs.RoleOf(ctx, orgID, userID)
	if errors.Is(err, organization.ErrNotMember) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return string(role), true, nil
}

// BySlug finds an organization by its slug, for a sign-in that names
// organizationSlug. It reads the plugin's table with its typed columns:
// reads are open to the app.
//
//ds:def id=ssodomains-byslug-8k2nw5qr
func (o orgAdapter) BySlug(ctx context.Context, slug string) (string, bool, error) {
	var id string
	q, err := sqlb.NewSelect(sqlb.SQLiteDialect{}).
		Columns(sqlb.Bind(organization.OrgID, &id)).
		From(organization.TableOrg).
		Where(sqlb.Eq(organization.OrgSlug, slug)).
		Build()
	if err != nil {
		return "", false, err
	}
	switch err := sqlb.One(ctx, o.db, q); {
	case errors.Is(err, sqlb.ErrNoRows):
		return "", false, nil
	case err != nil:
		return "", false, err
	}
	return id, true, nil
}

// AddMember joins a person who signed in through the organization's
// provider. organization.AddMember joins the sign-in's transaction, keeps an
// existing member's role, and runs the member hooks.
//
//ds:def id=ssodomains-addmember-2w6qt9ny
func (o orgAdapter) AddMember(ctx context.Context, orgID, userID, role string) error {
	return o.orgs.AddMember(ctx, orgID, userID, organization.Role(role))
}

// The adapter must stay an sso.Organizations.
var _ sso.Organizations = orgAdapter{}

// newHandler mounts the library's routes and /me, which only a signed-in
// user may see.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux
}

// meResponse is what /me answers.
type meResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// me is an app handler: RequireUser has already refused anyone signed out.
func me(w http.ResponseWriter, r *http.Request) {
	u := authhttp.MustUser(r)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meResponse{ID: u.ID, Name: u.Name}) // a client that hung up cannot be told
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
