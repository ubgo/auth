// Command jwt-templates hands a signed-in client tokens shaped for other
// services, picked by name: Clerk's getToken({ template }).
//
//	go run ./jwt-templates
//
// POST /auth/jwt/template {"template":"supabase"} answers a token Supabase
// accepts (HS256 with the project's JWT secret), "hasura" one for Hasura's
// jwk_url (EdDSA, the plugin's key), "convex" one for Convex's customJwt
// provider (ES256, a second published key), and "org" one carrying the
// session's active organization, its slug, the caller's role and the
// permissions it grants, and "profile" one carrying the user's public
// metadata (plugin/metadata). The templates live on the server: the client sends
// a name and can never shape a claim. Mail is printed to the log.
package main

import (
	"cmp"
	"context"
	"crypto"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/jwt/jwtpreset"
	"github.com/ubgo/auth/plugin/metadata"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/organization/orgjwt"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "jwt-templates.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers.
	readHeaderTimeout = 5 * time.Second
	// envSupabaseSecret holds the Supabase project's JWT secret (Project
	// Settings > API), at least jwt.MinHMACSecret bytes.
	envSupabaseSecret = "SUPABASE_JWT_SECRET"
	// convexApplicationID is the applicationID of the Convex customJwt
	// provider, written as aud.
	convexApplicationID = "convex-app"
	// hasuraAudience is the audience Hasura's JWT config checks.
	hasuraAudience = "hasura"
	// orgAudience is the audience of the organization template's receiver.
	orgAudience = "org-api"
	// profileAudience is the audience of the profile template's receiver.
	profileAudience = "profile-api"
	// publicMetadataClaim carries the user's public metadata document.
	publicMetadataClaim = "public_metadata"
)

// Template names a client asks for.
const (
	TemplateSupabase = "supabase"
	TemplateHasura   = "hasura"
	TemplateConvex   = "convex"
	TemplateOrg      = "org"
	TemplateProfile  = "profile"
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr listens on this machine only, for development.
	addr = "localhost:" + port
	// baseURL is the app's public URL; its origin is also the tokens' iss.
	baseURL = "http://" + addr
)

// sqlitePragmas are the settings every SQLite connection needs: WAL, a busy
// timeout and foreign keys, which the library's cascades depend on.
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"

// sqliteDSN builds the SQLite URI for a database file, escaping the path so a
// "#" or "?" in it cannot start the URI's fragment or query.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

// keys are the secrets the templates sign with. In production each comes
// from the secret store; this example makes the asymmetric ones per run.
type keys struct {
	main     crypto.Signer // EdDSA: the session token and the hasura template
	es256    crypto.Signer // ES256: the convex template, published beside main
	supabase []byte        // HS256 secret shared with Supabase, never published
}

func main() {
	k, err := newKeys(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	org, meta := organization.New(), metadata.New()
	jw, err := newJWT(k, org, meta)
	if err != nil {
		log.Fatal(err)
	}
	a, err := newAuth(db, org, meta, jw)
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

// newKeys makes the signing keys and reads the Supabase secret, or makes
// one for the run and says so.
func newKeys(getenv func(string) string) (keys, error) {
	main, err := jwt.GenerateKey(jwt.EdDSA)
	if err != nil {
		return keys{}, err
	}
	es, err := jwt.GenerateKey(jwt.ES256)
	if err != nil {
		return keys{}, err
	}
	secret := []byte(getenv(envSupabaseSecret))
	if len(secret) == 0 {
		raw := make([]byte, jwt.MinHMACSecret)
		_, _ = rand.Read(raw) // never fails since Go 1.24; a failing source crashes instead
		secret = []byte(base64.RawURLEncoding.EncodeToString(raw))
		log.Printf("%s is not set: using a random secret for this run", envSupabaseSecret)
	}
	if len(secret) < jwt.MinHMACSecret {
		return keys{}, fmt.Errorf("%s must be at least %d bytes", envSupabaseSecret, jwt.MinHMACSecret)
	}
	return keys{main: main, es256: es, supabase: secret}, nil
}

// newJWT registers the templates. Each preset is an example convention
// from jwtpreset; the org and profile templates are the app's own.
//
//ds:def id=jwttemplates-newjwt-r5mk8wqz
func newJWT(k keys, org *organization.Plugin, meta *metadata.Plugin) (*jwt.Plugin, error) {
	supabase, err := jwtpreset.Supabase(jwtpreset.SupabaseConfig{Key: jwt.HMACKey(k.supabase)})
	if err != nil {
		return nil, err
	}
	convex, err := jwtpreset.Convex(jwtpreset.ConvexConfig{ApplicationID: convexApplicationID, Alg: jwt.ES256})
	if err != nil {
		return nil, err
	}
	orgClaims, err := orgjwt.Claims(org)
	if err != nil {
		return nil, err
	}
	return jwt.New(
		jwt.WithSigningKey(k.main),
		jwt.AlgorithmKeys(k.es256),
		jwt.WithTemplate(TemplateSupabase, supabase),
		jwt.WithTemplate(TemplateHasura, jwtpreset.Hasura(jwtpreset.HasuraConfig{Audience: []string{hasuraAudience}})),
		jwt.WithTemplate(TemplateConvex, convex),
		jwt.WithTemplate(TemplateOrg, jwt.Template{Audience: []string{orgAudience}, Claims: orgClaims}),
		jwt.WithTemplate(TemplateProfile, jwt.Template{Audience: []string{profileAudience}, Claims: jwt.UserClaim(publicMetadataClaim, meta.PublicOf)}),
	), nil
}

// newAuth wires passwords, organizations, metadata and the token plugin.
func newAuth(db *sql.DB, org *organization.Plugin, meta *metadata.Plugin, jw *jwt.Plugin) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(email.MailerFunc(logMail))),
			password.New(),
			org,
			meta,
			jw,
		),
	)
}

// newHandler mounts the library's routes.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	return mux
}

// logMail prints mail instead of sending it.
func logMail(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, strings.TrimSpace(m.Text))
	return nil
}
