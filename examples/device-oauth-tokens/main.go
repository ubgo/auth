// Command device-oauth-tokens signs a command-line tool in with the device
// authorization grant (RFC 8628) of the OAuth provider: the tool shows a
// code, the user approves it in a browser where they are signed in, and the
// tool gets an access token, a refresh token and an ID token from the
// provider's token endpoint instead of a session.
//
//	go run ./device-oauth-tokens                 # serve the app
//	go run ./device-oauth-tokens register-cli    # register the CLI as an OAuth client, print its id, exit
//	go run ./device-oauth-tokens login <id>      # the CLI: sign in against the running app
//
// Mail is printed to the log instead of sent.
package main

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/deviceauth"
	"github.com/ubgo/auth/plugin/deviceauth/oauthdevice"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/oauthprovider"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "device-oauth-tokens.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// codePath is the device authorization endpoint: deviceauth's
	// CodeHandler, which the oauthdevice grant extends for OAuth clients.
	codePath = authPrefix + "/device/code"
	// loginPath is the app's login page, which the provider needs even
	// though the device grant never redirects a browser to it.
	loginPath = "/login"
	// cmdRegisterCLI is the subcommand that registers the CLI client.
	cmdRegisterCLI = "register-cli"
	// cmdLogin is the subcommand that runs the CLI against a running app:
	// login <client_id>.
	cmdLogin = "login"
	// cliName is the CLI client's name, shown on the approval page.
	cliName = "Example CLI"
	// cliScope is what the CLI asks for: an ID token with the profile and
	// email, and a refresh token.
	cliScope = "openid profile email offline_access"
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
	// baseURL is the app's public URL and the provider's issuer.
	baseURL = "http://localhost:" + port
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
	if len(os.Args) > 2 && os.Args[1] == cmdLogin {
		c := cli{CodeURL: baseURL + codePath, TokenURL: baseURL + oauthprovider.DefaultBasePath + "/token", ClientID: os.Args[2], HTTP: http.DefaultClient, Wait: sleep}
		tok, err := c.login(context.Background(), os.Stdout)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("signed in: token_type=%s expires_in=%d scope=%q refresh_token=%t id_token=%t\n", tok.TokenType, tok.ExpiresIn, tok.Scope, tok.RefreshToken != "", tok.IDToken != "")
		return
	}
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// A new key each start: ID tokens stop verifying after a restart. See
	// examples/oauth-provider for a key read from the environment.
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	app, err := newAuth(db, logMailer{}, key)
	if err != nil {
		log.Fatal(err) // a broken plugin combination fails here, not in production
	}
	defer app.a.Close()
	ctx := context.Background()
	if _, err := app.a.Migrate(ctx); err != nil {
		log.Fatal(err)
	}

	if len(os.Args) > 1 && os.Args[1] == cmdRegisterCLI {
		reg, err := registerCLI(ctx, app.op)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("client_id=%s\n", reg.ClientID)
		return
	}

	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(app), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// app is the wired library and the two plugins the handler mounts.
type app struct {
	a  *auth.Auth
	op *oauthprovider.Plugin
	dp *deviceauth.Plugin
}

// newAuth wires the device grant into both plugins. oauthdevice.New takes
// the absolute URL of the device authorization endpoint; deviceauth gets
// the grant with WithGrant, the provider gets its token-endpoint half with
// WithGrant(ExtensionGrant()) and advertises the endpoint in discovery. The
// grant is a plugin too, listed after both.
//
//ds:def id=newauth-deviceoauth-example
func newAuth(db *sql.DB, m email.Mailer, key ed25519.PrivateKey) (app, error) {
	dev := oauthdevice.New(baseURL + codePath)
	dp := deviceauth.New(deviceauth.WithGrant(dev))
	jw := jwt.New(jwt.WithSigningKey(key), jwt.Issuer(baseURL))
	op := oauthprovider.New(jw,
		oauthprovider.Issuer(baseURL),
		oauthprovider.LoginPage(loginPath),
		oauthprovider.WithGrant(dev.ExtensionGrant()),
		oauthprovider.DeviceAuthorizationEndpoint(dev.Endpoint()),
	)
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(m)), password.New(), jw, op, dp, dev),
	)
	return app{a: a, op: op, dp: dp}, err
}

// newHandler mounts the device authorization endpoint on its exact path
// (which wins over the /auth/ prefix), the library's routes, which include
// the approval page's /auth/device/verify and /auth/device/approve, and the
// provider's endpoints, where the CLI redeems its code.
//
//ds:def id=newhandler-deviceoauth-example
func newHandler(app app) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST "+codePath, app.dp.CodeHandler())
	mux.Handle(authPrefix+"/", authhttp.Handler(app.a, authhttp.Prefix(authPrefix)))
	mux.Handle("/.well-known/", app.op.Handler())
	mux.Handle(oauthprovider.DefaultBasePath+"/", app.op.Handler())
	return mux
}

// registerCLI registers the CLI as a public OAuth client: it cannot keep a
// secret, so it authenticates with its id alone. Its grant types name the
// device grant, and refresh_token for refresh tokens.
//
//ds:def id=registercli-deviceoauth-example
func registerCLI(ctx context.Context, op *oauthprovider.Plugin) (oauthprovider.Registration, error) {
	return op.CreateClient(ctx, oauthprovider.ClientSpec{
		ClientMetadata: oauthprovider.ClientMetadata{
			Name:       cliName,
			AuthMethod: oauthprovider.AuthMethodNone,
			GrantTypes: []string{deviceauth.GrantType, oauthprovider.GrantRefreshToken},
			Scope:      cliScope,
		},
	})
}

// cli is the command-line tool's side: where it asks for a code, where it
// redeems one, and its client id.
type cli struct {
	CodeURL  string
	TokenURL string
	ClientID string
	HTTP     *http.Client
	// Wait sleeps between polls; a test replaces it to approve in between.
	Wait func(ctx context.Context, d time.Duration) error
}

// login is the CLI: it asks for a code (deviceauth.Client does that part),
// shows it, and polls the provider's token endpoint until the user approves
// or denies. It polls itself rather than with deviceauth.Client.Poll,
// whose answer type has no refresh or ID token.
//
//ds:def id=cli-login-deviceoauth-example
func (c cli) login(ctx context.Context, out io.Writer) (oauthprovider.TokenResponse, error) {
	dc := &deviceauth.Client{CodeURL: c.CodeURL, TokenURL: c.TokenURL, ClientID: c.ClientID, HTTP: c.HTTP}
	code, err := dc.RequestCode(ctx, cliScope)
	if err != nil {
		return oauthprovider.TokenResponse{}, err
	}
	if _, err := fmt.Fprintf(out, "open %s and enter the code %s\n", code.VerificationURI, code.UserCode); err != nil {
		return oauthprovider.TokenResponse{}, err
	}
	interval := time.Duration(code.Interval) * time.Second
	for {
		if err := c.Wait(ctx, interval); err != nil {
			return oauthprovider.TokenResponse{}, err
		}
		tok, pending, err := c.redeem(ctx, code.DeviceCode)
		switch {
		case err != nil:
			return oauthprovider.TokenResponse{}, err
		case pending == rfcSlowDown:
			interval += slowDownStep
		case pending == "":
			return tok, nil
		}
	}
}

// sleep waits d, or less when ctx ends first.
func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// RFC 8628's answers while the user has not decided yet.
const (
	rfcAuthorizationPending = "authorization_pending"
	rfcSlowDown             = "slow_down"
	// slowDownStep is how much longer a client waits after slow_down,
	// RFC 8628 section 3.5.
	slowDownStep = 5 * time.Second
)

// tokenError is the RFC 6749 error answer of the token endpoint.
type tokenError struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

// redeem posts the device code to the token endpoint once. It returns the
// tokens, or the pending answer (authorization_pending, slow_down) to keep
// polling, or an error that ends the login (access_denied, expired_token).
func (c cli) redeem(ctx context.Context, deviceCode string) (oauthprovider.TokenResponse, string, error) {
	form := url.Values{"grant_type": {deviceauth.GrantType}, "device_code": {deviceCode}, "client_id": {c.ClientID}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return oauthprovider.TokenResponse{}, "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := c.HTTP.Do(req)
	if err != nil {
		return oauthprovider.TokenResponse{}, "", err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusOK {
		var tok oauthprovider.TokenResponse
		return tok, "", json.NewDecoder(res.Body).Decode(&tok)
	}
	var te tokenError
	if err := json.NewDecoder(res.Body).Decode(&te); err != nil {
		return oauthprovider.TokenResponse{}, "", fmt.Errorf("token endpoint: %s", res.Status)
	}
	if te.Error == rfcAuthorizationPending || te.Error == rfcSlowDown {
		return oauthprovider.TokenResponse{}, te.Error, nil
	}
	return oauthprovider.TokenResponse{}, "", errors.New(te.Error + ": " + te.Description)
}

// logMailer prints mail instead of sending it.
type logMailer struct{}

// Send logs the message.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
