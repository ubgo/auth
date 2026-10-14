// Command device-login is a CLI signing in with the device authorization
// grant (RFC 8628), better-auth's `npx auth login` demo in Go: the CLI asks
// the web app for a code, prints the code and the page to open, and polls
// while the person signs in on any browser and approves; the approval ends
// with a session of that person on the CLI, used as a bearer token.
//
//	go run ./device-login          # the web app, on localhost:8081
//	go run ./device-login -login   # the CLI: prints the code, polls, prints who it is signed in as
//
// Mail is printed to the log instead of sent.
package main

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/deviceauth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// clientID is the one client this web app accepts at /device/code; a
	// real app checks the id against its own list (deviceauth.ValidateClient).
	clientID = "example-cli"
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "device-login.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// codePath and tokenPath are the two RFC 8628 endpoints the CLI calls,
	// served by the plugin's RFC handlers so a stock client (this one,
	// golang.org/x/oauth2, any other) reads the errors it expects.
	codePath  = authPrefix + "/device/code"
	tokenPath = authPrefix + "/device/token"
	// readHeaderTimeout bounds how long a client may take to send headers.
	readHeaderTimeout = 5 * time.Second
	// loginWait is how long the CLI polls before giving up; the code itself
	// expires sooner (deviceauth.DefaultExpiresIn), which ends the poll with
	// expired_token first.
	loginWait = 35 * time.Minute
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set, so
	// two examples can run side by side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the web app listens: this machine only, for development.
	addr = "localhost:" + port
	// baseURL is the web app's public URL. Its origin is the only one allowed
	// to send cookie-authenticated POSTs, the approval included.
	baseURL = "http://localhost:" + port
)

// sqlitePragmas are the settings every SQLite connection needs: WAL and a
// busy timeout.
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// sqliteDSN builds the SQLite URI for a database file. It escapes the path
// instead of concatenating "file:"+path, because a "#" or "?" in a path would
// otherwise start the URI's fragment or query and open a different file.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

func main() {
	asCLI := flag.Bool("login", false, "run the CLI login instead of the web app")
	flag.Parse()
	if *asCLI {
		ctx, cancel := context.WithTimeout(context.Background(), loginWait)
		defer cancel()
		if err := login(ctx, os.Stdout, newClient(http.DefaultClient, baseURL)); err != nil {
			log.Fatal(err)
		}
		return
	}
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, dp, err := newAuth(db, logMailer{})
	if err != nil {
		log.Fatal(err) // a broken plugin combination fails here, not in production
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a, dp), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// newAuth wires email, passwords and the device plugin, which accepts only
// clientID. The verification URI is the plugin's default, /device on the
// base URL: a real app serves its approval page there; this example
// approves through the JSON routes (see the README). The test builds the
// app with the same function.
//
//ds:def id=devicelogin-newauth-7q2mx9kd
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, *deviceauth.Plugin, error) {
	dp := deviceauth.New(
		deviceauth.ValidateClient(func(_ context.Context, id string) (bool, error) { return id == clientID, nil }),
	)
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			dp,
		),
	)
	return a, dp, err
}

// newHandler mounts the two RFC endpoints, the library's other routes and
// /me. The RFC handlers are registered on their exact paths, which win over
// the /auth/ prefix.
//
//ds:def id=newhandler-47ztnykv owner=@khanakia stability=stable
func newHandler(a *auth.Auth, dp *deviceauth.Plugin) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST "+codePath, dp.CodeHandler())
	mux.Handle("POST "+tokenPath, dp.TokenHandler())
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux
}

// meResponse is what /me answers.
type meResponse struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Credential auth.Credential `json:"credential"`
}

// me is an app handler: RequireUser has already refused anyone signed out.
func me(w http.ResponseWriter, r *http.Request) {
	u := authhttp.MustUser(r)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meResponse{ID: u.ID, Name: u.Name, Credential: auth.RequestCredential(r.Context())}) // a client that hung up cannot be told
}

// newClient is the CLI's device client against the web app at server.
func newClient(hc *http.Client, server string) *deviceauth.Client {
	return &deviceauth.Client{CodeURL: server + codePath, TokenURL: server + tokenPath, ClientID: clientID, HTTP: hc}
}

// login is the CLI: ask for a code, show it, poll until the person approves
// or denies on another device, then call /me with the session as a bearer
// token. A denial or an expired code ends it with the RFC error
// (*deviceauth.ClientError), which the caller prints.
//
//ds:def id=devicelogin-login-3k8wq5nv
func login(ctx context.Context, out io.Writer, c *deviceauth.Client) error {
	code, err := c.RequestCode(ctx, "")
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "open %s and enter the code %s\n(or open %s)\nwaiting for approval...\n", code.VerificationURI, code.UserCode, code.VerificationURIComplete); err != nil {
		return err
	}
	tok, err := c.Poll(ctx, code)
	if err != nil {
		return err
	}
	server, err := url.Parse(c.TokenURL)
	if err != nil {
		return err
	}
	server.Path = "/me"
	var who meResponse
	if err := call(ctx, c.HTTP, server.String(), tok.AccessToken, &who); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "signed in as %s (%s), /me answered with credential %q\n", who.ID, who.Name, who.Credential)
	return err
}

// call makes a signed-in request with the bearer token and decodes the JSON
// answer into out.
func call(ctx context.Context, hc *http.Client, u, bearer string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(res.Body)
		return fmt.Errorf("%s: %s: %s", u, res.Status, raw)
	}
	return json.NewDecoder(res.Body).Decode(out)
}

// logMailer prints mail instead of sending it.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
