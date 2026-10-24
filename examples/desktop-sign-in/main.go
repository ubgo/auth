// Command desktop-sign-in is a desktop app, a CLI or an Electron shell signing
// in through the system browser: the app opens the web app's "open in app"
// page, the person signs in there however the web app allows (password,
// Google, a magic link), the page mints a hand-off token and sends the
// browser back to the app, on a loopback address the app is listening on or
// on the app's own URL scheme, and the app exchanges the token for a bearer
// session of its own. When neither return path works, the page shows the
// token for the person to paste.
//
//	go run ./desktop-sign-in          # the web app, on localhost:8081
//	go run ./desktop-sign-in -app     # the "desktop app": listens on 127.0.0.1:8082 and prints the URL to open
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
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/handoff"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// appLoopback is where the desktop app listens for the browser's return:
	// the loopback interface only, never every interface, on a port the OS
	// picks (RFC 8252 section 7.3). The web app accepts any loopback port as
	// a return address with auth.WithLoopbackReturn, so nothing is fixed.
	appLoopback = "127.0.0.1:0"
	// appScheme is the desktop app's own URL scheme, the other return path:
	// the OS routes a URL in it to the app. Listed as a scheme-only trusted
	// origin ("myapp://"), it is a trusted return address like the loopback.
	appScheme = "myapp"
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "desktop-sign-in.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// openInAppPath is the web app's page that hands a signed-in session to
	// the app; returnToParam names where to send the browser afterwards, and
	// tokenParam is how the token travels on that URL. challengeParam is the
	// app's S256 challenge (handoff.ChallengeMethod), which binds the token
	// to the verifier the app kept, so a token caught by another program
	// registered for the same scheme cannot be exchanged.
	openInAppPath  = "/open-in-app"
	returnToParam  = "returnTo"
	tokenParam     = "token"
	challengeParam = "challenge"
	// callbackPath is the path the app serves on its loopback listener.
	callbackPath = "/callback"
	// readHeaderTimeout bounds how long a client may take to send headers.
	readHeaderTimeout = 5 * time.Second
	// appWait is how long the desktop app waits for the browser to come back
	// before giving up; a person who walked away should not leave a listener
	// open for ever.
	appWait = 5 * time.Minute
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set, so
	// two examples can run side by side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the web app listens: this machine only, for development.
	addr = "localhost:" + port
	// baseURL is the web app's public URL. Its origin is the only one allowed
	// to send cookie-authenticated POSTs.
	baseURL = "http://localhost:" + port
)

// sqlitePragmas are the settings every SQLite connection needs: WAL, a busy
// timeout, and foreign keys, which the library's cascades depend on.
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// sqliteDSN builds the SQLite URI for a database file. It escapes the path
// instead of concatenating "file:"+path, because a "#" or "?" in a path would
// otherwise start the URI's fragment or query and open a different file.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

func main() {
	asApp := flag.Bool("app", false, "run the desktop app instead of the web app")
	flag.Parse()
	if *asApp {
		if err := runApp(context.Background(), os.Stdout, http.DefaultClient, baseURL, appLoopback, appWait, openBrowserByPrintingTo(os.Stdout)); err != nil {
			log.Fatal(err)
		}
		return
	}
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, hp, err := newAuth(db, logMailer{}, appScheme+"://")
	if err != nil {
		log.Fatal(err) // a broken plugin combination fails here, not in production
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a, hp), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// newAuth wires email, passwords and the hand-off plugin, and trusts the
// app's return addresses: any port on the loopback address (return URLs
// only, never the origin check) and the app's scheme. The hand-off plugin is
// ServerOnly, so only the open-in-app page mints tokens, after RequireUser
// and the return-address check; a page script cannot mint one on its own.
// The test builds the app with the same function.
//
//ds:def id=desktop-newauth-4w7mk2qr
func newAuth(db *sql.DB, m email.Mailer, trusted ...string) (*auth.Auth, *handoff.Plugin, error) {
	hp := handoff.New(handoff.ServerOnly())
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithTrustedOrigins(trusted...),
		auth.WithLoopbackReturn(),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			hp,
		),
	)
	return a, hp, err
}

// newHandler mounts the library's routes, the open-in-app page and /me.
func newHandler(a *auth.Auth, hp *handoff.Plugin) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle(openInAppPath, authhttp.Middleware(a)(authhttp.RequireUser(openInApp(a, hp))))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux
}

// openInApp is the page a signed-in person reaches from the app. A GET shows
// a confirmation with one button; the button's POST mints the token and, with
// a trusted returnTo, sends the browser there with the token as a query
// parameter, or without one shows the token for the person to paste into the
// app. The mint is a POST on purpose: a browser sends no Origin header on a
// navigation, so a GET could not pass the origin check that protects every
// cookie-authenticated mutation, and a page that hands a session to another
// client should take a click, not a link. An untrusted returnTo is refused
// before any token exists: the check is the same open-redirect defence every
// returnTo in the library goes through, and a token minted for an attacker's
// URL would be a session for the attacker. The app's challenge, when it sent
// one, is passed through to the mint unread: the plugin checks its shape and
// the app's verifier opens it.
//
//ds:def id=desktop-openinapp-8n3xv5tp
func openInApp(a *auth.Auth, hp *handoff.Plugin) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		returnTo, challenge := r.FormValue(returnToParam), r.FormValue(challengeParam)
		if returnTo != "" && !a.TrustsReturnURL(returnTo) {
			http.Error(w, "the return address is not trusted", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.Method != http.MethodPost {
			_ = confirmTemplate.Execute(w, confirmData{ReturnTo: returnTo, Challenge: challenge, User: authhttp.MustUser(r)}) // a client that hung up cannot be told
			return
		}
		res, err := hp.GenerateWith(r.Context(), handoff.GenerateRequest{Challenge: challenge})
		if err != nil {
			authhttp.WriteError(w, err)
			return
		}
		if returnTo == "" {
			_ = pasteTemplate.Execute(w, res) // a client that hung up cannot be told
			return
		}
		http.Redirect(w, r, withToken(returnTo, res.Token), http.StatusFound)
	})
}

// confirmData fills the confirmation page.
type confirmData struct {
	ReturnTo  string
	Challenge string
	User      auth.User
}

// confirmTemplate is the confirmation page: who is signed in, and one button
// that POSTs back with the same returnTo and challenge.
var confirmTemplate = template.Must(template.New("confirm").Parse(`<!doctype html>
<title>Open in the app</title>
<p>Signed in as {{.User.Name}}. Open the app with this account?</p>
<form method="post"><input type="hidden" name="returnTo" value="{{.ReturnTo}}"><input type="hidden" name="challenge" value="{{.Challenge}}"><button>Open the app</button></form>
`))

// withToken appends the token to a return URL's query, keeping whatever query
// the app put there (its own request id, say).
func withToken(returnTo, token string) string {
	u, err := url.Parse(returnTo)
	if err != nil {
		return returnTo // unreachable after TrustsReturnURL, which parsed it
	}
	q := u.Query()
	q.Set(tokenParam, token)
	u.RawQuery = q.Encode()
	return u.String()
}

// pasteTemplate is the fallback page: the token to type into the app and
// when it stops working.
var pasteTemplate = template.Must(template.New("paste").Parse(`<!doctype html>
<title>Open in the app</title>
<p>Paste this code into the app. It works once and expires at {{.ExpiresAt.Format "15:04:05"}}.</p>
<pre id="code">{{.Token}}</pre>
`))

// meResponse is what /me answers.
type meResponse struct {
	ID         string          `json:"id"`
	Credential auth.Credential `json:"credential"`
}

// me is an app handler: RequireUser has already refused anyone signed out.
func me(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meResponse{ID: authhttp.MustUser(r).ID, Credential: auth.RequestCredential(r.Context())}) // a client that hung up cannot be told
}

// logMailer prints mail instead of sending it.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}

// openBrowserByPrintingTo is the "open the system browser" step of a real
// app (xdg-open, open, rundll32), reduced to printing the URL.
func openBrowserByPrintingTo(w io.Writer) browserOpener {
	return func(u string) error {
		_, err := fmt.Fprintf(w, "open this URL in your browser:\n%s\n", u)
		return err
	}
}
