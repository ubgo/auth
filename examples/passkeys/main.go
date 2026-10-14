// Command passkeys lets people add a passkey (Face ID, Touch ID, Windows
// Hello, a security key, a phone) to their account and then sign in with it
// alone: no password, no code.
//
//	go run ./passkeys
//
// Then open http://localhost:8081 in a browser: the ceremony runs in the
// browser (navigator.credentials), so curl can show only its first step.
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
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/passkey"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "passkeys.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// appName is what the browser's passkey prompt shows.
	appName = "Acme"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set, so
	// two examples can run side by side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the server listens: this machine only, for development.
	// Use ":" + port to accept connections from the network.
	addr = "localhost:" + port
	// baseURL is the app's public URL. Its host is the passkeys' relying
	// party id, fixed for good once a passkey is registered, and its origin
	// is the only one a browser ceremony is accepted from.
	baseURL = "http://localhost:" + port
)

// sqlitePragmas are the settings every SQLite connection needs: WAL so readers
// do not block the writer, a busy timeout instead of an immediate "database is
// locked", and foreign keys, which SQLite leaves off and the library's cascades
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

func main() {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, err := newAuth(db, logMailer{})
	if err != nil {
		log.Fatal(err) // a broken plugin combination fails here, not in production
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// newAuth wires email and password for creating the account, and passkeys.
// Adding a passkey needs a fresh session, so an account comes first; after
// that, the passkey alone signs in. The relying party (id "localhost",
// origin baseURL) comes from WithBaseURL. The test builds the app with the
// same function.
//
//ds:def id=newauth-y6yqq3jq owner=@khanakia stability=stable
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			passkey.New(passkey.DisplayName(appName)),
		),
	)
}

// newHandler mounts the library's routes, the page that runs the browser
// ceremonies, and the app's /me page.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.HandleFunc("GET /{$}", page)
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux
}

// pageHTML is the whole browser side: sign up, add a passkey, sign in with
// it. The name matters: it is what the browser's passkey chooser shows (the
// plugin sends the user id as the account name). Each ceremony is two POSTs around one browser call: begin returns
// options, the browser asks the authenticator, finish sends the answer back
// with the ceremony handle. parseCreationOptionsFromJSON, parseRequestOptionsFromJSON
// and toJSON are the WebAuthn JSON helpers of current browsers; older ones
// need a base64url shim.
//
//ds:def id=pagehtml-uw4mt4hz owner=@khanakia stability=stable
const pageHTML = `<!doctype html>
<meta charset="utf-8">
<title>Passkeys</title>
<form id="signup"><input name="name" placeholder="name"> <input name="identifier" type="email" placeholder="email"> <input name="password" type="password" placeholder="password"> <button>Sign up</button></form>
<button id="add">Add a passkey</button>
<button id="signin">Sign in with a passkey</button>
<pre id="out"></pre>
<script>
const out = (v) => document.getElementById("out").textContent = JSON.stringify(v, null, 2);
const post = async (path, body) => {
  const res = await fetch("` + authPrefix + `" + path, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body || {})});
  const json = await res.json();
  if (!res.ok) throw json.error;
  return json;
};
const run = (fn) => async (e) => { e.preventDefault(); try { out(await fn()); } catch (err) { out(err); } };
document.getElementById("signup").onsubmit = run(() => post("/password/sign-up", Object.fromEntries(new FormData(document.getElementById("signup")))));
document.getElementById("add").onclick = run(async () => {
  const begin = await post("/passkey/register-begin");
  const cred = await navigator.credentials.create({publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(begin.options.publicKey)});
  return post("/passkey/register-finish", {ceremony: begin.ceremony, credential: cred.toJSON(), name: navigator.platform});
});
document.getElementById("signin").onclick = run(async () => {
  const begin = await post("/passkey/login-begin");
  const cred = await navigator.credentials.get({publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(begin.options.publicKey)});
  return post("/passkey/login-finish", {ceremony: begin.ceremony, credential: cred.toJSON()});
});
</script>
`

// page serves pageHTML.
func page(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(pageHTML)) // a client that hung up cannot be told
}

// meResponse is what /me answers.
type meResponse struct {
	ID string `json:"id"`
}

// me is an app handler: RequireUser has already refused anyone signed out.
func me(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meResponse{ID: authhttp.MustUser(r).ID}) // a client that hung up cannot be told
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
