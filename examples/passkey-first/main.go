// Command passkey-first creates accounts whose first and only credential is a
// passkey: no password ever exists. It also accepts security keys that cannot
// verify the user (no PIN, no biometric), turns away one authenticator model,
// and asks users who turned on a second factor for it after such a key, which
// proves only that the key is present.
//
//	AUTH_SECRET=$(openssl rand -base64 32) go run ./passkey-first
//
// Open http://localhost:8081 in a browser with a passkey or a security key.
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
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/passkey"
	"github.com/ubgo/auth/plugin/twofactor"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "passkey-first.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// appName is what the browser's passkey prompt shows.
	appName = "Acme"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
)

// deniedModel is the AAGUID of an authenticator model the product does not
// support, as the passkey-authenticator-aaguids list names models. This one
// is made up for the example. Without passkey.WithMetadata an AAGUID is the
// client's claim, so a deny list steers honest clients; an allow list
// (AllowAuthenticators) needs metadata to be a lock.
//
//ds:def id=deniedmodel-pkf7st01 owner=@khanakia stability=stable
const deniedModel = "0d1e5ade-0000-4000-8000-000000000001"

var (
	// port is the port the app listens on: 8081, or $PORT when it is set, so
	// two examples can run side by side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the server listens: this machine only, for development.
	// Use ":" + port to accept connections from the network.
	addr = "localhost:" + port
	// baseURL is the app's public URL. Its origin is the only one allowed to
	// send cookie-authenticated POSTs, and it is the passkeys' relying party.
	baseURL = "http://localhost:" + port
)

// sqlitePragmas are the settings every SQLite connection needs: WAL so readers
// do not block the writer, and a busy timeout instead of an immediate
// "database is locked".
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// sqliteDSN builds the SQLite URI for a database file. It escapes the path
// instead of concatenating "file:"+path, because a "#" or "?" in a path would
// otherwise start the URI's fragment or query and open a different file.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

func main() {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// The second factor's data is sealed with a key derived from the secret.
	a, err := newAuth(db, []byte(os.Getenv(auth.EnvSecret)), logMailer{})
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

// newAuth wires email (the address every account needs), passkeys with
// passkey-first sign-up, and a mailed second factor. No password plugin: the
// passkey is the only way in. The test builds the app with the same function.
//
//ds:def id=newauth-pkf7st02 owner=@khanakia stability=stable
func newAuth(db *sql.DB, secret []byte, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithSecret(secret),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			passkey.New(
				passkey.DisplayName(appName),
				passkey.WithSignUp(),
				passkey.AuthenticatorSelection(passkey.Selection{UserVerification: passkey.RequirementPreferred}),
				passkey.DenyAuthenticators(deniedModel),
			),
			twofactor.New(twofactor.DeliveredCodes()),
		),
	)
}

// newHandler mounts the library's routes, the sign-up page, and the app's
// /me page.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.HandleFunc("GET /{$}", page)
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux
}

// pageHTML is the browser side of a passkey-first sign-up and of a sign-in:
// each ceremony is two POSTs around one browser call. sign-up-begin takes the
// address and name and returns creation options; the browser creates the
// passkey; sign-up-finish creates the account and signs in.
// parseCreationOptionsFromJSON, parseRequestOptionsFromJSON and toJSON are
// the WebAuthn JSON helpers of current browsers.
//
//ds:def id=pagehtml-pkf7st03 owner=@khanakia stability=stable
const pageHTML = `<!doctype html>
<meta charset="utf-8">
<title>` + appName + `</title>
<input id="email" placeholder="email"> <input id="name" placeholder="name">
<button id="up">Create account with a passkey</button>
<button id="in">Sign in with a passkey</button>
<pre id="out"></pre>
<script>
const api = "` + authPrefix + `/passkey";
const post = async (path, body) => {
  const res = await fetch(api + path, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)});
  return res.json();
};
const show = v => document.getElementById("out").textContent = JSON.stringify(v, null, 2);
document.getElementById("up").onclick = async () => {
  const begin = await post("/sign-up-begin", {identifier: document.getElementById("email").value, name: document.getElementById("name").value});
  const cred = await navigator.credentials.create({publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(begin.options.publicKey)});
  show(await post("/sign-up-finish", {ceremony: begin.ceremony, credential: cred.toJSON()}));
};
document.getElementById("in").onclick = async () => {
  const begin = await post("/login-begin", {});
  const cred = await navigator.credentials.get({publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(begin.options.publicKey)});
  show(await post("/login-finish", {ceremony: begin.ceremony, credential: cred.toJSON()}));
};
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

// Send logs the message, including the link or code, so you can use it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
