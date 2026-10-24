// Command two-factor-security-key lets a user hold several second factors at
// once (an authenticator app and one or more security keys) and pick one at
// sign-in. A security key here is a WebAuthn authenticator (a USB or NFC key,
// or the laptop's own Touch ID or Windows Hello) used after the password,
// never instead of it.
//
//	go run ./two-factor-security-key
//
// Then open http://localhost:8081 in a browser: the WebAuthn ceremonies run
// in the browser (navigator.credentials), so curl can show only the steps
// around them. Set AUTH_SECRET to at least 32 characters so enrolled factors
// survive a restart; without it a random one is used for this run only.
package main

import (
	"cmp"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
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
	"github.com/ubgo/auth/plugin/twofactor"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "two-factor-security-key.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// appName is what authenticator apps and the browser's key prompt show.
	appName = "Acme"
	// envSecret names the variable holding the app secret every sealing key
	// is derived from, TOTP secrets included.
	envSecret = "AUTH_SECRET"
	// randomSecretBytes is the size of the per-run secret used without
	// AUTH_SECRET.
	randomSecretBytes = 32
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
	// baseURL is the app's public URL. Its host is the relying party id of
	// every security key, fixed for good once a key is registered.
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
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, err := newAuth(db, logMailer{}, appSecret())
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

// appSecret is AUTH_SECRET, or a random secret for this run only.
func appSecret() []byte {
	if s := os.Getenv(envSecret); s != "" {
		return []byte(s)
	}
	b := make([]byte, randomSecretBytes)
	rand.Read(b) // never fails since Go 1.24: it crashes the program instead
	log.Printf("WARN %s is not set: using a random secret, so factors enrolled now stop working at the next start", envSecret)
	return []byte(hex.EncodeToString(b))
}

// newAuth wires email and password for the first factor, and two-factor
// sign-in with two kinds of second factor: an authenticator app (TOTP) and
// security keys, which the passkey plugin stores and verifies. The passkey
// plugin is registered on its own too, because it owns the key table; its
// passkey sign-in is a separate feature this app simply does not link to.
// extra lets the test pass a clock.
//
//ds:def id=sk-newauth-7qm2vd4w owner=@khanakia stability=stable
func newAuth(db *sql.DB, m email.Mailer, secret []byte, extra ...auth.Option) (*auth.Auth, error) {
	pk := passkey.New(passkey.DisplayName(appName))
	opts := []auth.Option{
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithSecret(secret),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			pk,
			twofactor.New(twofactor.Issuer(appName), twofactor.WithSecurityKeys(pk.SecurityKeys())),
		),
	}
	return auth.New(append(opts, extra...)...)
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

// pageHTML is the browser side: sign up or in, add a security key (with a
// current code as proof once a factor is on), see the factors, and answer
// the sign-in challenge with the factor the user picks.
const pageHTML = `<!doctype html>
<meta charset="utf-8">
<title>Two-factor with security keys</title>
<form id="signup"><input name="identifier" type="email" placeholder="email"> <input name="password" type="password" placeholder="password"> <button>Sign up</button> <button id="signin">Sign in</button></form>
<p><button id="status">Factors</button> <input id="code" placeholder="current code (proof)"> <button id="addkey">Add a security key</button></p>
<p><button id="usekey">Verify with a security key</button> <input id="totp" placeholder="authenticator code"> <button id="usecode">Verify with the code</button></p>
<pre id="out"></pre>
<script>
const out = (v) => document.getElementById("out").textContent = JSON.stringify(v, null, 2);
const post = async (path, body) => {
  const res = await fetch("` + authPrefix + `" + path, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body || {})});
  const json = await res.json();
  if (!res.ok) throw json.error;
  return json;
};
const form = () => Object.fromEntries(new FormData(document.getElementById("signup")));
const run = (fn) => async (e) => { e.preventDefault(); try { out(await fn()); } catch (err) { out(err); } };
const code = () => document.getElementById("code").value;
document.getElementById("signup").onsubmit = run(() => post("/password/sign-up", form()));
document.getElementById("signin").onclick = run(() => post("/password/sign-in", form()));
document.getElementById("status").onclick = run(() => fetch("` + authPrefix + `/twofactor/status").then((r) => r.json()));
document.getElementById("addkey").onclick = run(async () => {
  const begin = await post("/twofactor/security-key/register-begin");
  const cred = await navigator.credentials.create({publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(begin.options.publicKey)});
  const proof = code() ? {method: "totp", code: code()} : undefined;
  return post("/twofactor/security-key/register-finish", {ceremony: begin.ceremony, credential: cred.toJSON(), name: "My key", proof});
});
document.getElementById("usekey").onclick = run(async () => {
  const begin = await post("/twofactor/security-key/challenge");
  const cred = await navigator.credentials.get({publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(begin.options.publicKey)});
  return post("/twofactor/verify", {method: "security_key", securityKey: {ceremony: begin.ceremony, credential: cred.toJSON()}});
});
document.getElementById("usecode").onclick = run(() => post("/twofactor/verify", {method: "totp", code: document.getElementById("totp").value}));
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

// me is an app handler: RequireUser has already refused anyone signed out,
// and anyone whose second factor is still pending.
func me(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meResponse{ID: authhttp.MustUser(r).ID}) // a client that hung up cannot be told
}

// logMailer prints mail instead of sending it.
type logMailer struct{}

// Send logs the message.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
