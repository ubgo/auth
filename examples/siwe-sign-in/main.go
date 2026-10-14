// Command siwe-sign-in signs people in with an Ethereum wallet (Sign-In with
// Ethereum, ERC-4361): the page asks for a nonce, the wallet signs a message
// carrying it, and the server checks the message and the signature. The
// first sign-in of a wallet creates the account.
//
//	go run ./siwe-sign-in
//
// Open http://localhost:8081 in a browser with a wallet extension such as
// MetaMask. The tests sign with a fixed test key instead (siwetest).
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
	"github.com/ubgo/auth/plugin/siwe"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "siwe-sign-in.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers.
	readHeaderTimeout = 5 * time.Second
)

var (
	// port is 8081, or $PORT when it is set, so two examples can run side by
	// side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the server listens: this machine only, for development.
	addr = "localhost:" + port
	// baseURL is the app's public URL. Its host is the domain a message must
	// name, and its origin the URI's: a message signed for another site is
	// refused.
	baseURL = "http://localhost:" + port
)

// sqlitePragmas: WAL so readers do not block the writer, and a busy timeout
// instead of an immediate "database is locked".
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// sqliteDSN builds the SQLite URI for a database file, escaping the path so
// a "#" or "?" in it cannot start the URI's fragment or query.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

func main() {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, err := newAuth(db)
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

// newAuth wires wallet sign-in. The email plugin is there so a user can add
// an address later; a wallet alone is an account (siwe.RequireEmail would
// ask for one at the first sign-in).
//
//ds:def id=siwe-example-newauth-4k8m2q7w
func newAuth(db *sql.DB) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(plugins()...),
	)
}

// plugins is the app's plugin list; the tests wire the same list.
func plugins() []auth.Plugin {
	return []auth.Plugin{
		email.New(email.Login(), email.Recover(), email.WithMailer(email.MailerFunc(logMail))),
		siwe.New(siwe.Chains(mainnet)),
	}
}

// mainnet is Ethereum's chain id. Naming the chains an app accepts refuses a
// message signed for a test network.
const mainnet = 1

// newHandler mounts the library's routes, the sign-in page and /me.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.HandleFunc("GET /{$}", page)
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux
}

// pageHTML asks the wallet for its address, gets a nonce, builds the
// ERC-4361 message, has the wallet sign it (personal_sign) and posts both to
// /auth/siwe/verify. A real app would use a library such as viem's
// createSiweMessage to build the message.
//
//ds:def id=siwe-example-page-9t2w6n4x
const pageHTML = `<!doctype html>
<meta charset="utf-8">
<title>Sign in with Ethereum</title>
<button id="go">Sign in with Ethereum</button>
<pre id="out"></pre>
<script>
const post = (path, body) => fetch("` + authPrefix + `/siwe" + path, {
  method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body),
}).then(r => r.json());
document.getElementById("go").onclick = async () => {
  const [address] = await ethereum.request({method: "eth_requestAccounts"});
  const chainId = parseInt(await ethereum.request({method: "eth_chainId"}), 16);
  const {nonce} = await post("/nonce", {walletAddress: address, chainId});
  // ERC-4361 asks for the EIP-55 checksummed address (viem's getAddress);
  // the server also accepts the lower-case form wallets return.
  const message = location.host + " wants you to sign in with your Ethereum account:\n" +
    address + "\n\nSign in to the example app.\n\nURI: " + location.origin +
    "\nVersion: 1\nChain ID: " + chainId + "\nNonce: " + nonce +
    "\nIssued At: " + new Date().toISOString();
  const signature = await ethereum.request({method: "personal_sign", params: [message, address]});
  const res = await post("/verify", {message, signature});
  document.getElementById("out").textContent = JSON.stringify(res, null, 2);
};
</script>
`

func page(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(pageHTML)) // a client that hung up cannot be told
}

// meResponse is what /me answers.
type meResponse struct {
	ID string `json:"id"`
}

func me(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meResponse{ID: authhttp.MustUser(r).ID}) // a client that hung up cannot be told
}

// logMail prints mail instead of sending it.
func logMail(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
