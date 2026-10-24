// Command behind-proxy is the quick start as it runs in production behind a
// load balancer: the client's address read from the proxy's forwarded
// headers (or from a header the edge signs), errors in RFC 9457
// problem+json, an OpenAPI document and a health route for the platform,
// plain HTML forms that post without JavaScript, and messages in the
// language the visitor picked.
//
//	go run ./behind-proxy
//
// Mail is printed to the log instead of sent; plug an SMTP or API client
// into logMailer's place.
package main

import (
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/i18n"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "behind-proxy.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
)

const (
	// proxyNetwork is the private network the load balancer connects from.
	// Only a request from it may name a client address in Forwarded or
	// X-Forwarded-For; anyone else keeps the address of their connection.
	proxyNetwork = "10.0.0.0/8"
	// edgeIPHeader and edgeSignatureHeader are what an edge function in
	// front of the load balancer adds: the client's address, and an
	// HMAC-SHA256 of it under edgeSecret, hex-encoded.
	edgeIPHeader        = "X-Edge-Client-IP"
	edgeSignatureHeader = "X-Edge-Signature"
	// forwardedForHeader is the de facto header most load balancers write;
	// named here because ClientIPHeaders replaces the default list.
	forwardedForHeader = "X-Forwarded-For"
	// problemTypeBase prefixes the error code to make an RFC 9457 "type" URI.
	problemTypeBase = "https://example.com/problems/"
	// problemContentType is RFC 9457's media type for a problem body.
	problemContentType = "application/problem+json"
	// apiTitle and apiVersion name the OpenAPI document.
	apiTitle   = "Example auth API"
	apiVersion = "1.0.0"
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set, so
	// two examples can run side by side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the server listens: this machine only, for development.
	// Use ":" + port to accept connections from the network.
	addr = "localhost:" + port
	// baseURL is the app's public URL. Its origin is the only one allowed to
	// send cookie-authenticated POSTs, and links in mail point at it.
	baseURL = "http://localhost:" + port
	// edgeSecret is the key the edge signs the client address with, shared
	// out of band. Empty means no edge: the signed header is never believed.
	edgeSecret = os.Getenv("EDGE_SECRET")
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

	a, err := newAuth(db, logMailer{})
	if err != nil {
		log.Fatal(err) // a broken plugin combination fails here, not in production
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a, edgeSecret), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// newAuth is the quick start's wiring plus the message catalogue of every
// shipped language, so an error is answered in the visitor's language.
//
//ds:def id=behindproxy-newauth-4kq8wz2m
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithMessages(i18n.Messages()),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
		),
	)
}

// transportOptions are the authhttp options this deployment needs. Handler
// and Middleware get the same list, because each reads the client address,
// the locale and the error shape on its own and they must agree.
//
//ds:def id=behindproxy-transportoptions-7nw3qk5r
func transportOptions(secret string) []authhttp.Option {
	return []authhttp.Option{
		authhttp.Prefix(authPrefix),
		// The client address: a signed edge header first, else the load
		// balancer's forwarded headers, else the connection's address.
		authhttp.ClientIPFunc(edgeClientIP(secret)),
		authhttp.TrustedProxies(proxyNetwork),
		authhttp.ClientIPHeaders(authhttp.HeaderForwarded, forwardedForHeader),
		// Errors in the API's own contract.
		authhttp.EncodeErrors(writeProblem),
		// For the platform: GET /auth/ok and GET /auth/openapi.json.
		authhttp.Health(),
		authhttp.OpenAPI(authhttp.OpenAPIInfo{Title: apiTitle, Version: apiVersion, Servers: []string{baseURL}}),
		// For plain HTML forms and the language picker.
		authhttp.AcceptForms(),
		authhttp.SkipTrailingSlash(),
		authhttp.LocaleCookie(""),
	}
}

// newHandler mounts the library's routes and the app's /me page.
func newHandler(a *auth.Auth, secret string) http.Handler {
	opts := transportOptions(secret)
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, opts...))
	mux.Handle("/me", authhttp.Middleware(a, opts...)(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux
}

// edgeClientIP believes the edge's client address only when its signature
// checks out under secret, compared in constant time. Any other request gets
// "", which is not an address, so authhttp falls back to TrustedProxies: a
// client that writes the header itself gains nothing.
//
//ds:def id=behindproxy-edgeclientip-6hp2nt8v
func edgeClientIP(secret string) func(r *http.Request) string {
	return func(r *http.Request) string {
		ip, sig := r.Header.Get(edgeIPHeader), r.Header.Get(edgeSignatureHeader)
		if secret == "" || ip == "" || net.ParseIP(ip) == nil {
			return ""
		}
		got, err := hex.DecodeString(sig)
		if err != nil || !hmac.Equal(got, signIP(secret, ip)) {
			return ""
		}
		return ip
	}
}

// signIP is the edge's signature of a client address.
func signIP(secret, ip string) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(ip)) // a hash.Hash never returns an error
	return mac.Sum(nil)
}

// problem is an RFC 9457 problem body. Code is an extension member, so a
// program can still branch on the library's stable error code.
type problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Code   string `json:"code"`
}

// writeProblem is the ErrorEncoder: info is already decided (a database
// failure is the generic 500 by now) and translated, so it only shapes the
// body. The status the client gets is info.Status whatever this writes.
//
//ds:def id=behindproxy-writeproblem-9xk4mq2w
func writeProblem(w http.ResponseWriter, _ *http.Request, info auth.ErrorInfo) {
	w.Header().Set("Content-Type", problemContentType)
	w.WriteHeader(info.Status)
	_ = json.NewEncoder(w).Encode(problem{ // a client that hung up cannot be told
		Type:   problemTypeBase + info.Code,
		Title:  info.Message,
		Status: info.Status,
		Code:   info.Code,
	})
}

// meResponse is what /me answers.
type meResponse struct {
	ID    string `json:"id"`
	Hello string `json:"hello"`
}

// me is an app handler: RequireUser has already refused anyone signed out.
func me(w http.ResponseWriter, r *http.Request) {
	u := authhttp.MustUser(r)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meResponse{ID: u.ID, Hello: u.Name}) // a client that hung up cannot be told
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
