// Command webhooks sends signed outgoing webhooks to another service when a
// user signs up, signs in or out, changes or is deleted, and when a security
// event fires: plugin/webhook, the Standard Webhooks spec, with retries and a
// dead-letter state.
//
//	AUTH_SECRET=$(openssl rand -base64 32) go run ./webhooks
//
// The program is both sides at once, so it runs on its own: it registers an
// endpoint pointing at its own /receiver route, which verifies every request
// with signature.Verify and prints the event. Sign up with
//
//	curl -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
//	  -H 'Content-Type: application/json' -d '{"identifier":"ada@example.com","password":"correct horse battery staple"}'
//
// and the receiver prints user.created, identity.created and session.created.
// A real receiver lives in another service and needs only the signature
// package and the secret this program prints at start.
package main

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/webhook"
	"github.com/ubgo/auth/plugin/webhook/signature"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "webhooks.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// receiverPath is the demo receiver's route.
	receiverPath = "/receiver"
	// readHeaderTimeout bounds how long a client may take to send headers.
	readHeaderTimeout = 5 * time.Second
	// maintainEvery is how often the app runs the webhook retries. The first
	// retry waits webhook.DefaultRetryBase (a minute), so a minute keeps the
	// schedule honest; the library has no scheduler of its own.
	maintainEvery = time.Minute
	// maxBody bounds what the receiver reads of a request.
	maxBody = 1 << 20
)

var (
	// port is 8081, or $PORT when it is set, so two examples can run side by
	// side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the server listens: this machine only, for development.
	addr = "localhost:" + port
	// baseURL is the app's public URL.
	baseURL = "http://localhost:" + port
)

// sqlitePragmas: WAL so readers do not block the writer, and a busy timeout
// instead of an immediate "database is locked".
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// sqliteDSN builds the SQLite URI for a database file, escaping the path.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

func main() {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	// AllowPrivateNetworks only because the receiver is this program on
	// localhost; in production leave it out, and the SSRF guard refuses any
	// endpoint that resolves to a private or local address.
	hooks := webhook.New(webhook.AllowPrivateNetworks())
	opts := append([]auth.Option{auth.WithDB(db, sqlb.SQLiteDialect{}), auth.WithBaseURL(baseURL)},
		options([]byte(os.Getenv(auth.EnvSecret)), hooks)...)
	a, err := auth.New(opts...)
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	ctx := context.Background()
	if _, err := a.Migrate(ctx); err != nil {
		log.Fatal(err)
	}
	secret, err := ensureEndpoint(ctx, hooks, baseURL+receiverPath)
	if err != nil {
		log.Fatal(err)
	}
	go maintain(ctx, a)
	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a, receiver(secret, os.Stdout)), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// options wires the webhook sender: the secret derives the key endpoint
// secrets are sealed with, and the sink forwards the security event stream
// as security.* webhooks.
//
//ds:def id=webhooks-example-options-4tq8mw2k
func options(secret []byte, hooks *webhook.Plugin) []auth.Option {
	return []auth.Option{
		auth.WithSecret(secret),
		auth.WithPlugins(plugins(hooks)...),
		auth.WithSecuritySink(hooks.SecuritySink(), auth.SecurityQueue{Name: "webhook"}),
	}
}

// plugins is the app's plugin list: email, password and the webhook sender.
//
//ds:def id=plugins-kw9p328g
func plugins(hooks *webhook.Plugin) []auth.Plugin {
	return []auth.Plugin{
		email.New(email.Login(), email.Recover(), email.WithMailer(email.MailerFunc(logMail))),
		password.New(),
		hooks,
	}
}

// ensureEndpoint registers the demo endpoint on the first run and returns its
// secret; a later run finds it and reads the secret back.
//
//ds:def id=ensureendpoint-vjnph843
func ensureEndpoint(ctx context.Context, hooks *webhook.Plugin, target string) (string, error) {
	eps, err := hooks.Endpoints(ctx)
	if err != nil {
		return "", err
	}
	for _, ep := range eps {
		if ep.URL == target {
			return hooks.EndpointSecret(ctx, ep.ID)
		}
	}
	ep, secret, err := hooks.CreateEndpoint(ctx, webhook.EndpointInput{URL: target, Description: "demo receiver"})
	if err != nil {
		return "", err
	}
	log.Printf("registered endpoint %s for %s", ep.ID, ep.URL)
	return secret, nil
}

// maintain retries failed deliveries on a schedule. "auth maintain" from a
// cron job does the same in a deployment with several instances.
//
//ds:def id=maintain-j4krxy46
func maintain(ctx context.Context, a *auth.Auth) {
	t := time.NewTicker(maintainEvery)
	defer t.Stop()
	for range t.C {
		res, err := a.Maintain(ctx, auth.MaintainOptions{})
		if err != nil {
			log.Printf("maintain: %v", err)
			continue
		}
		if len(res) > 0 {
			log.Printf("maintain: %v", res)
		}
	}
}

// receiver is what the other service runs: read the raw body, verify it with
// the endpoint's secret, then decode. A request that does not verify gets 401
// and is never decoded. A real receiver also de-duplicates on webhook-id,
// because delivery is at least once.
//
//ds:def id=receiver-qx9v2dqr
func receiver(secret string, out io.Writer) http.Handler {
	enc := json.NewEncoder(out)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
		if err != nil {
			http.Error(w, "unreadable body", http.StatusBadRequest)
			return
		}
		if err := signature.Verify(secret, r.Header, body); err != nil {
			http.Error(w, "bad signature", http.StatusUnauthorized)
			return
		}
		var ev webhook.Envelope
		if err := json.Unmarshal(body, &ev); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		_ = enc.Encode(map[string]any{"id": r.Header.Get(signature.HeaderID), "type": ev.Type, "data": ev.Data}) // demo output only
		w.WriteHeader(http.StatusNoContent)
	})
}

// newHandler mounts the library's routes and the demo receiver.
func newHandler(a *auth.Auth, recv http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("POST "+receiverPath, recv)
	return mux
}

// logMail prints mail instead of sending it.
func logMail(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q", m.To, m.Subject)
	return nil
}
