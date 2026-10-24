// Command security-events feeds the library's security event stream to the
// app's own log drain: a rate rule over its limit and a password sprayed
// across accounts each become one typed record, handed in batches to the
// sinks the app registered, off the request path.
//
//	AUTH_SECRET=$(openssl rand -base64 32) go run ./security-events
//
// The drain here is a small function that writes one JSON line per event to
// standard output, standing in for a SIEM client, a log shipper or an
// alerting hook; the library ships the seam, never a vendor client.
// WithSecurityLog adds the zero-setup sink beside it: one structured line per
// event on the Auth's logger.
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
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "security-events.db"
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
	// The spraying guard counts each failed password under a keyed hash, so
	// the secret is required; auth.New refuses a missing or short one.
	opts := append([]auth.Option{
		auth.WithDB(db, sqlb.SQLiteDialect{}), auth.WithBaseURL(baseURL),
		auth.WithSecret([]byte(os.Getenv(auth.EnvSecret))),
		auth.WithRateRules(signInRule()),
		auth.WithPlugins(plugins()...),
	}, securitySinks(os.Stdout)...)
	a, err := auth.New(opts...)
	if err != nil {
		log.Fatal(err)
	}
	// Close drains the sinks' queues (bounded) before the process ends.
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// signInsPerMinute is how many password sign-ins an address makes a minute
// before the app's rule blocks it. It sits above sprayFailures so the
// spraying guard, not this rule, is what refuses a sprayed password in the
// walkthrough.
const signInsPerMinute = 5

// signInRule limits password sign-in per address. Each window it is
// exceeded in yields one rate.limit event, not one per refused call, so a
// flood is one line in the drain.
//
//ds:def id=securityevents-example-rule-5qw8nk3v
func signInRule() auth.RateRule {
	return auth.RateRule{Match: password.EndpointSignIn, Key: auth.ByIP, Limit: signInsPerMinute, Window: time.Minute}
}

// sprayFailures is how many failed sign-ins with one password, across every
// account and address, make the guard refuse that password; the crossing is
// one credential.stuffing event.
const sprayFailures = 3

// plugins is the app's plugin list: email and password, with the guard
// against one password sprayed across many accounts.
func plugins() []auth.Plugin {
	return []auth.Plugin{
		email.New(email.Login(), email.Recover(), email.WithMailer(email.MailerFunc(logMail))),
		password.New(password.GuardCredentialStuffing(password.StuffingPolicy{PasswordFailures: sprayFailures})),
	}
}

// drainQueue shapes the drain's queue: a name for SecurityStats and the log,
// small batches so a quiet stream still ships promptly. The zero value would
// take every default (1024 buffered, 100 per batch, 2s).
var drainQueue = auth.SecurityQueue{Name: drainName, BatchSize: drainBatch, FlushEvery: drainFlush}

const (
	// drainName labels the drain in SecurityStats.
	drainName = "drain"
	// drainBatch is the most events handed to the drain in one call.
	drainBatch = 10
	// drainFlush is the longest an event waits for its batch to fill.
	drainFlush = time.Second
)

// securitySinks registers the two sinks: the app's drain writing to w, and
// the library's logger sink. Each has its own queue and goroutine, so a slow
// drain delays only itself and never a sign-in.
//
//ds:def id=securityevents-example-sinks-8vk3qw2n
func securitySinks(w io.Writer) []auth.Option {
	return []auth.Option{
		auth.WithSecuritySink(jsonDrain(w), drainQueue),
		auth.WithSecurityLog(auth.SecurityQueue{}),
	}
}

// jsonDrain is the app's log drain: one JSON line per event. It runs on the
// sink's goroutine with a bounded context, so it may block on a network; an
// error is counted in SecurityStats and that batch is not offered again. An
// event carries no password, token or input, so it can leave the process as
// it stands.
func jsonDrain(w io.Writer) auth.SecuritySinkFunc {
	enc := json.NewEncoder(w)
	return func(_ context.Context, batch []auth.SecurityEvent) error {
		for _, e := range batch {
			if err := enc.Encode(e); err != nil {
				return err
			}
		}
		return nil
	}
}

// newHandler mounts the library's routes.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	return mux
}

// logMail prints mail instead of sending it.
func logMail(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
