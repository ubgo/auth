// Command rate-actions shows the three things a rate rule can do with a call
// over its limit: block it (429, the default), let it through and log it, or
// ask for a captcha. Here sign-in is limited to three calls a minute per
// address, and the fourth must carry a captcha token.
//
//	go run ./rate-actions
//
// The captcha is a fake verifier that accepts the token "human", so no
// provider account is needed; a real app passes captcha.Turnstile,
// captcha.Recaptcha or another provider.
package main

import (
	"cmp"
	"context"
	"database/sql"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/captcha"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "rate-actions.db"
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
	a, err := auth.New(auth.WithDB(db, sqlb.SQLiteDialect{}), auth.WithBaseURL(baseURL), auth.WithRateRules(signInRule(auth.RateChallenge)), auth.WithPlugins(plugins()...))
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

// freeSignIns is how many sign-in calls an address makes a minute before the
// rule acts. The password plugin has its own, higher limits as well; this is
// the app's lower one, added on top.
const freeSignIns = 3

// humanToken is the one captcha token the fake verifier accepts.
const humanToken = "human"

// signInRule limits password sign-in per address and does action with the
// calls over the limit: auth.RateBlock refuses them with 429 (the default,
// what an empty Action means), auth.RateLog lets them through and records
// them, auth.RateChallenge answers 428 auth.challenge_required until the
// call carries a captcha token the verifier accepts. Every action reports
// to the logger, the observer and the audit log.
//
//ds:def id=rateactions-example-rule-6k2q8w4n
func signInRule(action auth.RateAction) auth.RateRule {
	return auth.RateRule{Match: password.EndpointSignIn, Key: auth.ByIP, Limit: freeSignIns, Window: time.Minute, Action: action}
}

// plugins is the app's plugin list. ChallengeOnly makes the captcha plugin
// guard nothing on its own and serve only as the rate challenger: a visitor
// under the limit never sees a captcha. Registering the plugin is what makes
// it the challenger; auth.WithRateChallenger would name another.
//
//ds:def id=rateactions-example-plugins-4v9m3x7q
func plugins() []auth.Plugin {
	human := captcha.VerifierFunc(func(_ context.Context, token, _ string) error {
		if token == humanToken {
			return nil
		}
		return captcha.ErrFailed
	})
	return []auth.Plugin{
		email.New(email.Login(), email.Recover(), email.WithMailer(email.MailerFunc(logMail))),
		password.New(),
		captcha.New(human, captcha.ChallengeOnly()),
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
