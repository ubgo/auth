// Command pow-challenge asks a client over a rate limit for proof of work
// instead of refusing it: the same story as rate-actions, with plugin/pow as
// the rate challenger in place of a captcha. Password sign-in is limited to
// three calls a minute per address; the fourth is answered 428
// auth.challenge_required, and goes through once it carries a solved
// challenge in the X-Pow-Proof header.
//
//	go run ./pow-challenge
//
// No third party is in the loop: the server issues a random challenge, the
// client spends CPU time finding a nonce, and the server checks it with one
// hash. It makes a flood of guesses cost the sender per guess; it is not a
// bot detector, so the rate limits stay.
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
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/pow"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "pow-challenge.db"
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
	a, err := auth.New(auth.WithDB(db, sqlb.SQLiteDialect{}), auth.WithBaseURL(baseURL), auth.WithRateRules(signInRule()), auth.WithPlugins(plugins(pow.DefaultDifficulty)...))
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
// rule asks for work. The password plugin has its own, higher limits as
// well; this is the app's lower one, added on top.
const freeSignIns = 3

// signInRule limits password sign-in per address and challenges the calls
// over the limit: auth.RateChallenge answers 428 auth.challenge_required
// until the call carries a proof the registered challenger (plugin/pow)
// accepts. Inside the limit no proof is asked for, and one sent is ignored.
//
//ds:def id=powchallenge-example-rule-7kq3wn5x
func signInRule() auth.RateRule {
	return auth.RateRule{Match: password.EndpointSignIn, Key: auth.ByIP, Limit: freeSignIns, Window: time.Minute, Action: auth.RateChallenge}
}

// plugins is the app's plugin list. Registering pow is what makes it the rate
// challenger; it and plugin/captcha are both challengers, and auth.New refuses
// an app that registers both. difficulty is the leading zero bits a proof
// needs: main uses pow.DefaultDifficulty (20, about a million hashes), the
// tests a small value so they run in milliseconds.
//
//ds:def id=powchallenge-example-plugins-4vn8qk2w
func plugins(difficulty int) []auth.Plugin {
	return []auth.Plugin{
		email.New(email.Login(), email.Recover(), email.WithMailer(email.MailerFunc(logMail))),
		password.New(),
		pow.New(pow.Difficulty(difficulty)),
	}
}

// newHandler mounts the library's routes, POST /auth/pow/challenge among
// them.
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
