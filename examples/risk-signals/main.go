// Command risk-signals shows the three risk interfaces: an IP reputation
// check, a bot check and a trial-abuse check, each a small function the app
// passes and each reported to the security event stream.
//
//	go run ./risk-signals
//
// The library ships no detector and no vendor client. Here the IP check is a
// denylist of one documentation address, the bot check refuses a script's
// user agent, and the trial-abuse check compares a sign-up's address, with
// dots and "+tag" folded away, with the accounts that already used the
// trial. A real app wraps its own list, vendor or table in the same
// functions.
package main

import (
	"cmp"
	"context"
	"database/sql"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
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
	dbFile = "risk-signals.db"
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
	opts := append([]auth.Option{
		auth.WithDB(db, sqlb.SQLiteDialect{}), auth.WithBaseURL(baseURL),
		auth.WithPlugins(plugins()...),
		// The zero-setup sink: each flag is one line on the logger.
		auth.WithSecurityLog(auth.SecurityQueue{}),
	}, riskOptions()...)
	a, err := auth.New(opts...)
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

// The addresses and values the checks know.
const (
	// badIP is on the denylist, as a Tor exit or a hosting range would be.
	badIP = "203.0.113.66"
	// goodIP is any other address.
	goodIP = "203.0.113.67"
	// scriptAgent is the user agent of a script; browsers do not send it.
	scriptAgent = "python-requests/2.32"
	// usedTrialMail already used the free trial, in its folded form.
	usedTrialMail = "trial@example.com"
)

// Reasons the checks give; they end up on the event as AttrReason.
const (
	reasonDenylist = "denylist"
	reasonScript   = "script-agent"
	reasonRepeat   = "repeat-address"
)

// denylist is the addresses the IP check flags.
var denylist = map[netip.Addr]bool{netip.MustParseAddr(badIP): true}

// ipCheck is the IPReputation: a map lookup, fast and local as the
// interface requires, since it runs on the request. A vendor lookup goes in
// the same function behind a cache and a tight timeout, returning its error
// when it cannot answer; the policy then decides whether that lets the call
// through (the default) or refuses it (RiskFailClosed).
var ipCheck = auth.IPReputationFunc(func(_ context.Context, ip netip.Addr) (auth.RiskVerdict, error) {
	return auth.RiskVerdict{Flagged: denylist[ip], Reason: reasonDenylist}, nil
})

// botCheck is the BotChecker: it flags a user agent that names a scripting
// library. Real detectors weigh headers, timing and fingerprints; they read
// the same BotSignals.
var botCheck = auth.BotCheckerFunc(func(_ context.Context, s auth.BotSignals) (auth.RiskVerdict, error) {
	return auth.RiskVerdict{Flagged: strings.HasPrefix(s.Client.UserAgent, "python-requests"), Reason: reasonScript}, nil
})

// foldMail folds an address to the form one person's variants share: no
// dots and no "+tag" in the local part, lower case. The library hands the
// checker the normalized value; folding the aliases is the app's rule.
func foldMail(addr string) string {
	local, domain, ok := strings.Cut(addr, "@")
	if !ok {
		return addr
	}
	local, _, _ = strings.Cut(local, "+")
	return strings.ReplaceAll(local, ".", "") + "@" + domain
}

// trialUsed is the folded addresses that already had the free trial. A real
// app asks its database.
var trialUsed = map[string]bool{foldMail(usedTrialMail): true}

// trialCheck is the TrialAbuseChecker: a sign-up whose folded address already
// had the trial is flagged. It sees the new user's id, the normalized
// identifiers and the client, and never the password.
var trialCheck = auth.TrialAbuseCheckerFunc(func(_ context.Context, s auth.SignUpInfo) (auth.RiskVerdict, error) {
	for _, id := range s.Identifiers {
		if trialUsed[foldMail(id.Value)] {
			return auth.RiskVerdict{Flagged: true, Reason: reasonRepeat}, nil
		}
	}
	return auth.RiskVerdict{}, nil
})

// riskOptions turns on all three checks with the zero policy: a flag blocks
// with 403, and a check that errors lets the call through and logs.
// auth.RiskPolicy{Action: auth.RateLog} would only record, which is how to
// measure a detector before enforcing it; OnError: auth.RiskFailClosed
// refuses when the check cannot answer.
func riskOptions() []auth.Option {
	return []auth.Option{
		auth.WithIPReputation(ipCheck, auth.RiskPolicy{}),
		auth.WithBotCheck(botCheck, auth.RiskPolicy{}),
		auth.WithTrialAbuseCheck(trialCheck, auth.RiskPolicy{}),
	}
}

// plugins is the app's plugin list.
func plugins() []auth.Plugin {
	return []auth.Plugin{
		email.New(email.Login(), email.Recover(), email.WithMailer(email.MailerFunc(logMail))),
		password.New(),
	}
}

// trustedProxies is the reverse proxy in front of the app, on this machine.
var trustedProxies = []string{"127.0.0.1", "::1"}

// newHandler mounts the library's routes behind the trusted proxy.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix), authhttp.TrustedProxies(trustedProxies...)))
	return mux
}

// logMail prints mail instead of sending it.
func logMail(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
