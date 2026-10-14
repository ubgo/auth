// Command audit-redaction keeps a security log that ranks every event and
// holds no raw personal data: each row carries a severity, and the address
// and the email typed are masked before the row is written.
//
//	go run ./audit-redaction
//
// Mail is printed to the log instead of sent; plug an SMTP or API client into
// logMailer's place.
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
	"github.com/ubgo/auth/plugin/audit"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "audit-redaction.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers.
	readHeaderTimeout = 5 * time.Second
	// sqlitePragmas: WAL so readers do not block the writer, and a busy
	// timeout instead of an immediate "database is locked".
	sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	// monitorAddress is the app's own uptime-check account, whose failed
	// sign-ins are expected noise.
	monitorAddress = "monitor@example.com"
)

var (
	// port is 8081, or $PORT when set, so two examples can run side by side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// baseURL is the app's public URL; its origin is the only one allowed to
	// send cookie-authenticated POSTs.
	baseURL = "http://localhost:" + port
)

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
	a, _, err := newApp(db, logMailer{})
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: "localhost:" + port, Handler: authhttp.Handler(a, authhttp.Prefix(authPrefix)), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// newApp wires email and password sign-in and the audit log with its three
// optional knobs: a severity per operation, a func for a rule that needs the
// whole event, and the default masking helper. Without audit.Redact the rows
// are stored whole. The test builds the app with the same function.
//
//ds:def id=newapp-auditredaction-4k7r2xtq owner=@khanakia stability=stable
func newApp(db *sql.DB, m email.Mailer) (*auth.Auth, *audit.Plugin, error) {
	au := audit.New(
		// A new account is worth a second look in this app: rank sign-ups warn.
		audit.Severities(map[auth.EndpointID]audit.Severity{"password.sign-up": audit.SeverityWarn}),
		// A rule that needs the whole event: the monitoring account failing
		// to sign in is expected, so it stays info.
		audit.SeverityFunc(func(e audit.Event, current audit.Severity) audit.Severity {
			if !e.OK && e.Identifier == monitorAddress {
				return audit.SeverityInfo
			}
			return current
		}),
		// The IP is stored as its /24 (or /48) network and the email's local
		// part is masked, before the row is written.
		audit.Redact(audit.MaskPIIRedactor),
	)
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(m)), password.New(), au),
	)
	return a, au, err
}

// logMailer prints mail instead of sending it.
type logMailer struct{}

// Send logs the message.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q", m.To, m.Subject)
	return nil
}
