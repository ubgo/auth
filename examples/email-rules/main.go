// Command email-rules decides which addresses may sign up and words the mail
// they get: a disposable-domain block list, a check that the domain can
// receive mail at all, an optional allow-list of domains for an internal
// tool, a welcome mail at the first verified address, and the mail in the
// reader's language.
//
//	go run ./email-rules
//	ALLOWED_DOMAINS=acme.com,*.acme.com go run ./email-rules
//
// The MX check asks this machine's DNS resolver. Mail is printed to the log
// instead of sent.
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
	dbFile = "email-rules.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// appName is the product name the mail is signed with.
	appName = "Acme"
	// localeFrench is the language tag of the French templates. A request
	// sending Accept-Language: fr-CA gets them too: the tag falls back to its
	// base language.
	localeFrench = "fr"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
	// envAllowed names the variable listing the only domains that may sign
	// up, comma-separated; unset lets every domain the other rules accept.
	// "acme.com" is that domain exactly, "*.acme.com" every subdomain of it.
	envAllowed = "ALLOWED_DOMAINS"
	// domainSeparator splits envAllowed.
	domainSeparator = ","
)

// blockList is a disposable-domain list in the one-domain-per-line format the
// public lists use. A real app loads the disposable-email-domains project's
// file (thousands of lines) and refreshes it; three lines show the format.
//
//ds:def id=blocklist-emr7ls01 owner=@khanakia stability=stable
const blockList = `# disposable mail providers
mailinator.com
guerrillamail.com
10minutemail.com
`

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

	// nil is net.DefaultResolver: the MX check asks real DNS.
	a, err := newAuth(db, logMailer{}, nil, splitDomains(os.Getenv(envAllowed)))
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

// newAuth wires email and password with the address rules and the mail
// wording. The resolver is a parameter so the test answers DNS itself; main
// passes nil for the system resolver. A malformed block list fails here,
// at start, rather than letting every address through. A non-empty allowed
// list admits only those domains (email.AllowDomains), given before the
// other checks so an outside address is refused without a DNS lookup; an
// entry that names no domain fails auth.New (email.ErrBadDomainList).
//
//ds:def id=newauth-emr7ls02 owner=@khanakia stability=stable
func newAuth(db *sql.DB, m email.Mailer, dns email.MXResolver, allowed []string) (*auth.Auth, error) {
	blocked, err := email.ParseDomainList(strings.NewReader(blockList))
	if err != nil {
		return nil, err
	}
	opts := []email.Option{email.Login(), email.Recover(), email.WithMailer(m)}
	if len(allowed) > 0 {
		opts = append(opts, email.AllowDomains(allowed...))
	}
	opts = append(opts,
		email.CheckAddresses(email.BlockDomains(blocked...), email.RequireMX(dns, 0)),
		email.Welcome(),
		email.Templates(brandTemplates),
		email.TemplatesByLocale(map[string]email.TemplateFunc{localeFrench: frenchTemplates}),
	)
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(opts...), password.New()),
	)
}

// splitDomains reads envAllowed's comma-separated list, dropping blanks, so
// an unset variable is no allow-list at all.
func splitDomains(raw string) []string {
	var out []string
	for _, d := range strings.Split(raw, domainSeparator) {
		if d = strings.TrimSpace(d); d != "" {
			out = append(out, d)
		}
	}
	return out
}

// brandTemplates words the welcome in the product's voice and leaves every
// other message to the library's English defaults, so a purpose this
// function does not know still sends a usable mail.
//
//ds:def id=brandtemplates-emr7ls03 owner=@khanakia stability=stable
func brandTemplates(m auth.Message) (subject, text string) {
	if m.Purpose == auth.PurposeWelcome {
		return "Welcome to " + appName, "Your address is verified and your " + appName + " account is ready."
	}
	return email.DefaultTemplates(m)
}

// frenchTemplates translates the two messages a new user sees; any other
// purpose falls back to brandTemplates, which falls back to the defaults. A
// template must carry m.Link or m.Code when the message has one.
//
//ds:def id=frenchtemplates-emr7ls04 owner=@khanakia stability=stable
func frenchTemplates(m auth.Message) (subject, text string) {
	switch {
	case m.Purpose == auth.PurposeVerify && m.Link != "":
		return "Vérifiez votre adresse", "Ouvrez ce lien pour vérifier votre adresse :\n\n" + m.Link + "\n\nSi vous n'avez rien demandé, ignorez ce message."
	case m.Purpose == auth.PurposeWelcome:
		return "Bienvenue chez " + appName, "Votre adresse est vérifiée et votre compte " + appName + " est prêt."
	}
	return brandTemplates(m)
}

// newHandler mounts the library's routes and the app's /me page.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux
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

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
