// Command fiber is the quick start app on fiber v3: email and password
// sign-in, the library's routes mounted on a fiber group, and a fiber handler
// that only a signed-in user may reach. Fiber runs on fasthttp, not net/http;
// contrib/fiber bridges the two for the library's handlers.
//
//	go run ./fiber
//
// Mail is printed to the log instead of sent; plug an SMTP or API client
// into logMailer's place.
package main

import (
	"cmp"
	"context"
	"database/sql"
	"log"
	"net/url"
	"os"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/ubgo/auth"
	authfiber "github.com/ubgo/auth/contrib/fiber"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "fiber.db"
	// authPrefix is the fiber group the library's routes are mounted on.
	authPrefix = "/auth"
	// readTimeout bounds how long a client may take to send a request, so a
	// slow client cannot hold a connection open forever.
	readTimeout = 5 * time.Second
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
)

// sqlitePragmas are the settings every SQLite connection needs: WAL so readers
// do not block the writer, a busy timeout instead of an immediate "database is
// locked", and foreign keys, which SQLite leaves off and the library's cascades
// depend on.
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// sqliteDSN builds the SQLite URI for a database file. It escapes the path
// instead of concatenating "file:"+path, because a "#" or "?" in a path would
// otherwise start the URI's fragment or query and open a different file. It
// escapes only the path, never building a url.URL with a scheme, because Go
// writes a relative path such as "auth.db" as "file://auth.db", which SQLite
// reads as a host.
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
	log.Fatal(newHandler(a).Listen(addr, fiber.ListenConfig{DisableStartupMessage: true}))
}

// newAuth wires the library exactly as the net/http quick start does: the
// framework changes nothing about which plugins run.
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
		),
	)
}

// newHandler builds the fiber app: every operation registered on the /auth
// group (so fiber answers unknown paths itself), and the app's own routes
// behind authfiber.Middleware, which resolves the session once per request.
//
//ds:def id=newhandler-cdpjrvw5
func newHandler(a *auth.Auth) *fiber.App {
	app := fiber.New(fiber.Config{ReadTimeout: readTimeout})
	authfiber.Mount(app.Group(authPrefix), a)
	app.Get("/me", authfiber.Middleware(a), authfiber.RequireUser(), me)
	return app
}

// meResponse is what /me answers.
type meResponse struct {
	ID    string `json:"id"`
	Hello string `json:"hello"`
}

// me is an app handler: RequireUser has already refused anyone signed out.
//
//ds:def id=me-sgxnupxm
func me(c fiber.Ctx) error {
	u := authfiber.MustUser(c)
	return c.JSON(meResponse{ID: u.ID, Hello: u.Name})
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
