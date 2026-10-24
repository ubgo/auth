// Command plugin-delivery runs an app with an identifier plugin of its own:
// chat handles, in the chat subpackage. A user adds a handle, proves it with
// a code the app's chat bot sends, and from then on the handle is the
// account's recovery channel: "forgot password" delivers the reset link to
// the chat, because the email plugin here is for sign-in only.
//
//	go run ./plugin-delivery
//
// Mail and chat messages are printed to the log instead of sent; plug an SMTP
// client and your chat platform's bot API into logMailer and logBot.
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
	"github.com/ubgo/auth/examples/plugin-delivery/chat"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "plugin-delivery.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
	// PurposeNudge is a message purpose of the app's own, sent through
	// whichever channel the user has; the chat plugin cannot know its
	// wording, so the message carries it in DefaultText.
	PurposeNudge auth.Purpose = "app.nudge"
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set, so
	// two examples can run side by side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the server listens: this machine only, for development.
	// Use ":" + port to accept connections from the network.
	addr = "localhost:" + port
	// baseURL is the app's public URL. Its origin is the only one allowed to
	// send cookie-authenticated POSTs, and links in messages point at it.
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

	a, err := newAuth(db, logMailer{}, logBot{}, time.Now)
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

// newAuth wires the app. Email signs in but does not recover; the chat handle
// is the recovery channel, so a reset link travels through the bot. The clock
// is a parameter so the test can move time and expire a code; main passes
// time.Now.
//
//ds:def id=newauth-2k4jmfjn
func newAuth(db *sql.DB, m email.Mailer, bot chat.Sender, now func() time.Time) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithClock(now),
		auth.WithPlugins(
			email.New(email.Login(), email.WithMailer(m)),
			password.New(),
			chat.New(bot, chat.Recover()),
		),
	)
}

// newHandler mounts the library's routes, which now include /auth/chat/add
// and /auth/chat/verify, plus the app's own /nudge.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/nudge", authhttp.Middleware(a)(authhttp.RequireUser(nudgeHandler(a))))
	return mux
}

// nudgeText is the app's own message, worded by the app because no identifier
// plugin knows what a nudge is.
const nudgeText = "You have 3 unread comments. Open the app to see them."

// nudgeHandler sends the signed-in user a message of the app's own through
// their recovery channel: DeliverRecovery picks the first recovery kind the
// user has a verified identity for, here the chat handle.
//
//ds:def id=nudgehandler-ez4j5zqk
func nudgeHandler(a *auth.Auth) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := authhttp.MustUser(r)
		msg := auth.Message{Purpose: PurposeNudge, DefaultSubject: "Unread comments", DefaultText: nudgeText}
		if err := a.DeliverRecovery(r.Context(), u.ID, msg); err != nil {
			authhttp.WriteError(w, err)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
}

// logMailer prints mail instead of sending it.
type logMailer struct{}

// Send logs the message.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}

// logBot prints chat messages instead of sending them. A real one calls the
// chat platform's bot API with the handle and the text.
type logBot struct{}

// Send logs the message, including the code or link, so you can type it in.
func (logBot) Send(_ context.Context, handle, text string) error {
	log.Printf("chat to=@%s %q", handle, text)
	return nil
}
