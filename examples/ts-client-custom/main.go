// Command ts-client-custom is an app with a plugin of its own (nickname, in
// ./nickname) and a TypeScript frontend that calls it through a typed client
// generated from this app's own operation list:
//
//	go run ./ts-client-custom                                        # serve
//	go run ./ts-client-custom auth client ts --out ts-client-custom/web/src/auth  # write the client
//	go generate ./ts-client-custom                                   # the same, through the directive below
//
// The prebuilt client in clients/ts knows only the library's plugins; this
// one also has client.nickname.set and client.nickname.get and the
// nickname.too_long error code, because the binary that writes it is the app.
//
// Mail is printed to the log instead of sent.
package main

//go:generate go run . auth client ts --out web/src/auth

import (
	"cmp"
	"context"
	"database/sql"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authcli"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/examples/ts-client-custom/nickname"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "ts-client-custom.db"
	// authPrefix is where the library's routes are mounted, and so the
	// path the frontend's baseURL ends with.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
	// authCommand is the first argument that hands the rest of the command
	// line to authcli, so `ts-client-custom auth client ts --out …` writes
	// the client. Any word works.
	authCommand = "auth"
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set, so
	// two examples can run side by side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// addr is where the server listens: this machine only, for development.
	addr = "localhost:" + port
	// baseURL is the app's public URL. Its origin is the only one allowed to
	// send cookie-authenticated POSTs, and links in mail point at it.
	baseURL = "http://localhost:" + port
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

// main handles `auth …` before it migrates or listens, so writing the
// client needs no database and no free port.
//
//ds:def id=tsclientcustom-main-4mq8zt2w
func main() {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, err := newAuth(db, logMailer{})
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()

	ctx := context.Background()
	if code, handled := command(ctx, a, os.Args[1:], os.Stdout, os.Stderr); handled {
		_ = a.Close() // os.Exit skips the deferred calls
		os.Exit(code)
	}

	applied, err := a.Migrate(ctx)
	if err != nil {
		log.Fatal(err)
	}
	for _, name := range applied {
		log.Printf("migrated %s", name)
	}
	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// command runs "auth ..." through authcli (which has `client ts`) and
// reports handled=true with its exit code; any other command line is the
// server's.
//
//ds:def id=tsclientcustom-command-7xw3kq9p
func command(ctx context.Context, a *auth.Auth, args []string, stdout, stderr io.Writer) (code int, handled bool) {
	if len(args) == 0 || args[0] != authCommand {
		return authcli.ExitOK, false
	}
	return authcli.Main(ctx, a, args[1:], stdout, stderr), true
}

// newAuth wires the library with the app's own plugin last. The server, the
// client command and the tests all build the app with this one function,
// so the generated client describes exactly what the server serves.
//
//ds:def id=tsclientcustom-newauth-9pk2wv6r
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			nickname.New(),
		),
	)
}

// newHandler mounts the library's routes, which include the plugin's
// /auth/nickname/set and /auth/nickname/get.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	return mux
}

// logMailer prints mail instead of sending it.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
