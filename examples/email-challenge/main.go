// Command email-challenge signs people in without a password, across devices:
// the browser that asks keeps a poll token, one mail carries both a link and a
// code, and the session always lands in the browser that asked, even when the
// mail is opened on a phone.
//
//	go run ./email-challenge
//
// Mail is printed to the log instead of sent; plug an SMTP or API client into
// logMailer's place.
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
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/emailchallenge"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "email-challenge.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
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

	a, err := newAuth(db, logMailer{})
	if err != nil {
		log.Fatal(err) // a broken plugin combination fails here, not in production
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// newAuth wires email addresses and the email challenge, and nothing else: no
// password exists. SignUp lets a completed challenge create the account for an
// address nobody has verified yet. The test builds the app with the same
// function.
//
//ds:def id=newauth-ec7chl01 owner=@khanakia stability=stable
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			emailchallenge.New(emailchallenge.SignUp()),
		),
	)
}

// newHandler mounts the library's routes, the approval page the mailed link
// opens, and the app's /me page.
//
//ds:def id=newhandler-ec7chl02 owner=@khanakia stability=stable
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.HandleFunc("GET "+emailchallenge.DefaultPage, approvalPage)
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux
}

// approvalPageHTML is the page the mailed link opens. It asks the context
// route what to show, which approves nothing on another device, so a mail
// scanner that fetches the link changes nothing; only the Confirm button's
// POST approves. Opened in the browser that asked, context approves at once.
//
//ds:def id=approvalpagehtml-ec7chl03 owner=@khanakia stability=stable
const approvalPageHTML = `<!doctype html>
<meta charset="utf-8">
<title>Approve sign-in</title>
<p id="msg">Checking…</p>
<button id="ok" hidden>Confirm</button>
<script>
const token = new URLSearchParams(location.search).get("token");
const api = "` + authPrefix + `/emailchallenge";
const msg = document.getElementById("msg"), ok = document.getElementById("ok");
fetch(api + "/context?token=" + encodeURIComponent(token)).then(r => r.json()).then(c => {
  if (c.state === "needs-confirmation") {
    msg.textContent = "Sign in as " + c.identifier + " from " + c.userAgent + " (" + c.ipAddress + ")?";
    ok.hidden = false;
  } else if (c.state === "approved") msg.textContent = "Approved. Go back to your other tab.";
  else if (c.state === "wrong-browser") msg.textContent = "Open this link in the browser where you started.";
  else msg.textContent = "This sign-in request is not valid any more.";
});
ok.onclick = async () => {
  const res = await fetch(api + "/approve", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({token})});
  ok.hidden = true;
  msg.textContent = res.ok ? "Approved. Go back to your other tab." : (await res.json()).error.message;
};
</script>
`

// approvalPage serves approvalPageHTML.
func approvalPage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(approvalPageHTML)) // a client that hung up cannot be told
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

// Send logs the message, including the link and the code, so you can use them
// by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
