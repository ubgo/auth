// Command custom-pages is the ready-made pages in an app's own look and
// words: its own layout and stylesheet over the built-in forms, its own
// button text in English and French, and a "sign in with GitHub" button that
// the OAuth plugin offers and the app relabels.
//
//	GITHUB_CLIENT_ID=… GITHUB_CLIENT_SECRET=… go run ./custom-pages
//
// Open http://localhost:8081/login in a browser. Without the GitHub
// variables the page has no GitHub button. Mail is printed to the log
// instead of sent.
package main

import (
	"cmp"
	"context"
	"database/sql"
	"embed"
	"errors"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/authui"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "custom-pages.db"
	// authPrefix is where the library's JSON routes are mounted; the
	// GitHub button links to its start route under it.
	authPrefix = "/auth"
	// appName is shown in the page header and every title.
	appName = "Acme"
	// dashboardPath is the app's own page, where a sign-in lands.
	dashboardPath = "/dashboard"
	// pagesDir is the folder of this app's own templates inside pagesFS.
	pagesDir = "pages"
	// githubProvider is the OAuth provider's name, the middle of its routes
	// and of its button's ID.
	githubProvider = "github"
	// githubMethodID is the button's ID: the plugin's, so authui.Methods
	// replaces the plugin's button in place instead of adding a second.
	githubMethodID = oauth.PluginName + "." + githubProvider
	// githubLabel is the app's English text for that button.
	githubLabel = "Sign in with your GitHub work account"
	// methodTextPrefix starts the text key of a sign-in button's label
	// ("authui.method." + ID), the key a translation uses.
	methodTextPrefix = "authui.method."
	// footerKey is a text of the app's own layout. Any key works in
	// {{.T "…"}}; the "authui." prefix is the library's.
	footerKey = "app.footer"
	// envGitHubID and envGitHubSecret are the OAuth app's credentials.
	envGitHubID     = "GITHUB_CLIENT_ID"
	envGitHubSecret = "GITHUB_CLIENT_SECRET"
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
	// post the forms, and links in mail point at it.
	baseURL = "http://localhost:" + port
)

// pagesFS holds this app's layout.html and ui.css. Every other page comes
// from the built-in templates (see pageTemplates).
//
//go:embed pages
var pagesFS embed.FS

// sqlitePragmas are the settings every SQLite connection needs: WAL so readers
// do not block the writer, and a busy timeout instead of an immediate
// "database is locked".
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// sqliteDSN builds the SQLite URI for a database file, escaping the path so a
// "#" or "?" in it cannot start the URI's fragment or query.
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

func main() {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	var providers []oauth.Provider
	if id, secret := os.Getenv(envGitHubID), os.Getenv(envGitHubSecret); id != "" && secret != "" {
		providers = append(providers, oauth.GitHub(id, secret))
	}
	a, err := newAuth(db, logMailer{}, providers)
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

// newAuth wires email addresses, passwords and the OAuth providers. The
// OAuth plugin offers one sign-in button per provider to the pages.
func newAuth(db *sql.DB, m email.Mailer, providers []oauth.Provider) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			oauth.New(oauth.WithProviders(providers...)),
		),
	)
}

// pageTexts is the app's wording, by locale. A key missing here shows the
// library's English (authui.DefaultTexts lists every key), so a partial
// translation never shows a blank. The same map could also be passed to
// auth.WithMessages to translate error messages.
//
//ds:def id=custompages-pagetexts-5rk2vn8q
var pageTexts = auth.Messages{
	"en": {
		string(authui.TextSignIn): "Log in",
		footerKey:                 "Acme Ltd · Need help? support@example.com",
	},
	"fr": {
		string(authui.TextSignIn):         "Se connecter",
		string(authui.TextPassword):       "Mot de passe",
		string(authui.TextCreateAccount):  "Créer un compte",
		methodTextPrefix + githubMethodID: "Se connecter avec son compte GitHub professionnel",
		footerKey:                         "Acme SARL · Besoin d’aide ? support@example.com",
	},
}

// newHandler mounts the pages at the root with the app's templates, texts
// and GitHub button, the JSON routes under authPrefix, and the dashboard.
//
//ds:def id=custompages-newhandler-8mt4qw2x
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("GET "+dashboardPath, authhttp.Middleware(a)(http.HandlerFunc(dashboard)))
	mux.Handle("/", authui.Handler(a,
		authui.AppName(appName),
		authui.AfterSignIn(dashboardPath),
		authui.APIPrefix(authPrefix),
		authui.Templates(pageTemplates()),
		authui.Texts(pageTexts),
		// Same ID as the plugin's button, so this one replaces it in place.
		authui.Methods(authhttp.SignInMethod{
			ID:    githubMethodID,
			Kind:  oauth.UIMethodKind,
			Label: githubLabel,
			Route: "/" + oauth.PluginName + "/" + githubProvider + "/start",
		}),
	))
	return mux
}

// pageTemplates is this app's files laid over the built-in ones: a name
// pagesFS has wins, any other is read from authui.DefaultTemplates. So the
// app owns its layout and stylesheet and still gets every fix to the forms.
//
//ds:def id=custompages-pagetemplates-3wh7kd9p
func pageTemplates() fs.FS {
	own, err := fs.Sub(pagesFS, pagesDir)
	if err != nil {
		panic(err) // pagesDir is a constant that the embed directive names
	}
	return overlayFS{top: own, base: authui.DefaultTemplates()}
}

// overlayFS opens a name from top, else from base.
type overlayFS struct{ top, base fs.FS }

// Open implements fs.FS.
func (o overlayFS) Open(name string) (fs.File, error) {
	f, err := o.top.Open(name)
	if errors.Is(err, fs.ErrNotExist) {
		return o.base.Open(name)
	}
	return f, err
}

// dashboardPage is the app's own page: it greets the user, with a sign-out
// form that posts to the pages.
var dashboardPage = template.Must(template.New("dashboard").Parse(`<!doctype html>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Dashboard · {{.App}}</title>
<h1>Hello, {{.Name}}</h1>
<form method="post" action="` + authui.PathLogout + `"><button>Sign out</button></form>
`))

// dashboardData is what dashboardPage renders.
type dashboardData struct {
	App  string
	Name string
}

// dashboard shows the page to a signed-in user and sends anyone else to the
// sign-in page.
func dashboard(w http.ResponseWriter, r *http.Request) {
	u, ok := authhttp.CurrentUser(r)
	if !ok {
		http.Redirect(w, r, authui.PathLogin, http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := dashboardPage.Execute(w, dashboardData{App: appName, Name: u.Name}); err != nil {
		log.Printf("dashboard: %v", err)
	}
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
