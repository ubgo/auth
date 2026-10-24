// Command translated-errors answers every library error in the caller's
// language: German for "Accept-Language: de", French for a locale cookie of
// "fr", and the language a signed-in user picked in settings on any device.
// The code of an error never changes, so a client that matches codes sees no
// difference. It also shows an app handler that matches library errors with
// errors.Is and answers in its own shape, and the page a failed browser flow
// lands on (auth.WithErrorURL).
//
//	go run ./translated-errors
//
// Mail is printed to the log instead of sent; plug an SMTP or API client
// into logMailer's place.
package main

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"slices"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/i18n"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/magiclink"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "translated-errors.db"
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
	h, err := newHandler(a)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// Locales the app knows by name.
const (
	// localeEnglish is the language the library's errors are declared in. It
	// is not in i18n.Locales because a request in English needs no catalogue.
	localeEnglish = "en"
	// localeGerman is the locale whose wording the app overrides and whose
	// mail it translates.
	localeGerman = "de"
)

// supportedLocales are the languages a user may pick in settings: English
// plus every language the i18n catalogue ships. The settings endpoint refuses
// anything else, so the stored value is always one the app can answer in.
var supportedLocales = append([]string{localeEnglish}, i18n.Locales...)

// colLocale is the app's column on auth_user that holds the user's chosen
// language. The app owns it (auth.AppName); the library only reads it.
const colLocale = "app_locale"

// localeColumn declares colLocale: text, NOT NULL with an empty default, so
// rows that existed before the column are filled and "" means "not chosen",
// which WithUserLocale ignores.
//
//ds:def id=translated-errors-locale-column-sk97jqwe
var localeColumn = auth.ColumnExtension{Name: colLocale, Type: auth.ColumnText, Default: "''"}

// UserLocale is the typed expression of colLocale, for writing it with
// SetUserColumn and reading it with LoadUserColumns.
var UserLocale = sqlb.Col[string](auth.TableUser, colLocale)

// ourWrongPasswordDE is the app's own German wording for a wrong password,
// friendlier than the shipped translation. It replaces one entry; every other
// German message stays the catalogue's.
const ourWrongPasswordDE = "E-Mail-Adresse oder Passwort stimmen nicht. Versuchen Sie es noch einmal."

// messages is the catalogue errors are answered from: every language the
// i18n package ships, with one German message replaced by the app's own.
// i18n.Messages returns a fresh map on every call, so editing it changes
// nothing anyone else holds.
//
//ds:def id=translated-errors-catalog-override-4yx294mh
func messages() auth.Messages {
	m := i18n.Messages()
	m[localeGerman][password.ErrInvalidCredentials.Code] = ourWrongPasswordDE
	return m
}

// newAuth wires email and password sign-in, magic links opened over GET (a
// browser flow whose failure lands on the error page), the translated
// catalogue, the user's stored language, and the error page. The test builds
// the app with the same function.
//
//ds:def id=translated-errors-newauth-w57j7swr
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.Multiple(), email.WithMailer(m),
				email.TemplatesByLocale(map[string]email.TemplateFunc{localeGerman: germanMail})),
			password.New(),
			magiclink.New(magiclink.VerifyByGET()),
		),
		auth.WithMessages(messages()),
		auth.WithUserColumns(localeColumn),
		auth.WithUserLocale(colLocale),
		auth.WithErrorURL(authPrefix+authhttp.ErrorPagePath),
	)
}

// localeRule makes the library read the request's language from the
// auth_locale cookie before Accept-Language, so a language picked on the
// site wins over the browser's list. Handler and Middleware both take it, so
// the library's routes and the app's own handlers agree.
var localeRule = authhttp.LocaleCookie(authhttp.DefaultLocaleCookieName)

// authRoutes mounts the library's routes with the locale rule and the error
// page WithErrorURL points at: GET /auth/error?error=<code> shows the code
// and its message in the request's language.
//
//ds:def id=translated-errors-error-page-ab7ax3sy
func authRoutes(a *auth.Auth) http.Handler {
	return authhttp.Handler(a, authhttp.Prefix(authPrefix), localeRule, authhttp.ErrorPage(authhttp.ErrorPageOptions{}))
}

// Routes of the app's own handlers.
const (
	// loginPath is the app's own sign-in endpoint, over the typed Go API.
	loginPath = "/api/login"
	// localePath stores the signed-in user's language.
	localePath = "/api/locale"
	// mePath answers who is signed in and their stored language.
	mePath = "/me"
)

// newHandler mounts the library's routes and the app's handlers. The app's
// handlers run behind Middleware, which attaches the request (and so its
// language and session) to the context the Go API reads.
//
//ds:def id=translated-errors-newhandler-yu5wmag9
func newHandler(a *auth.Auth) (http.Handler, error) {
	pw, err := auth.PluginOf[*password.Plugin](a)
	if err != nil {
		return nil, err
	}
	withAuth := authhttp.Middleware(a, localeRule)
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authRoutes(a))
	mux.Handle("POST "+loginPath, withAuth(login(a, pw)))
	mux.Handle("POST "+localePath, withAuth(authhttp.RequireUser(setLocale(a))))
	mux.Handle("GET "+mePath, withAuth(authhttp.RequireUser(me(a))))
	return mux, nil
}

// loginRequest is the body of the app's sign-in endpoint.
type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// loginAnswer is the app's own answer shape, not the library's: a reason the
// app's front end switches on and a message to show.
type loginAnswer struct {
	OK      bool   `json:"ok"`
	UserID  string `json:"userId,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

// The reasons the app's sign-in endpoint answers with.
const (
	// reasonBadRequest: the body was not JSON.
	reasonBadRequest = "bad_request"
	// reasonWrongPassword: password.ErrInvalidCredentials, which also covers
	// an unknown address so the answer reveals no account.
	reasonWrongPassword = "wrong_password"
	// reasonSlowDown: a rate rule refused the attempt.
	reasonSlowDown = "slow_down"
	// reasonFailed: anything else the library refused.
	reasonFailed = "failed"
)

// login is an app handler over the typed Go API. It matches the library's
// errors with errors.Is, which compares codes, and answers in the app's own
// shape; the message comes from Auth.ErrorInfo, so it is in the request's
// language. The session cookie a success issues is set by Middleware.
//
//ds:def id=translated-errors-errors-is-handler-rpcnvudj
func login(a *auth.Auth, pw *password.Plugin) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in loginRequest
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeJSON(w, http.StatusBadRequest, loginAnswer{Reason: reasonBadRequest})
			return
		}
		res, err := pw.SignIn(r.Context(), password.SignInRequest{Identifier: in.Email, Password: password.Secret(in.Password)})
		msg := a.ErrorInfo(r.Context(), err).Message
		switch {
		case err == nil:
			writeJSON(w, http.StatusOK, loginAnswer{OK: true, UserID: res.User.ID})
		case errors.Is(err, password.ErrInvalidCredentials):
			writeJSON(w, http.StatusUnauthorized, loginAnswer{Reason: reasonWrongPassword, Message: msg})
		case errors.Is(err, auth.ErrRateLimited):
			writeJSON(w, http.StatusTooManyRequests, loginAnswer{Reason: reasonSlowDown, Message: msg})
		default:
			log.Printf("sign-in failed: %v", err) // the log is the only record of an internal error's detail
			writeJSON(w, auth.ErrorOf(err).Status, loginAnswer{Reason: reasonFailed, Message: msg})
		}
	}
}

// localeRequest is the body of the settings endpoint.
type localeRequest struct {
	Locale string `json:"locale"`
}

// localeAnswer is what the settings endpoint and /me answer.
type localeAnswer struct {
	ID     string `json:"id,omitempty"`
	Locale string `json:"locale"`
}

// reasonUnsupportedLocale is the settings endpoint's refusal of a language
// the app cannot answer in.
const reasonUnsupportedLocale = "unsupported_locale"

// setLocale stores the signed-in user's language in colLocale. From the next
// request on, WithUserLocale makes it win over Accept-Language and the
// locale cookie for that user, for errors and mail alike.
//
//ds:def id=translated-errors-store-user-locale-v35bz7mj
func setLocale(a *auth.Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in localeRequest
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || !slices.Contains(supportedLocales, in.Locale) {
			writeJSON(w, http.StatusBadRequest, loginAnswer{Reason: reasonUnsupportedLocale})
			return
		}
		if err := auth.SetUserColumn(r.Context(), a, auth.AppName, authhttp.MustUser(r).ID, UserLocale, in.Locale); err != nil {
			log.Printf("store locale: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, localeAnswer{Locale: in.Locale})
	}
}

// me answers the signed-in user and the language they stored.
func me(a *auth.Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out := localeAnswer{ID: authhttp.MustUser(r).ID}
		if err := a.LoadUserColumns(r.Context(), out.ID, sqlb.Bind(UserLocale, &out.Locale)); err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// writeJSON answers v as JSON with status.
func writeJSON[T any](w http.ResponseWriter, status int, v T) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v) // a client that hung up cannot be told
}

// germanMail is the German wording of every mail the email plugin sends,
// picked when the message's locale is German: the request's, or the stored
// one of a signed-in user. A real app switches on m.Purpose for each kind of
// mail; this one words the verification mail and gives every other purpose
// one generic text that still carries the link or the code.
//
//ds:def id=translated-errors-german-mail-56uy8n8b
func germanMail(m auth.Message) (subject, text string) {
	if m.Purpose == auth.PurposeVerify {
		return "Bitte bestätigen Sie Ihre E-Mail-Adresse", "Öffnen Sie diesen Link, um die Adresse zu bestätigen:\n\n" + m.Link + "\n"
	}
	text = "Eine Nachricht zu Ihrem Konto.\n"
	if m.Link != "" {
		text += "\nLink: " + m.Link + "\n"
	}
	if m.Code != "" {
		text += "\nCode: " + m.Code + "\n"
	}
	return "Eine Nachricht zu Ihrem Konto", text
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
