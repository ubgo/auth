// Command phone-options shows three choices of the phone plugin on an
// email-and-password account, one per mode:
//
//	go run ./phone-options                     # one number; change replaces it in one step
//	PHONE_MODE=multiple go run ./phone-options # several numbers, one primary
//	PHONE_MODE=provider go run ./phone-options # the SMS provider makes and checks the codes
//
// Mail and texts are printed to the log instead of sent. The provider mode
// uses fakeVerify, an in-process stand-in shaped like Twilio Verify; plug your
// provider's client into its place.
package main

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/phone"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "phone-options.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
	// envMode names the environment variable that picks the mode.
	envMode = "PHONE_MODE"
)

// mode is which of the phone plugin's choices the app runs with.
type mode string

// The modes.
const (
	// modeSingle is the default: one number per account, replaced in one
	// step by change and confirm-change.
	modeSingle mode = ""
	// modeMultiple keeps several numbers per account (phone.Multiple).
	modeMultiple mode = "multiple"
	// modeProvider hands the codes to the SMS provider (phone.WithVerifier).
	modeProvider mode = "provider"
)

// errUnknownMode refuses a PHONE_MODE that is none of the modes, so a typo
// does not silently start the default.
var errUnknownMode = errors.New("phone-options: PHONE_MODE must be empty, multiple or provider")

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

	opts, err := phoneOptions(mode(os.Getenv(envMode)), logSMS{})
	if err != nil {
		log.Fatal(err)
	}
	a, err := newAuth(db, logMailer{}, logSMS{}, opts...)
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

// phoneOptions turns a mode into the phone plugin's options. The provider's
// service texts its own codes, so it is given the SMS sender here only
// because the fake has no network of its own.
//
//ds:def id=phone-options-modes-6xq3wm8v
func phoneOptions(m mode, sms phone.SMSSender) ([]phone.Option, error) {
	switch m {
	case modeSingle:
		return nil, nil
	case modeMultiple:
		return []phone.Option{phone.Multiple()}, nil
	case modeProvider:
		return []phone.Option{phone.WithVerifier(newFakeVerify(sms))}, nil
	default:
		return nil, fmt.Errorf("%w: %q", errUnknownMode, m)
	}
}

// newAuth wires email and password for sign-in, and the phone plugin with
// the mode's options. The test builds the app with the same function.
func newAuth(db *sql.DB, m email.Mailer, sms phone.SMSSender, opts ...phone.Option) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			phone.New(append([]phone.Option{phone.WithSMS(sms)}, opts...)...),
		),
	)
}

// newHandler mounts the library's routes and the app's /me page.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("GET /me", authhttp.Middleware(a)(authhttp.RequireUser(meHandler(a))))
	return mux
}

// appUser is the app's composite user: the primary number is a nested struct
// loaded by a join in the same statement (ADR-0001).
type appUser struct {
	auth.User
	Phone phone.Data
}

// Bindings lists every column the composite user reads.
func (u *appUser) Bindings() []sqlb.Binding {
	return sqlb.Bindings(auth.UserBindings(&u.User), phone.UserBindings(&u.Phone))
}

// Joins brings the user's primary phone identity into the query.
func (u *appUser) Joins() []sqlb.Join { return []sqlb.Join{phone.UserJoin()} }

// meResponse is what /me answers: the primary number, the one texts go to.
type meResponse struct {
	ID    string `json:"id"`
	Phone string `json:"phone"`
}

// meHandler loads the signed-in user with their primary number in one query.
func meHandler(a *auth.Auth) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var u appUser
		if err := a.LoadUser(r.Context(), authhttp.MustUser(r).ID, &u); err != nil {
			authhttp.WriteError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(meResponse{ID: u.ID, Phone: u.Phone.Number}) // a client that hung up cannot be told
	})
}

// The fake verification service's settings, the ones Twilio Verify uses by
// default.
const (
	// verifyDigits is the length of the codes the service makes.
	verifyDigits = 6
	// verifyModulus is 10^verifyDigits: codes are drawn below it and padded.
	verifyModulus = 1_000_000
	// verifyMaxChecks wrong checks end a verification; the user asks again.
	verifyMaxChecks = 5
	// verifyTTL is how long a verification stays open.
	verifyTTL = 10 * time.Minute
)

// verification is one open verification of the fake service.
type verification struct {
	code    string
	checks  int
	expires time.Time
}

// fakeVerify stands in for a provider's verification service such as Twilio
// Verify: Send makes a code and texts it, Check compares it, and the service
// keeps its own lifetime and attempt count. The library never sees the code.
// Replace it with a client of your provider's API; Check must answer a
// wrong, expired or exhausted code with phone.ErrCodeInvalid.
type fakeVerify struct {
	sms  phone.SMSSender
	mu   sync.Mutex
	open map[string]*verification
}

// newFakeVerify starts a service that texts through sms.
func newFakeVerify(sms phone.SMSSender) *fakeVerify {
	return &fakeVerify{sms: sms, open: map[string]*verification{}}
}

// Send opens a new verification for number, replacing an open one, and
// texts its code.
//
//ds:def id=phone-options-fakeverify-send-3qz7tb4p
func (f *fakeVerify) Send(ctx context.Context, number string) error {
	n, err := rand.Int(rand.Reader, big.NewInt(verifyModulus))
	if err != nil {
		return err
	}
	code := fmt.Sprintf("%0*d", verifyDigits, n.Int64())
	f.mu.Lock()
	f.open[number] = &verification{code: code, expires: time.Now().Add(verifyTTL)}
	f.mu.Unlock()
	return f.sms.Send(ctx, number, "Your verification code is "+code+".")
}

// Check approves code for number once, and counts a wrong one.
//
//ds:def id=phone-options-fakeverify-check-5hm9rw3e
func (f *fakeVerify) Check(_ context.Context, number, code string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.open[number]
	if !ok || time.Now().After(v.expires) || v.checks >= verifyMaxChecks {
		return phone.ErrCodeInvalid
	}
	if subtle.ConstantTimeCompare([]byte(code), []byte(v.code)) != 1 { // a timing-safe compare, as for every secret
		v.checks++
		return phone.ErrCodeInvalid
	}
	delete(f.open, number)
	return nil
}

// logMailer prints mail instead of sending it.
type logMailer struct{}

// Send logs the message.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}

// logSMS prints texts instead of sending them. Replace it with your SMS
// provider's API client.
type logSMS struct{}

// Send logs the text, including the code, so you can type it in by hand.
func (logSMS) Send(_ context.Context, to, text string) error {
	log.Printf("sms to=%s %q", to, text)
	return nil
}
