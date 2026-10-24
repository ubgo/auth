// Command session-tuning is one email-and-password app that turns the
// session knobs the defaults leave alone: how long a session lives and how
// often its expiry slides, app data returned with the session, whether the
// client's address is kept, a key-value store in place of the session table,
// and the stateless-token switches.
//
//	go run ./session-tuning                          # lifetimes + extras, sessions in the database
//	go run ./session-tuning -no-ip                   # keep no IP or user agent with a session
//	go run ./session-tuning -kv                      # sessions and rate counters in a key-value store
//	go run ./session-tuning -deferred                # reads never slide; the client asks for it
//	go run ./session-tuning -stateless -version 1    # sealed tokens; raise -version to sign everyone out
//	go run ./session-tuning -stateless -read-every 2m # stateless, user read once per 2 minutes
//
// Mail is printed to the log instead of sent; plug an SMTP or API client
// into logMailer's place.
package main

import (
	"cmp"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
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
	dbFile = "session-tuning.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
	// envSessionKey is the key that seals stateless tokens, as 64 hex
	// characters. Unset, a random key is used for this run only, so every
	// stateless session ends when the process does.
	envSessionKey = "AUTH_SESSION_KEY"
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

// sessionConfig is a tighter lifetime than auth.DefaultSessionConfig (7 days
// idle, 30 at most, written at most daily), the kind a finance or admin app
// wants: half an hour without a request signs the user out, nobody stays in
// past a working day, and an active session's expiry is written at most
// every five minutes, so a busy user costs one write per five minutes rather
// than one per request.
//
//ds:def id=session-tuning-config-r3j2ke3u
var sessionConfig = auth.SessionConfig{
	IdleTimeout:  30 * time.Minute,
	MaxLifetime:  12 * time.Hour,
	RefreshAfter: 5 * time.Minute,
}

// maxDeviceAccounts is how many accounts one browser may hold at once
// (WithMultiSession), so the account switcher's list can carry extras too.
const maxDeviceAccounts = 3

// planFree is the plan every account is on in this example. A real app reads
// its billing table here.
const planFree = "free"

// sessionInfo is the app data GET /auth/session returns under "extras": what
// the front end would otherwise fetch with a second request.
type sessionInfo struct {
	// Plan is the account's plan, for the upgrade banner.
	Plan string `json:"plan"`
	// SignedInAt is when this session began, for "signed in since".
	SignedInAt time.Time `json:"signedInAt"`
}

// sessionExtras computes sessionInfo for the signed-in call. Its signature is
// auth.SessionExtras, whose any result is the library's encode-only boundary:
// the value is only ever JSON-encoded, so the app's own struct goes in.
//
//ds:def id=session-tuning-extras-2h3vpcv9
func sessionExtras(_ context.Context, c *auth.Call) (any, error) {
	return sessionInfo{Plan: planFree, SignedInAt: c.Session.CreatedAt}, nil
}

// tuning is one wiring: which optional session switches are on. The test
// fills it directly; main fills it from the flags.
type tuning struct {
	// NoIP is WithoutIPTracking: sessions keep no address or user agent.
	NoIP bool
	// KV, when set, holds sessions and rate counters (WithSecondaryStorage).
	KV auth.SecondaryStorage
	// Deferred is WithDeferredSessionRefresh: reads report needsRefresh.
	Deferred bool
	// Stateless seals the session into the token with Key.
	Stateless bool
	// Key seals stateless tokens; auth.SealKeySize bytes.
	Key []byte
	// Version is WithStatelessVersion; raising it signs everyone out.
	Version int
	// ReadEvery is WithStatelessRefreshWithoutRead's interval; 0 is off.
	ReadEvery time.Duration
	// Clock replaces time.Now; nil is the real clock. The test moves it.
	Clock func() time.Time
}

// errBadKey refuses a session key that is not auth.SealKeySize bytes in hex.
var errBadKey = fmt.Errorf("%s must be %d hex characters", envSessionKey, hex.EncodedLen(auth.SealKeySize))

func main() {
	tu, err := parseFlags(os.Args[1:], os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	a, err := newAuth(db, logMailer{}, tu)
	if err != nil {
		log.Fatal(err) // a refused combination fails here, not in production
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// parseFlags reads the switches. The stateless key comes from the
// environment, or is random for this run.
func parseFlags(args []string, getenv func(string) string) (tuning, error) {
	var tu tuning
	var kv bool
	fs := flag.NewFlagSet("session-tuning", flag.ContinueOnError)
	fs.BoolVar(&tu.NoIP, "no-ip", false, "keep no IP address or user agent with a session")
	fs.BoolVar(&kv, "kv", false, "keep sessions and rate counters in an in-memory key-value store")
	fs.BoolVar(&tu.Deferred, "deferred", false, "reads never slide the expiry; POST /auth/session/refresh does")
	fs.BoolVar(&tu.Stateless, "stateless", false, "seal the session into the token; no session row")
	fs.IntVar(&tu.Version, "version", 0, "stateless token version; raising it signs everyone out")
	fs.DurationVar(&tu.ReadEvery, "read-every", 0, "stateless: load the user at most once per interval (0: every request)")
	if err := fs.Parse(args); err != nil {
		return tuning{}, err
	}
	if kv {
		tu.KV = newMemoryKV(time.Now)
	}
	if tu.Stateless {
		key, err := sessionKey(getenv(envSessionKey))
		if err != nil {
			return tuning{}, err
		}
		tu.Key = key
	}
	return tu, nil
}

// sessionKey decodes the stateless key, or makes a random one when none is
// set, and says so: a random key ends every session at restart.
func sessionKey(hexKey string) ([]byte, error) {
	if hexKey == "" {
		log.Printf("%s is not set: using a random key, so sessions end when the process does", envSessionKey)
		key := make([]byte, auth.SealKeySize)
		_, err := rand.Read(key)
		return key, err
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil || len(key) != auth.SealKeySize {
		return nil, errBadKey
	}
	return key, nil
}

// newAuth wires email and password sign-in, the session lifetime and the
// extras every wiring shares, then the switches tu turns on. The test builds
// every wiring through this same function.
//
//ds:def id=session-tuning-newauth-3c38e9ht
func newAuth(db *sql.DB, m email.Mailer, tu tuning) (*auth.Auth, error) {
	return auth.New(append([]auth.Option{
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
		),
		auth.WithSession(sessionConfig),
		auth.WithSessionExtras(sessionExtras),
		auth.WithMultiSession(maxDeviceAccounts),
		auth.WithDeviceSessionExtras(),
	}, switches(tu)...)...)
}

// switches turns tu into options. Each line is the complete wiring for its
// switch; an app keeps the ones it wants.
//
//ds:def id=session-tuning-switches-j4xj7s7k
func switches(tu tuning) []auth.Option {
	var opts []auth.Option
	if tu.Clock != nil {
		opts = append(opts, auth.WithClock(tu.Clock))
	}
	if tu.NoIP {
		opts = append(opts, auth.WithoutIPTracking())
	}
	if tu.KV != nil {
		opts = append(opts, auth.WithSecondaryStorage(tu.KV))
	}
	if tu.Deferred {
		opts = append(opts, auth.WithDeferredSessionRefresh())
	}
	if tu.Stateless {
		opts = append(opts, auth.WithStatelessSessions(tu.Key), auth.WithStatelessVersion(tu.Version))
		if tu.ReadEvery > 0 {
			opts = append(opts, auth.WithStatelessRefreshWithoutRead(tu.ReadEvery))
		}
	}
	return opts
}

// newHandler mounts the library's routes; the session routes are the page.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	return mux
}

// kvEntry is one value of memoryKV with the moment it stops existing; a zero
// expires means never.
type kvEntry struct {
	value   string
	expires time.Time
}

// memoryKV is an auth.SecondaryStorage in this process's memory: the four
// methods over a map, which is what an adapter over Redis, Memcached or a
// cloud KV implements. It is gone on restart and not shared by instances, so
// use it for tests and single-process tools only.
//
//ds:def id=session-tuning-memorykv-qaqbuguv
type memoryKV struct {
	mu   sync.Mutex
	now  func() time.Time
	data map[string]kvEntry
}

// newMemoryKV returns an empty store that reads time from now, the same clock
// the Auth uses, so a session and its key expire together.
func newMemoryKV(now func() time.Time) *memoryKV {
	return &memoryKV{now: now, data: map[string]kvEntry{}}
}

// live returns the entry under key unless it is absent or expired. The
// caller holds mu.
func (m *memoryKV) live(key string) (kvEntry, bool) {
	e, ok := m.data[key]
	if ok && !e.expires.IsZero() && !m.now().Before(e.expires) {
		delete(m.data, key)
		return kvEntry{}, false
	}
	return e, ok
}

// expiry turns a ttl into the moment it ends; 0 is never.
func (m *memoryKV) expiry(ttl time.Duration) time.Time {
	if ttl <= 0 {
		return time.Time{}
	}
	return m.now().Add(ttl)
}

// Get implements auth.SecondaryStorage.
func (m *memoryKV) Get(_ context.Context, key string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.live(key)
	return e.value, ok, nil
}

// Set implements auth.SecondaryStorage.
func (m *memoryKV) Set(_ context.Context, key, value string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = kvEntry{value: value, expires: m.expiry(ttl)}
	return nil
}

// Delete implements auth.SecondaryStorage.
func (m *memoryKV) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

// Increment implements auth.SecondaryStorage: a fixed window, so only the
// first hit sets the expiry.
func (m *memoryKV) Increment(_ context.Context, key string, ttl time.Duration) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.live(key)
	if !ok {
		e = kvEntry{value: "0", expires: m.expiry(ttl)}
	}
	n, err := strconv.ParseInt(e.value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("counter %s holds %q: %w", key, e.value, err)
	}
	n++
	e.value = strconv.FormatInt(n, 10)
	m.data[key] = e
	return n, nil
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including any link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
