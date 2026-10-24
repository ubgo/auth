// Command session-strategies is one email-and-password app whose sessions
// are stored and checked in whichever way the flags choose, so each wiring
// can be read, run and compared:
//
//	go run ./session-strategies                       # sessions in the database (the default)
//	go run ./session-strategies -store memory         # this process's memory
//	go run ./session-strategies -store redis          # Redis, with AUTH_REDIS_ADDR set
//	go run ./session-strategies -store custom         # a store of your own (logstore.go)
//	go run ./session-strategies -store stateless      # no store: the token carries the session
//	go run ./session-strategies -cache snapshot       # the client holds a sealed copy
//	go run ./session-strategies -cache memory         # a cache in this process
//	go run ./session-strategies -cache redis          # a cache in Redis
//	go run ./session-strategies -lifetimes by-client  # browsers 30 days, apps a year
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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	redisrate "github.com/ubgo/auth/contrib/redis"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "session-strategies.db"
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

// Environment variables the program reads.
const (
	// envRedisAddr is the Redis address the redis store and cache use, such
	// as 127.0.0.1:6379. Unset, those choices refuse to start.
	envRedisAddr = "AUTH_REDIS_ADDR"
	// envSessionKey is the key that seals stateless tokens and snapshots, as
	// 64 hex characters. Unset, a random key is used for this run only: every
	// session ends when the process does, and the log says so.
	envSessionKey = "AUTH_SESSION_KEY"
)

// storeChoice is where sessions live.
type storeChoice string

// The stores. Each is a complete wiring an app would copy.
const (
	// storeDatabase is the default: the auth_session table, which joins the
	// app's transactions and needs nothing else.
	storeDatabase storeChoice = "database"
	// storeMemory keeps sessions in this process: gone on restart, not shared
	// by instances. For tests and single-process tools.
	storeMemory storeChoice = "memory"
	// storeRedis keeps sessions in Redis, off the database and shared by
	// every instance.
	storeRedis storeChoice = "redis"
	// storeCustom is the app's own store: logstore.go wraps the memory store
	// and logs every call, which is what a store of your own looks like.
	storeCustom storeChoice = "custom"
	// storeStateless keeps no session anywhere: the token is the session,
	// sealed with the session key.
	storeStateless storeChoice = "stateless"
)

// storeChoices is the canonical order of the stores, for the usage text.
var storeChoices = []storeChoice{storeDatabase, storeMemory, storeRedis, storeCustom, storeStateless}

// cacheChoice is what sits in front of the session lookup.
type cacheChoice string

// The caches. Each skips the lookup for cacheTTL per request.
const (
	// cacheNone looks the session up on every request.
	cacheNone cacheChoice = "none"
	// cacheSnapshot hands the client a sealed copy of its session; the server
	// keeps nothing. A request with a valid copy touches no store at all.
	cacheSnapshot cacheChoice = "snapshot"
	// cacheMemory remembers looked-up sessions in this process.
	cacheMemory cacheChoice = "memory"
	// cacheRedis remembers them in Redis, shared by every instance.
	cacheRedis cacheChoice = "redis"
)

// cacheChoices is the canonical order of the caches, for the usage text.
var cacheChoices = []cacheChoice{cacheNone, cacheSnapshot, cacheMemory, cacheRedis}

// lifetimesChoice is how long a session lives.
type lifetimesChoice string

// The lifetime policies.
const (
	// lifetimesDefault gives every session auth.DefaultSessionConfig.
	lifetimesDefault lifetimesChoice = "default"
	// lifetimesByClient gives browsers (cookie) and apps (bearer) different
	// lifetimes, chosen when the session is created and kept with it.
	lifetimesByClient lifetimesChoice = "by-client"
)

// lifetimesChoices is the canonical order of the policies, for the usage text.
var lifetimesChoices = []lifetimesChoice{lifetimesDefault, lifetimesByClient}

// The numbers behind the choices.
const (
	// cacheTTL is how long a cached session is trusted before the store is
	// asked again: also how long a revoked session keeps working on a device
	// that holds a cached copy. The core clamps it to auth.MaxSessionCacheTTL.
	cacheTTL = 2 * time.Minute
	// memoryCacheEntries bounds the in-process cache.
	memoryCacheEntries = 10_000
	// day is a calendar day, for the lifetimes below.
	day = 24 * time.Hour
)

// The by-client lifetimes: a browser session slides for a week and ends after
// thirty days; an app on a phone stays signed in for a year of use.
var (
	webLifetime = auth.SessionLifetime{Idle: 7 * day, Max: 30 * day}
	appLifetime = auth.SessionLifetime{Idle: 90 * day, Max: 365 * day}
)

// config is one wiring: the three choices plus what they need from outside.
// The test fills it directly; main fills it from the flags and environment.
type config struct {
	Store     storeChoice
	Cache     cacheChoice
	Lifetimes lifetimesChoice
	// RedisAddr is required by the redis store and cache.
	RedisAddr string
	// Key seals stateless tokens and snapshots; auth.SealKeySize bytes.
	Key []byte
	// CustomStore is the store behind storeCustom. Nil means the logging
	// store over the memory store; the test passes a counting one.
	CustomStore auth.SessionStore
}

// Wiring errors, so a bad flag fails before the server listens.
var (
	errUnknownChoice = errors.New("unknown choice")
	errNoRedis       = errors.New(envRedisAddr + " is not set")
	errBadKey        = errors.New(envSessionKey + " must be 64 hex characters")
)

func main() {
	cfg, err := parseFlags(os.Args[1:], os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, err := newAuth(db, logMailer{}, cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	log.Printf("sessions: store=%s cache=%s lifetimes=%s", cfg.Store, cfg.Cache, cfg.Lifetimes)
	log.Printf("listening on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: newHandler(a), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}

// parseFlags reads the three choices from args and what they need from the
// environment. A choice the program does not know is refused here, not
// silently treated as the default.
func parseFlags(args []string, getenv func(string) string) (config, error) {
	fs := flag.NewFlagSet("session-strategies", flag.ContinueOnError)
	store := fs.String("store", string(storeDatabase), "where sessions live: "+joinChoices(storeChoices))
	cache := fs.String("cache", string(cacheNone), "what skips the lookup: "+joinChoices(cacheChoices))
	lifetimes := fs.String("lifetimes", string(lifetimesDefault), "how long sessions live: "+joinChoices(lifetimesChoices))
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	cfg := config{Store: storeChoice(*store), Cache: cacheChoice(*cache), Lifetimes: lifetimesChoice(*lifetimes), RedisAddr: getenv(envRedisAddr)}
	if err := errors.Join(checkChoice(cfg.Store, storeChoices), checkChoice(cfg.Cache, cacheChoices), checkChoice(cfg.Lifetimes, lifetimesChoices)); err != nil {
		return config{}, err
	}
	if cfg.Store == storeStateless || cfg.Cache == cacheSnapshot {
		key, err := sessionKey(getenv(envSessionKey))
		if err != nil {
			return config{}, err
		}
		cfg.Key = key
	}
	return cfg, nil
}

// checkChoice refuses a value outside the known set.
func checkChoice[T ~string](v T, known []T) error {
	for _, k := range known {
		if v == k {
			return nil
		}
	}
	return fmt.Errorf("%w: %q, want one of %s", errUnknownChoice, string(v), joinChoices(known))
}

// joinChoices lists a set for the usage text.
func joinChoices[T ~string](known []T) string {
	names := make([]string, len(known))
	for i, k := range known {
		names[i] = string(k)
	}
	return strings.Join(names, "|")
}

// sessionKey decodes the sealing key from the environment, or makes one for
// this run when none is set. A key that is set but wrong is refused: a typo
// must not silently become a fresh key that ends every session.
func sessionKey(hexKey string) ([]byte, error) {
	if hexKey == "" {
		key := make([]byte, auth.SealKeySize)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		log.Printf("WARN %s is not set: using a random key for this run, so every session ends when the process does", envSessionKey)
		return key, nil
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil || len(key) != auth.SealKeySize {
		return nil, errBadKey
	}
	return key, nil
}

// newAuth wires the app: the plugins are the quick start's, and the session
// options come from the configuration. The test builds every wiring through
// this same function.
func newAuth(db *sql.DB, m email.Mailer, cfg config) (*auth.Auth, error) {
	opts, err := sessionOptions(cfg)
	if err != nil {
		return nil, err
	}
	return auth.New(append([]auth.Option{
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
		),
	}, opts...)...)
}

// sessionOptions turns the configuration into auth options. Each case is the
// complete wiring for that choice; an app keeps the one it wants.
//
//ds:def id=sessionoptions-982a5xp5
func sessionOptions(cfg config) ([]auth.Option, error) {
	var opts []auth.Option
	var rdb *redis.Client
	if cfg.Store == storeRedis || cfg.Cache == cacheRedis {
		if cfg.RedisAddr == "" {
			return nil, errNoRedis
		}
		rdb = redis.NewClient(&redis.Options{Addr: cfg.RedisAddr})
		if err := rdb.Ping(context.Background()).Err(); err != nil {
			return nil, fmt.Errorf("redis at %s does not answer: %w", cfg.RedisAddr, err)
		}
	}

	switch cfg.Store {
	case storeDatabase:
		// Nothing to add: auth_session is the default.
	case storeMemory:
		opts = append(opts, auth.WithSessionStore(auth.NewMemorySessionStore()))
	case storeRedis:
		opts = append(opts, auth.WithSessionStore(redisrate.NewSessionStore(rdb)))
	case storeCustom:
		store := cfg.CustomStore
		if store == nil {
			store = newLoggingStore(auth.NewMemorySessionStore(), log.Default())
		}
		opts = append(opts, auth.WithSessionStore(store))
	case storeStateless:
		opts = append(opts, auth.WithStatelessSessions(cfg.Key))
	}

	switch cfg.Cache {
	case cacheNone:
	case cacheSnapshot:
		opts = append(opts, auth.WithSessionCache(auth.NewSnapshotCache(cfg.Key), cacheTTL))
	case cacheMemory:
		opts = append(opts, auth.WithSessionCache(auth.NewMemorySessionCache(memoryCacheEntries), cacheTTL))
	case cacheRedis:
		opts = append(opts, auth.WithSessionCache(redisrate.NewSessionCache(rdb), cacheTTL))
	}

	if cfg.Lifetimes == lifetimesByClient {
		opts = append(opts, auth.WithSessionPolicy(auth.ByCredential(webLifetime, appLifetime)))
	}
	return opts, nil
}

// newHandler mounts the library's routes and one page of the app's own.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux
}

// meResponse is what /me answers: who is signed in and how the session
// arrived, which is what the lifetime policy decides by.
type meResponse struct {
	ID         string          `json:"id"`
	Credential auth.Credential `json:"credential"`
	ExpiresAt  time.Time       `json:"expiresAt"`
}

// me is an app handler: RequireUser has already refused anyone signed out.
func me(w http.ResponseWriter, r *http.Request) {
	u := authhttp.MustUser(r)
	s, _ := auth.CurrentSession(r.Context())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meResponse{ID: u.ID, Credential: auth.RequestCredential(r.Context()), ExpiresAt: s.ExpiresAt}) // a client that hung up cannot be told
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
