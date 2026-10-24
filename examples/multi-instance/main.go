// Command multi-instance runs two instances of one app on one database, the
// way a deployment behind a load balancer does, and shows that they share
// the rate limits: five wrong passwords spread across both instances lock the
// account on both.
//
//	go run ./multi-instance
//
// Instance A listens on localhost:8081 and instance B on localhost:8082. They
// are two *auth.Auth values in one process so the demo is one command; in
// production each is its own process on its own machine, and nothing here
// changes. Both use the public URL of the load balancer, http://localhost:8081.
//
// The counters live in the database (auth.WithDBRateStore), which needs no
// new infrastructure. Set AUTH_REDIS_ADDR (for example 127.0.0.1:6379) to
// count them in Redis instead, through contrib/redis.
package main

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
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
	// dbFile is the SQLite database both instances use, created next to where
	// you run the program. Any engine works; with Postgres or MySQL the
	// instances would be on separate machines.
	dbFile = "multi-instance.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
	// envRedisAddr names the variable that switches the counters to Redis.
	envRedisAddr = "AUTH_REDIS_ADDR"
	// instanceHeader is a response header naming the instance that answered,
	// so the demo shows the load balancer's choice.
	instanceHeader = "X-Instance"
)

var (
	// port is the port the app listens on: 8081, or $PORT when it is set, so
	// two examples can run side by side.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	// portB is instance B's port: 8082, or $PORT_B when it is set; instance A
	// takes $PORT.
	portB = cmp.Or(os.Getenv("PORT_B"), "8082")
	// addrA and addrB are where the two instances listen: this machine only,
	// for development.
	addrA = "localhost:" + port
	addrB = "localhost:" + portB
	// baseURL is the app's public URL, the load balancer's, which both
	// instances share. Its origin is the only one allowed to send
	// cookie-authenticated POSTs, whichever instance receives them.
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

// instance is one app instance: the address it listens on and its name.
type instance struct {
	name string
	addr string
}

// instances are the two the demo runs.
var instances = []instance{{name: "A", addr: addrA}, {name: "B", addr: addrB}}

func main() {
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	rates, err := rateStore(os.Getenv(envRedisAddr))
	if err != nil {
		log.Fatal(err)
	}

	errs := make(chan error, len(instances))
	for i, in := range instances {
		a, err := newAuth(db, logMailer{}, rates)
		if err != nil {
			log.Fatal(err)
		}
		defer a.Close()
		if i == 0 {
			// One instance migrates; in production the deploy job runs
			// "auth migrate" once (see the cli example).
			if _, err := a.Migrate(context.Background()); err != nil {
				log.Fatal(err)
			}
		}
		srv := &http.Server{Addr: in.addr, Handler: newHandler(a, in.name), ReadHeaderTimeout: readHeaderTimeout}
		log.Printf("instance %s listening on %s", in.name, in.addr)
		go func() { errs <- srv.ListenAndServe() }()
	}
	log.Fatal(<-errs)
}

// rateStore picks where the instances count rate limits: in Redis when
// redisAddr is set, otherwise in the auth database.
//
//ds:def id=ratestore-7z8zumcj
func rateStore(redisAddr string) (auth.Option, error) {
	if redisAddr == "" {
		log.Printf("rate limits: counted in the database table %s", auth.TableNameRateLimit)
		return auth.WithDBRateStore(), nil
	}
	client := redis.NewClient(&redis.Options{Addr: redisAddr})
	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("redis at %s does not answer: %w", redisAddr, err)
	}
	log.Printf("rate limits: counted in Redis at %s", redisAddr)
	return auth.WithRateStore(redisrate.New(client)), nil
}

// newAuth builds one instance. Every instance gets the same plugins, the same
// database and the same rate store; only the store makes their limits shared.
//
//ds:def id=newauth-5nsvtcd9
func newAuth(db *sql.DB, m email.Mailer, rates auth.Option) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		rates,
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
		),
	)
}

// newHandler is one instance's routes: the library's, and /me. Every response
// says which instance answered.
func newHandler(a *auth.Auth, name string) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(instanceHeader, name)
		mux.ServeHTTP(w, r)
	})
}

// meResponse is what /me answers.
type meResponse struct {
	ID    string `json:"id"`
	Hello string `json:"hello"`
}

// me is an app handler: RequireUser has already refused anyone signed out.
// Sessions live in the database, so a cookie issued by one instance works on
// the other.
func me(w http.ResponseWriter, r *http.Request) {
	u := authhttp.MustUser(r)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meResponse{ID: u.ID, Hello: u.Name}) // a client that hung up cannot be told
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
