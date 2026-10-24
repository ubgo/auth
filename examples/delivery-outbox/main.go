// Command delivery-outbox shows the three seams behind every mail and SMS
// the library sends: a durable outbox so a failed or interrupted send is
// retried instead of lost, the app's own background runner instead of one
// goroutine per message, and a verification store of the app's own instead
// of the auth_verification table.
//
//	AUTH_SECRET=$(openssl rand -hex 32) go run ./delivery-outbox
//
// The mailer here fails its first send on purpose, so the first sign-up's
// verification mail is only sent by the outbox retry about a minute later.
// Mail is printed to the log instead of sent.
package main

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
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
	dbFile = "delivery-outbox.db"
	// authPrefix is where the library's routes are mounted.
	authPrefix = "/auth"
	// readHeaderTimeout bounds how long a client may take to send headers, so
	// a slow client cannot hold a connection open forever.
	readHeaderTimeout = 5 * time.Second
	// shutdownTimeout bounds how long a stopping server waits for requests
	// in flight before it gives up on them.
	shutdownTimeout = 10 * time.Second
	// outboxEvery is how often the app calls SendOutbox. A failed row waits
	// at least auth.DeliveryRetryBase (a minute) before it is due again, so
	// polling more often than that only shortens the delay after it is due.
	outboxEvery = 15 * time.Second
	// workers is how many deliveries the pool sends at once: a mail server
	// that allows few connections is not flooded by a burst of sign-ups.
	workers = 4
	// queueSize is how many deliveries wait for a free worker before the
	// pool starts a goroutine for the overflow instead.
	queueSize = 64
	// demoFailures is how many sends the demo mailer fails before it works.
	demoFailures = 1
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	pool := newWorkerPool(workers, queueSize)
	defer pool.Close() // after a.Close, which waits for every delivery
	mailer := newFlakyMailer(logMailer{}, demoFailures)
	a, err := newAuth(db, []byte(os.Getenv(auth.EnvSecret)), mailer, pool.Run, newMapVerificationStore())
	if err != nil {
		log.Fatal(err) // a missing AUTH_SECRET fails here, not at the first mail
	}
	defer a.Close()
	if _, err := a.Migrate(ctx); err != nil {
		log.Fatal(err)
	}
	go runOutbox(ctx, a, outboxEvery)

	srv := &http.Server{Addr: addr, Handler: newHandler(a), ReadHeaderTimeout: readHeaderTimeout}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx) // the process is ending; a request that outlives the timeout is cut
	}()
	log.Printf("listening on %s", baseURL)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		log.Print(err)
	}
}

// newAuth wires email and password sign-up with the three delivery seams:
// WithDeliveryOutbox writes every mail to auth_delivery_outbox in the
// transaction that produced it (sealed with a key derived from the secret),
// WithBackground hands each post-commit send to run, and
// WithVerificationStore keeps the verify-email tokens in store. extra is for
// the test's clock. The test builds the app with the same function.
//
//ds:def id=delivery-outbox-wiring-fj73ekcs
func newAuth(db *sql.DB, secret []byte, m email.Mailer, run auth.BackgroundFunc, store auth.VerificationStore, extra ...auth.Option) (*auth.Auth, error) {
	return auth.New(append([]auth.Option{
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithSecret(secret),
		auth.WithDeliveryOutbox(),
		auth.WithBackground(run),
		auth.WithVerificationStore(store),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
		),
	}, extra...)...)
}

// newHandler mounts the library's routes.
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	return mux
}

// runOutbox calls SendOutbox every interval until ctx ends: it sends the
// messages whose first send failed, once their backoff has passed, and the
// ones a crashed process never sent. Several instances may run it at once;
// each row is claimed by one of them. "auth sweep" (authcli) does the same
// from a cron job instead of a loop.
//
//ds:def id=outbox-retry-loop-je8dw7qr
func runOutbox(ctx context.Context, a *auth.Auth, interval time.Duration) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		res, err := a.SendOutbox(ctx)
		if err != nil {
			log.Printf("outbox: %v", err)
			continue
		}
		if res.Sent+res.Failed > 0 {
			log.Printf("outbox: sent=%d failed=%d", res.Sent, res.Failed)
		}
	}
}

// poolTask is one unit of post-commit work waiting for a worker.
type poolTask struct {
	ctx context.Context
	run func(context.Context)
}

// workerPool is a fixed set of goroutines that runs the library's
// post-commit work (message delivery, background bookkeeping): the app's
// own runner, handed to auth.WithBackground as pool.Run. It counts what it
// ran so the test can see deliveries went through it.
//
//ds:def id=background-worker-pool-s3uzpqz2
type workerPool struct {
	tasks chan poolTask
	wg    sync.WaitGroup
	// ran counts tasks a worker ran; overflow counts tasks that found the
	// queue full and got a goroutine of their own.
	ran, overflow atomic.Int64
}

// newWorkerPool starts n workers reading a queue of size queue.
func newWorkerPool(n, queue int) *workerPool {
	p := &workerPool{tasks: make(chan poolTask, queue)}
	for range n {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			for t := range p.tasks {
				t.run(t.ctx)
				p.ran.Add(1)
			}
		}()
	}
	return p
}

// Run is the auth.BackgroundFunc. It must return at once, because the
// request is waiting on it, and it must never drop a task, because the
// library counts each one and WaitDeliveries (and Close) would wait forever
// for a dropped one. So a full queue does not block: the task gets its own
// goroutine, as it would without WithBackground.
//
//ds:def id=background-runner-u33536kg
func (p *workerPool) Run(ctx context.Context, task func(context.Context)) {
	select {
	case p.tasks <- poolTask{ctx: ctx, run: task}:
	default:
		p.overflow.Add(1)
		go task(ctx)
	}
}

// Close stops the workers once the queue is drained. Call it after
// auth.Close, which waits for every delivery; Run after Close panics.
func (p *workerPool) Close() {
	close(p.tasks)
	p.wg.Wait()
}

// mapVerificationStore keeps verification tokens in a map in this process:
// a stand-in for whatever store the app already runs (a cache, a document
// database). It keeps only the token's hash, as every store must, and
// passes github.com/ubgo/auth/verificationtest, which the test runs. A
// store outside the database joins no transaction; see
// auth.VerificationStore for what that gives up.
//
//ds:def id=custom-verification-store-t8h4nk2b
type mapVerificationStore struct {
	mu   sync.Mutex
	rows map[string]auth.Verification
}

// newMapVerificationStore returns an empty store.
func newMapVerificationStore() *mapVerificationStore {
	return &mapVerificationStore{rows: map[string]auth.Verification{}}
}

// storeKey files a token under its purpose and hash, so a token presented
// for another purpose is simply not found and is not spent.
func storeKey(purpose auth.Purpose, tokenHash []byte) string {
	return string(purpose) + ":" + hex.EncodeToString(tokenHash)
}

// Insert saves v under tokenHash.
func (s *mapVerificationStore) Insert(_ context.Context, v auth.Verification, tokenHash []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows[storeKey(v.Purpose, tokenHash)] = v
	return nil
}

// Consume spends a live token once: the lookup and the delete happen under
// one lock, so of two concurrent calls exactly one finds the row.
//
//ds:def id=verification-store-consume-yt8ygtxx
func (s *mapVerificationStore) Consume(_ context.Context, purpose auth.Purpose, tokenHash []byte, now time.Time) (auth.Verification, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := storeKey(purpose, tokenHash)
	v, ok := s.rows[key]
	if !ok || !v.ExpiresAt.After(now) {
		return auth.Verification{}, auth.ErrTokenInvalid
	}
	delete(s.rows, key)
	v.ConsumedAt = &now
	return v, nil
}

// ConsumeAll ends every token of purpose filed under identifier and issued
// up to now; a token issued later stays spendable.
func (s *mapVerificationStore) ConsumeAll(_ context.Context, purpose auth.Purpose, identifier string, now time.Time) error {
	s.deleteWhere(func(v auth.Verification) bool {
		return v.Purpose == purpose && v.Identifier == identifier && !v.CreatedAt.After(now)
	})
	return nil
}

// DeleteIdentifiers ends every token, of any purpose, filed under one of
// identifiers and issued up to now.
func (s *mapVerificationStore) DeleteIdentifiers(_ context.Context, identifiers []string, now time.Time) error {
	gone := make(map[string]bool, len(identifiers))
	for _, id := range identifiers {
		gone[id] = true
	}
	s.deleteWhere(func(v auth.Verification) bool { return gone[v.Identifier] && !v.CreatedAt.After(now) })
	return nil
}

// Sweep deletes the tokens that expired before cutoff. Spent tokens are
// already gone: Consume deletes them.
func (s *mapVerificationStore) Sweep(_ context.Context, cutoff time.Time) (int64, error) {
	return s.deleteWhere(func(v auth.Verification) bool { return v.ExpiresAt.Before(cutoff) }), nil
}

// Len reports how many tokens the store holds.
func (s *mapVerificationStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.rows)
}

// deleteWhere deletes every row match accepts and returns how many.
func (s *mapVerificationStore) deleteWhere(match func(auth.Verification) bool) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	for k, v := range s.rows {
		if match(v) {
			delete(s.rows, k)
			n++
		}
	}
	return n
}

// errMailerDown is what flakyMailer returns while it is failing.
var errMailerDown = errors.New("mailer: connection refused (simulated)")

// flakyMailer fails its first sends, as a mail API does during an outage,
// then passes mail to next. It exists to show the outbox retry.
//
//ds:def id=flaky-mailer-n9pdnye9
type flakyMailer struct {
	next email.Mailer
	// left is how many sends still fail; it goes negative once they are used.
	left atomic.Int64
}

// newFlakyMailer returns a mailer that fails failures sends, then works.
func newFlakyMailer(next email.Mailer, failures int) *flakyMailer {
	f := &flakyMailer{next: next}
	f.left.Store(int64(failures))
	return f
}

// Send fails while failures are left, then delegates.
func (f *flakyMailer) Send(ctx context.Context, m email.Mail) error {
	if f.left.Add(-1) >= 0 {
		return errMailerDown
	}
	return f.next.Send(ctx, m)
}

// logMailer prints mail instead of sending it. Replace it with SMTP, an email
// API or a queue.
type logMailer struct{}

// Send logs the message, including the link, so you can open it by hand.
func (logMailer) Send(_ context.Context, m email.Mail) error {
	log.Printf("mail to=%s subject=%q\n%s", m.To, m.Subject, m.Text)
	return nil
}
