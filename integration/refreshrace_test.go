package integration

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauthprovider"
	"github.com/ubgo/sqlb"
)

// Two refreshes in flight with the same refresh token, the case a relying
// party with two tabs or two instances meets every time its access token
// expires: both present the token before either has the rotated pair.
//
// The schedule is forced, not hoped for. The first refresh is held inside
// its transaction after it has marked the token rotated (ClientAccess runs
// there, at issue), so its rotation is written and uncommitted. The second
// refresh then starts, and the first is released only once the second is
// committed to the interleaving:
//   - on Postgres and MySQL, once the second begins its own rotate UPDATE
//     (seen through the tracer). It has read the database before the first
//     committed and rotates after it, so on MySQL's REPEATABLE READ a plain
//     re-read of the row still sees it unrotated: the race this file pins.
//   - on SQLite, once the second's operation starts. SQLite has one writer:
//     opened as production opens it, with _txlock=immediate, the second
//     transaction's BEGIN waits for the first to commit, so the two are
//     serialized whichever way they meet and only the outcome is checked.
//     (With the default deferred BEGIN the second would read, then fail its
//     write with SQLITE_BUSY: a configuration error, not this race.)

// refreshRaceTimeout bounds each wait of the forced schedule, so a schedule
// that never happens fails the test instead of hanging it.
const refreshRaceTimeout = 10 * time.Second

// refreshReuseWindow is the RefreshReuseInterval of the window case: far
// longer than the test, so only the race decides, never the clock.
const refreshReuseWindow = 30 * time.Second

// refreshRace holds the first refresh inside its transaction and releases it
// when the second starts rotating.
type refreshRace struct {
	// armed makes the next ClientAccess call the held one.
	armed atomic.Bool
	// holding is closed when the first refresh is held, rotated and not
	// committed; release lets it go on.
	holding, release chan struct{}
	// watching makes the tracer report the second refresh reaching the
	// point where the first may go on (committed), by closing committed once.
	watching  atomic.Bool
	committed chan struct{}
	once      sync.Once
	// marks reports whether a span start is that point; see the file
	// comment for why it differs by engine.
	marks func(auth.SpanInfo) bool
}

func newRefreshRace(engine string) *refreshRace {
	r := &refreshRace{holding: make(chan struct{}), release: make(chan struct{}), committed: make(chan struct{})}
	tokenTable := tbl(oauthprovider.TableNameToken)
	r.marks = func(s auth.SpanInfo) bool {
		return s.Kind == auth.SpanDatabase && s.DBOperation == tracedUpdate && s.Table == tokenTable
	}
	if engine == auth.EngineSQLite {
		r.marks = func(s auth.SpanInfo) bool { return s.Kind == auth.SpanOperation }
	}
	return r
}

// access is the ClientAccess rule: it allows everyone, and holds the armed
// call until release.
func (r *refreshRace) access(context.Context, oauthprovider.Client, oauthprovider.AccessUser) error {
	if r.armed.CompareAndSwap(true, false) {
		close(r.holding)
		<-r.release
	}
	return nil
}

// noSpan is the span refreshRace hands back: it traces nothing.
type noSpan struct{}

func (noSpan) End(error) {}

// tracedUpdate is SpanInfo.DBOperation for an UPDATE statement.
const tracedUpdate = "update"

// Start sees every span start; while watching, the only call running is the
// second refresh (the first is held), so the first marked span is its.
func (r *refreshRace) Start(ctx context.Context, s auth.SpanInfo) (context.Context, auth.Span) {
	if r.watching.Load() && r.marks(s) {
		r.once.Do(func() { close(r.committed) })
	}
	return ctx, noSpan{}
}

// wait fails the test when ch is not closed within refreshRaceTimeout.
func (r *refreshRace) wait(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(refreshRaceTimeout):
		t.Fatalf("the forced schedule stalled waiting for %s", what)
	}
}

// refreshOutcome is one refresh's answer.
type refreshOutcome struct {
	res oauthprovider.TokenResponse
	err error
}

// sqliteImmediate is the transaction mode production SQLite apps open with:
// BEGIN IMMEDIATE takes the write lock at once, so a second writer waits
// (busy_timeout) rather than failing after it has read.
const sqliteImmediate = "&_txlock=immediate"

// eachRaceEngine is eachEngine with SQLite opened in sqliteImmediate mode.
func eachRaceEngine(t *testing.T, fn func(t *testing.T, e *env)) {
	for _, eng := range engines(t) {
		t.Run(eng.name, func(t *testing.T) {
			var db *sql.DB
			var d sqlb.Dialect
			if eng.name == auth.EngineSQLite {
				db, d = openSQLiteDSN(t, sqlitePragmas+sqliteImmediate)
			} else {
				db, d = eng.open(t)
			}
			fn(t, newEnv(t, eng.name, db, d))
		})
	}
}

// openSQLiteDSN is openSQLite with the given URI query.
func openSQLiteDSN(t *testing.T, query string) (*sql.DB, sqlb.Dialect) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), "auth.db"), query))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, sqlb.SQLiteDialect{}
}

// raceRefresh issues a pair, then runs the two refreshes of it on the forced
// schedule and returns the pair and both answers, first then second.
func raceRefresh(t *testing.T, e *env, opts ...oauthprovider.Option) (opEnv, oauthprovider.Registration, oauthprovider.TokenResponse, refreshOutcome, refreshOutcome) {
	t.Helper()
	r := newRefreshRace(e.engine)
	o := newOPEnvWith(t, e, []auth.Option{auth.WithTracer(r)}, append([]oauthprovider.Option{oauthprovider.ClientAccess(r.access)}, opts...)...)
	reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
	tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
	req := oauthprovider.TokenRequest{GrantType: oauthprovider.GrantRefreshToken, RefreshToken: tok.RefreshToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}

	first, second := make(chan refreshOutcome, 1), make(chan refreshOutcome, 1)
	r.armed.Store(true)
	go func() {
		res, err := o.op.Token(anon(o.a), req)
		first <- refreshOutcome{res, err}
	}()
	r.wait(t, r.holding, "the first refresh to rotate")
	r.watching.Store(true)
	go func() {
		res, err := o.op.Token(anon(o.a), req)
		second <- refreshOutcome{res, err}
	}()
	r.wait(t, r.committed, "the second refresh to start")
	close(r.release)
	return o, reg, tok, <-first, <-second
}

// Inside RefreshReuseInterval, the second of two concurrent refreshes gets a
// pair of its own and the family stays alive, on every engine: the second
// refresh must judge the window on the committed rotation, not on what its
// transaction read before the first committed.
//
//ds:def id=testoauthprovider-concurrentrefreshinsidewindow-k3v9pd2r owner=@khanakia stability=stable
func TestOAuthProvider_ConcurrentRefreshInsideReuseWindow(t *testing.T) {
	eachRaceEngine(t, func(t *testing.T, e *env) {
		o, _, _, first, second := raceRefresh(t, e, oauthprovider.RefreshReuseInterval(refreshReuseWindow))
		if first.err != nil {
			t.Fatalf("first refresh: %v", first.err)
		}
		if second.err != nil {
			t.Fatalf("second refresh inside the reuse window: %v, want a new pair", second.err)
		}
		if first.res.RefreshToken == second.res.RefreshToken || second.res.RefreshToken == "" {
			t.Fatalf("the second refresh's refresh token %q is not a pair of its own", second.res.RefreshToken)
		}
		for name, res := range map[string]oauthprovider.TokenResponse{"first": first.res, "second": second.res} {
			if _, err := o.op.VerifyAccessToken(context.Background(), res.AccessToken); err != nil {
				t.Errorf("the %s refresh's access token = %v, want valid (the family must stay alive)", name, err)
			}
		}
	})
}

// With the default RefreshReuseInterval of 0, the second of two concurrent
// refreshes is reuse: invalid_grant, and the whole family is revoked, the
// first refresh's new pair included (OAuth 2.1 section 4.3.1). The fix for
// the window case must not soften this.
//
//ds:def id=testoauthprovider-concurrentrefreshnowindow-r8m2xq5w owner=@khanakia stability=stable
func TestOAuthProvider_ConcurrentRefreshWithoutWindowRevokesFamily(t *testing.T) {
	eachRaceEngine(t, func(t *testing.T, e *env) {
		o, reg, _, first, second := raceRefresh(t, e)
		if first.err != nil {
			t.Fatalf("first refresh: %v", first.err)
		}
		if !errors.Is(second.err, oauthprovider.ErrInvalidGrant) {
			t.Fatalf("second refresh with no reuse window = %v, want invalid_grant", second.err)
		}
		if _, err := o.op.VerifyAccessToken(context.Background(), first.res.AccessToken); !errors.Is(err, oauthprovider.ErrInvalidToken) {
			t.Errorf("the first refresh's access token after the reuse = %v, want invalid_token", err)
		}
		next := oauthprovider.TokenRequest{GrantType: oauthprovider.GrantRefreshToken, RefreshToken: first.res.RefreshToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}
		if _, err := o.op.Token(anon(o.a), next); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
			t.Errorf("the first refresh's refresh token after the reuse = %v, want invalid_grant", err)
		}
	})
}

// With RefreshReplay, the second of two concurrent refreshes inside the
// window answers the first one's response, byte for byte, on every engine:
// the stored response must be read as committed, like the rotation, or on
// MySQL the second would miss it and issue a pair of its own.
//
//ds:def id=testoauthprovider-concurrentrefreshreplay-w4n7ct6h owner=@khanakia stability=stable
func TestOAuthProvider_ConcurrentRefreshReplaysFirstAnswer(t *testing.T) {
	eachRaceEngine(t, func(t *testing.T, e *env) {
		_, _, _, first, second := raceRefresh(t, e, oauthprovider.RefreshReuseInterval(refreshReuseWindow), oauthprovider.RefreshReplay(p1Sealer(t)))
		if first.err != nil || second.err != nil {
			t.Fatalf("first refresh = %v, second = %v; want both answered", first.err, second.err)
		}
		if second.res.AccessToken != first.res.AccessToken || second.res.RefreshToken != first.res.RefreshToken {
			t.Fatal("the second refresh got a pair of its own, want the first refresh's response replayed")
		}
	})
}
