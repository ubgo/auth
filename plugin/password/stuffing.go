package password

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/ubgo/auth"
)

// StuffingPolicy configures GuardCredentialStuffing for an embedded library:
// it spots password guessing spread over many IPs and accounts, which the
// per-IP and per-identifier rate rules cannot see, because each address and
// each account only sees a few tries.
type StuffingPolicy struct {
	// PasswordFailures is how many failed sign-ins with one password, across
	// every account and every IP, refuse that password for the rest of the
	// Window: password spraying, one common password tried against many
	// accounts. 0 is DefaultStuffingPasswordFailures.
	PasswordFailures int
	// GlobalFailures is how many failed sign-ins across every account and
	// IP, per Window, refuse every password sign-in for the rest of it: a
	// stuffing run with leaked pairs, where each pair is tried once. 0 turns
	// the global rule off, the default, because it refuses legitimate users
	// too while an attack lasts.
	GlobalFailures int
	// Window is how long failures are counted and a refusal lasts. 0 is
	// DefaultStuffingWindow.
	Window time.Duration
	// LogOnly counts and logs a warning when a threshold is crossed but
	// refuses nothing: Sentinel's "log" action, for tuning the thresholds
	// against real traffic before turning the refusal on.
	LogOnly bool
}

// Defaults of StuffingPolicy.
const (
	// DefaultStuffingPasswordFailures failures of one password in a window
	// refuse it. Ten, because a person mistyping their own password fails a
	// few times, while a spray tries the same password against hundreds of
	// accounts.
	//
	//ds:def id=password-stuffing-defaults-7qk2wn5m owner=@khanakia stability=stable
	DefaultStuffingPasswordFailures = 10
	// DefaultStuffingWindow is the counting window and the refusal's length.
	DefaultStuffingWindow = 15 * time.Minute
)

// stuffingKeyLabel derives the HMAC key the password is counted under, so the
// rate store never holds the password or a hash anyone could test guesses
// against without the app's secret.
const stuffingKeyLabel = "password.stuffing"

// Rate-store keys of the guard; the core hashes them again before storing.
const (
	stuffingPasswordKey = "password.stuffing.password|"
	stuffingGlobalKey   = "password.stuffing.global"
)

// WarnCredentialStuffing is logged at every start while the guard refuses
// (not LogOnly): it refuses legitimate users who share a sprayed password,
// and under GlobalFailures every user while an attack lasts.
const WarnCredentialStuffing = "password: GuardCredentialStuffing is on: a password that failed on many accounts is refused for everyone who uses it, and with GlobalFailures every password sign-in is refused while failures exceed the limit"

// GuardCredentialStuffing turns on the guard (off by default). Each failed
// password sign-in, for an account that exists or not, is counted twice in
// the core's rate store: under a keyed HMAC of the password (the key derived
// from auth.WithSecret, so the store never holds the password) and, with
// GlobalFailures, under one global key. A sign-in whose password is over its
// limit, or any sign-in while the global count is over its limit, is refused
// with the core's 429 auth.rate_limited before the password is checked, so the
// answer never tells a guesser whether a refused guess was right.
//
// Risk, and why it is opt-in: everyone whose password is the sprayed one
// cannot sign in for the window, and the global rule refuses every user for
// as long as an attack keeps the failures up. Needs auth.WithSecret and a
// rate store that can read a count without adding to it (an auth.RatePeeker:
// the core's memory, database and storage stores, and contrib/redis; auth.New
// fails with auth.ErrRatePeekUnsupported otherwise), shared across instances.
func GuardCredentialStuffing(pol StuffingPolicy) Option {
	return func(p *Plugin) { p.stuffing = &stuffingGuard{pol: pol} }
}

// stuffingGuard is the running guard: the policy with its defaults filled and
// the HMAC key, set by init.
type stuffingGuard struct {
	pol  StuffingPolicy
	key  []byte
	core *auth.Auth
}

// validate checks the policy and that a key can be derived.
func (g *stuffingGuard) validate(c *auth.Config) error {
	if g.pol.PasswordFailures < 0 || g.pol.GlobalFailures < 0 || g.pol.Window < 0 {
		return fmt.Errorf("%w: GuardCredentialStuffing limits and window cannot be negative", auth.ErrBadOperation)
	}
	if _, err := c.DeriveKeys(stuffingKeyLabel); err != nil {
		return fmt.Errorf("password: GuardCredentialStuffing: %w", err)
	}
	return nil
}

// init refuses a rate store that cannot read a count without adding to it,
// fills the defaults, derives the key and warns when the guard refuses.
func (g *stuffingGuard) init(a *auth.Auth) error {
	if g.pol.PasswordFailures == 0 {
		g.pol.PasswordFailures = DefaultStuffingPasswordFailures
	}
	if g.pol.Window == 0 {
		g.pol.Window = DefaultStuffingWindow
	}
	if !a.CanPeekRates() {
		return fmt.Errorf("password: GuardCredentialStuffing: %w", auth.ErrRatePeekUnsupported)
	}
	keys, err := a.Config().DeriveKeys(stuffingKeyLabel)
	if err != nil {
		return err
	}
	// The current secret's key: after a rotation the counts start again,
	// which only shortens one window.
	g.key, g.core = keys[0], a
	if !g.pol.LogOnly {
		a.Logger().Warn(WarnCredentialStuffing)
	}
	return nil
}

// passwordKey is the rate-store key of one password: an HMAC under the
// guard's key, never the password.
func (g *stuffingGuard) passwordKey(pw Secret) string {
	m := hmac.New(sha256.New, g.key)
	m.Write([]byte(pw.Reveal()))
	return stuffingPasswordKey + hex.EncodeToString(m.Sum(nil))
}

// check refuses a sign-in while its password, or every sign-in, is over its
// limit. It reads the counts without adding to them, so a correct password
// is never counted, and it runs before the password is checked, for known
// and unknown accounts alike.
func (g *stuffingGuard) check(ctx context.Context, pw Secret) error {
	n, err := g.core.RatePeek(ctx, g.passwordKey(pw), g.pol.Window)
	if err != nil {
		return err
	}
	if n >= g.pol.PasswordFailures && !g.pol.LogOnly {
		return auth.RateLimitedFor(g.pol.Window)
	}
	if g.pol.GlobalFailures == 0 {
		return nil
	}
	n, err = g.core.RatePeek(ctx, stuffingGlobalKey, g.pol.Window)
	if err != nil {
		return err
	}
	if n >= g.pol.GlobalFailures && !g.pol.LogOnly {
		return auth.RateLimitedFor(g.pol.Window)
	}
	return nil
}

// failed counts one failed sign-in. The rate stores write outside the
// sign-in's transaction (the database store through its own connection), so
// the refusal's rollback does not take the count with it. Crossing a limit
// logs a warning once per window; a store failure is logged, since the answer
// is already ErrInvalidCredentials.
func (g *stuffingGuard) failed(ctx context.Context, pw Secret) {
	n, err := g.core.RateHit(ctx, g.passwordKey(pw), g.pol.Window)
	if err != nil {
		g.core.Logger().Error("password: count a failed sign-in", "error", err)
		return
	}
	if n == g.pol.PasswordFailures {
		g.core.Logger().Warn("password: one password failed on many accounts (password spraying)", "failures", n, "window", g.pol.Window)
		g.emit(ctx, auth.ScopePassword, n)
	}
	if g.pol.GlobalFailures == 0 {
		return
	}
	n, err = g.core.RateHit(ctx, stuffingGlobalKey, g.pol.Window)
	if err != nil {
		g.core.Logger().Error("password: count a failed sign-in", "error", err)
		return
	}
	if n == g.pol.GlobalFailures {
		g.core.Logger().Warn("password: failed sign-ins across all accounts passed the limit (credential stuffing)", "failures", n, "window", g.pol.Window)
		g.emit(ctx, auth.ScopeGlobal, n)
	}
}

// emit reports a limit crossing to the security event stream: once per window
// and scope, the moment the count reaches the limit, not on every refusal that
// follows, so an attack is one event and not one per blocked request. The
// outcome is blocked when the guard now refuses and logged under LogOnly.
func (g *stuffingGuard) emit(ctx context.Context, scope string, failures int) {
	outcome := auth.RateOutcomeBlocked
	if g.pol.LogOnly {
		outcome = auth.RateOutcomeLogged
	}
	e := auth.SecurityEvent{
		Kind: auth.SecurityCredentialStuffing, Severity: auth.SeverityAlert, Outcome: outcome,
		Attrs: map[string]string{auth.AttrScope: scope, auth.AttrFailures: strconv.Itoa(failures), auth.AttrWindow: g.pol.Window.String()},
	}
	if info, ok := auth.OperationOf(ctx); ok {
		e.Op = info.ID
	}
	g.core.EmitSecurity(e)
}
