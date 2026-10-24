// Package guard is a plugin that changes how other plugins' operations behave
// without touching them: it hooks password sign-in and sign-up, vetoes data
// writes, adds a condition every session must meet, and acts as a second
// factor. It is the reference for the three ways a plugin can intervene —
// operation hooks, data hooks and session rules — in one small package.
//
// The PIN is a demonstration of the second-factor contract, not a factor to
// ship: a real one is plugin/twofactor (TOTP) or plugin/passkey.
package guard

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
)

// Names the plugin registers.
const (
	PluginName = "guard"
	// ColSuspendedAt is set when the user pauses their account: a session
	// condition then refuses every request until it is cleared.
	ColSuspendedAt = "guard_suspended_at"
	// ColPINHash holds the hash of the user's PIN, or NULL when none is set;
	// a set PIN makes every sign-in need a second step.
	ColPINHash = "guard_pin_hash"
)

// The operations, by id.
const (
	EndpointSetPIN  auth.EndpointID = "guard.set-pin"
	EndpointVerify  auth.EndpointID = "guard.verify"
	EndpointSuspend auth.EndpointID = "guard.suspend"
)

// PIN bounds: digits only, long enough to not be guessed in the attempts a
// pending session's ten minutes allow, short enough to type.
const (
	MinPINLength = 4
	MaxPINLength = 12
)

// Errors with stable codes.
//
//ds:def id=guard-errorgroup-v7s28dt2 owner=@khanakia stability=stable
var (
	ErrDomainBlocked = auth.NewError("guard.domain_blocked", http.StatusBadRequest, "Sign up with a work or personal address, not a disposable one.")
	ErrSignInsPaused = auth.NewError("guard.sign_ins_paused", http.StatusServiceUnavailable, "Signing in is paused for maintenance. Try again in a few minutes.")
	ErrPINInvalid    = auth.NewError("guard.pin_invalid", http.StatusBadRequest, "Use 4 to 12 digits.")
	ErrPINWrong      = auth.NewError("guard.pin_wrong", http.StatusBadRequest, "That PIN is not right.")
)

// The plugin's columns on auth_user, typed.
var (
	SuspendedAt = sqlb.Col[*time.Time](auth.TableUser, ColSuspendedAt)
	PINHash     = sqlb.Col[*string](auth.TableUser, ColPINHash)
)

// PINRequest is the input of set-pin and verify.
type PINRequest struct {
	PIN string `json:"pin"`
}

// Plugin is the guard plugin. Build it with New.
type Plugin struct {
	a       *auth.Auth
	blocked []string
	paused  atomic.Bool
	// attempts counts sign-in attempts, failed ones included: the count is
	// recorded with AfterTx, which runs whether the call's transaction
	// committed or rolled back.
	attempts atomic.Int64
	// signedIn counts sign-ins that reached the client: recorded with
	// AfterCommit, which never runs for a rolled-back call.
	signedIn atomic.Int64

	setPIN  *auth.Op[PINRequest, auth.Done]
	verify  *auth.Op[PINRequest, auth.Done]
	suspend *auth.Op[struct{}, auth.Done]
}

// The optional interfaces this plugin implements, checked by the compiler.
//
//ds:def id=guard-interfaces-wyabf8bu owner=@khanakia stability=stable
var (
	_ auth.Initializer       = (*Plugin)(nil)
	_ auth.Dependent         = (*Plugin)(nil)
	_ auth.ColumnExtender    = (*Plugin)(nil)
	_ auth.OperationHooker   = (*Plugin)(nil)
	_ auth.DataHooker        = (*Plugin)(nil)
	_ auth.SessionChecker    = (*Plugin)(nil)
	_ auth.SecondFactor      = (*Plugin)(nil)
	_ auth.OperationProvider = (*Plugin)(nil)
)

// New builds the plugin. blockedDomains are refused at sign-up.
//
//ds:def id=guard-new-yjmedx8z owner=@khanakia stability=stable
func New(blockedDomains ...string) *Plugin {
	p := &Plugin{blocked: blockedDomains}
	p.setPIN = auth.Define(auth.OpInfo{ID: EndpointSetPIN, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/set-pin"}, p.doSetPIN)
	p.verify = auth.Define(auth.OpInfo{ID: EndpointVerify, Kind: auth.Mutation, Require: auth.PendingSecondFactor, Path: "/verify"}, p.doVerify)
	p.suspend = auth.Define(auth.OpInfo{ID: EndpointSuspend, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/suspend"}, p.doSuspend)
	return p
}

// Name is the only method every plugin must have.
func (p *Plugin) Name() string { return PluginName }

// Init keeps the core handle.
func (p *Plugin) Init(a *auth.Auth) error {
	p.a = a
	return nil
}

// Requires names the plugins whose operations this one hooks. auth.New
// refuses the list without them, instead of a hook that silently never runs.
//
//ds:def id=guard-requires-sr5wkkdp owner=@khanakia stability=stable
func (p *Plugin) Requires() []string { return []string{password.PluginName, email.PluginName} }

// Columns adds the two flags to auth_user; the core writes their migrations.
//
//ds:def id=guard-columns-7dyww6fr owner=@khanakia stability=stable
func (p *Plugin) Columns() []auth.ColumnExtension {
	return []auth.ColumnExtension{
		{Table: auth.TableNameUser, Name: ColSuspendedAt, Type: auth.ColumnTimestamp, Nullable: true},
		{Table: auth.TableNameUser, Name: ColPINHash, Type: auth.ColumnText, Nullable: true},
	}
}

// Pause stops sign-ins until Resume; the Before hook answers ErrSignInsPaused.
func (p *Plugin) Pause()  { p.paused.Store(true) }
func (p *Plugin) Resume() { p.paused.Store(false) }

// Attempts returns how many sign-ins were tried, and SignedIn how many
// succeeded. The difference between the two counters is the point of
// AfterTx versus AfterCommit.
func (p *Plugin) Attempts() int64 { return p.attempts.Load() }
func (p *Plugin) SignedIn() int64 { return p.signedIn.Load() }

// OperationHooks run around password sign-in: Before can refuse the call
// outright, After sees the result and can still fail it (its effects are then
// dropped, so no cookie leaks out).
//
//ds:def id=guard-ophooks-gxn9sxkv owner=@khanakia stability=stable
func (p *Plugin) OperationHooks() []auth.OperationHook {
	return []auth.OperationHook{{
		Match: []auth.EndpointID{password.EndpointSignIn},
		Before: func(ctx context.Context, _ *auth.Call) error {
			// The count must survive a wrong password, which fails the call
			// and rolls its transaction back: AfterTx runs either way.
			p.a.AfterTx(ctx, func(context.Context) { p.attempts.Add(1) })
			if p.paused.Load() {
				return ErrSignInsPaused
			}
			return nil
		},
		After: func(ctx context.Context, _ *auth.Call, result any) error {
			// result is the operation's own output; a hook that matches one
			// operation asserts its type.
			if r, ok := result.(password.SignInResult); ok && !r.SecondFactorRequired {
				// Counted only once the session is committed: a rollback
				// after this hook must not count a sign-in that never was.
				p.a.AfterCommit(ctx, func(context.Context) { p.signedIn.Add(1) })
			}
			return nil
		},
	}}
}

// DataHooks veto an identity whose domain is blocked, inside the sign-up's
// transaction: the user row written a moment earlier is rolled back with it.
//
//ds:def id=guard-datahooks-j8sk38hw owner=@khanakia stability=stable
func (p *Plugin) DataHooks() auth.DataHooks {
	return auth.DataHooks{Identity: auth.TableHooks[auth.Identity]{
		BeforeCreate: func(_ context.Context, _ sqlb.DBTX, idn *auth.Identity) error {
			if idn.Kind != email.KindEmail {
				return nil
			}
			for _, d := range p.blocked {
				if strings.HasSuffix(idn.Value, "@"+d) {
					return ErrDomainBlocked
				}
			}
			return nil
		},
	}}
}

// SessionPredicates refuses every session of a suspended user, on the next
// request: the condition is part of the session lookup itself. It names
// only auth_user, so it works with every session store and in stateless mode.
//
//ds:def id=guard-sessionpredicates-bhn849gb owner=@khanakia stability=stable
func (p *Plugin) SessionPredicates() []sqlb.Predicate {
	return []sqlb.Predicate{sqlb.IsNull(SuspendedAt)}
}

// SecondFactorRequired makes the sign-in of a user with a PIN pending until
// verify promotes it.
//
//ds:def id=guard-secondfactor-yxtthcug owner=@khanakia stability=stable
func (p *Plugin) SecondFactorRequired(ctx context.Context, userID string) (bool, error) {
	var hash *string
	if err := p.a.LoadUserColumns(ctx, userID, sqlb.Bind(PINHash, &hash)); err != nil {
		return false, err
	}
	return hash != nil, nil
}

// Lifetimes by how much the sign-in proved. A session that passed the PIN
// gets the client's lifetime, a browser's or an app's; one proven by the
// password alone lives a day, so a leaked password keeps working for hours
// rather than months.
//
//ds:def id=guard-lifetimes-v6b73gyd owner=@khanakia stability=stable
var (
	WebLifetime       = auth.SessionLifetime{Idle: 7 * 24 * time.Hour, Max: 365 * 24 * time.Hour}
	AppLifetime       = auth.SessionLifetime{Idle: 90 * 24 * time.Hour, Max: 365 * 24 * time.Hour}
	OneFactorLifetime = auth.SessionLifetime{Idle: 24 * time.Hour, Max: 24 * time.Hour}
)

// SessionPolicy is a policy of the plugin's own, for auth.WithSessionPolicy.
// It runs when a session is created, after Init, so p.a is set; a policy that
// needs a row loads it through ctx, which carries the sign-in's transaction.
//
//ds:def id=guard-sessionpolicy-7n2k4vqd owner=@khanakia stability=stable
func (p *Plugin) SessionPolicy() auth.SessionPolicy {
	byClient := auth.ByCredential(WebLifetime, AppLifetime)
	return func(ctx context.Context, in auth.SessionPolicyInput) auth.SessionLifetime {
		var hash *string
		if err := p.a.LoadUserColumns(ctx, in.UserID, sqlb.Bind(PINHash, &hash)); err != nil || hash == nil {
			return OneFactorLifetime
		}
		return byClient(ctx, in)
	}
}

// Operations lists the operations for every transport.
func (p *Plugin) Operations() []auth.Operation {
	return []auth.Operation{p.setPIN, p.verify, p.suspend}
}

// doSetPIN stores the PIN's hash. FreshSignIn: a stolen laptop with an old
// session must not be able to add a factor the owner does not know.
//
//ds:def id=guard-dosetpin-wjxw9abv owner=@khanakia stability=stable
func (p *Plugin) doSetPIN(ctx context.Context, c *auth.Call, in PINRequest) (auth.Done, error) {
	if !validPIN(in.PIN) {
		return auth.Done{}, ErrPINInvalid
	}
	h := hashPIN(c.User.ID, in.PIN)
	return auth.Done{OK: true}, auth.SetUserColumn(ctx, p.a, PluginName, c.User.ID, PINHash, &h)
}

// doVerify runs with the pending session, the only kind a PendingSecondFactor
// operation sees, and promotes it when the PIN matches.
//
//ds:def id=guard-doverify-p7k3rc4g owner=@khanakia stability=stable
func (p *Plugin) doVerify(ctx context.Context, c *auth.Call, in PINRequest) (auth.Done, error) {
	var hash *string
	if err := p.a.LoadUserColumns(ctx, c.Session.UserID, sqlb.Bind(PINHash, &hash)); err != nil {
		return auth.Done{}, err
	}
	if hash == nil || subtle.ConstantTimeCompare([]byte(*hash), []byte(hashPIN(c.Session.UserID, in.PIN))) != 1 {
		return auth.Done{}, ErrPINWrong
	}
	if _, err := p.a.PromoteSession(ctx, c); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, nil
}

// doSuspend pauses the account: every session stops at its next lookup. A
// request served from a SessionCache is not looked up, so with a cache the
// pause reaches a device only when its entry expires (the cache TTL); the
// plugin has no way to drop another device's entry, and only the core's
// sign-out drops this one.
//
//ds:def id=guard-dosuspend-49jufxqz owner=@khanakia stability=stable
func (p *Plugin) doSuspend(ctx context.Context, c *auth.Call, _ struct{}) (auth.Done, error) {
	now := p.a.Now()
	return auth.Done{OK: true}, auth.SetUserColumn(ctx, p.a, PluginName, c.User.ID, SuspendedAt, &now)
}

// validPIN is MinPINLength to MaxPINLength digits.
func validPIN(pin string) bool {
	if len(pin) < MinPINLength || len(pin) > MaxPINLength {
		return false
	}
	for _, r := range pin {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// hashPIN binds the PIN to its user, so equal PINs hash apart.
func hashPIN(userID, pin string) string {
	sum := sha256.Sum256([]byte(userID + ":" + pin))
	return hex.EncodeToString(sum[:])
}
