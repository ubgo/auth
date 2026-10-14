package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// WithStatelessSessions makes the session token carry the session itself,
// sealed with the first key (SealKeySize bytes each, AES-256-GCM), so a request needs no
// session store and no session row. Every request still loads the user (one
// primary-key query) with the SessionChecker conditions, so a ban applies at
// once; DeleteUserSessions ("sign out everywhere", a password reset) sets
// auth_user.sessions_valid_after, which refuses every token issued before it.
//
// What stateless mode gives up, because the server holds nothing per session:
// a session cannot be listed beyond the request's own or revoked one by one
// (Sessions and DeleteSession answer ErrSessionsUnavailable), a sign-out on
// one device is only the cookie being cleared, and the token is longer than a
// stored session's (about 400 characters). Replacing the key is the global
// logout switch: every token sealed with the old key stops opening. To
// rotate WITHOUT signing everyone out, pass the new key first and the old
// one after it: new tokens are sealed with the first key and every key opens
// (KeyRing); drop the old key once its tokens have expired.
//
// WithStatelessSessions and WithSessionStore exclude each other; New refuses
// both, and refuses no key at all.
//
//ds:def id=opt-withstatelesssessions-56w8hk96 owner=@khanakia stability=stable
func WithStatelessSessions(keys ...[]byte) Option {
	return func(s *settings) { s.stateless, s.statelessKeys = true, keys }
}

// ErrSessionsUnavailable is answered where a deployment keeps no session list:
// stateless sessions cannot be listed beyond the current one or revoked one
// by one, because nothing about them exists on the server.
var ErrSessionsUnavailable = NewError("auth.sessions_unavailable", http.StatusConflict, "Sessions cannot be listed or ended one by one here.")

// statelessAAD binds a sealed session to its purpose, so a value sealed with
// the same key for anything else — a snapshot, a plugin's secret — cannot be
// presented as a session token.
const statelessAAD = "auth.session.v1"

// statelessSessions seals and opens session tokens. ring is built once at
// New from keys New has already checked, so sealing cannot fail on the key.
type statelessSessions struct {
	ring *KeyRing
	// version is what every token must carry; see WithStatelessVersion.
	version int
	// readEvery is WithStatelessRefreshWithoutRead's interval, already
	// clamped; 0 means every request loads the user, the default.
	readEvery time.Duration
}

// statelessClaims is the session as it travels in the token. Short JSON keys
// because the whole thing is a cookie; IP and user agent stay out, since the
// only session a stateless deployment can show is the request's own.
type statelessClaims struct {
	// Version is the WithStatelessVersion number the token was sealed under.
	Version    int       `json:"v,omitempty"`
	ID         string    `json:"id"`
	UserID     string    `json:"u"`
	CreatedAt  time.Time `json:"c"`
	ExpiresAt  time.Time `json:"e"`
	LastSeenAt time.Time `json:"l"`
	Pending    bool      `json:"p,omitempty"`
	// Tasks is Session.Tasks.
	Tasks          SessionTasks `json:"k,omitempty"`
	Transient      bool         `json:"t,omitempty"`
	ImpersonatedBy *string      `json:"i,omitempty"`
	IdleSeconds    int64        `json:"is,omitempty"`
	RefreshSeconds int64        `json:"rs,omitempty"`
	MaxExpiresAt   *time.Time   `json:"m,omitempty"`
	// ReauthenticatedAt is Session.ReauthenticatedAt: Reauthenticate
	// reseals the same session with it.
	ReauthenticatedAt *time.Time `json:"ra,omitempty"`
	// Data is the app's JSON (Session.Data). It rides in the token because
	// stateless mode has nowhere else; MaxSessionDataSize keeps the cookie
	// under the browsers' limit.
	Data AppData `json:"d,omitempty"`
	// Read is the user as the last full read found it, carried only under
	// WithStatelessRefreshWithoutRead; nil otherwise and in every token
	// sealed before a full read happened (a new sign-in, a rotation).
	Read *statelessRead `json:"r,omitempty"`
}

// statelessRead is the user a full read loaded, and when. A request within
// the read interval of At uses User instead of loading it; see
// WithStatelessRefreshWithoutRead.
type statelessRead struct {
	User User      `json:"u"`
	At   time.Time `json:"a"`
}

// seal returns the token that carries s and no read user. Base64url like
// every other token, so a transport treats it the same way; only its length
// differs.
func (st *statelessSessions) seal(s Session) (Token, error) { return st.sealWith(s, nil) }

// sealWith is seal carrying the user of the last full read, under
// WithStatelessRefreshWithoutRead.
func (st *statelessSessions) sealWith(s Session, read *statelessRead) (Token, error) {
	plain, err := json.Marshal(statelessClaims{
		Version: st.version,
		ID:      s.ID, UserID: s.UserID, CreatedAt: s.CreatedAt, ExpiresAt: s.ExpiresAt, LastSeenAt: s.LastSeenAt,
		Pending: s.SecondFactorPending, Tasks: s.Tasks, Transient: s.Transient, ImpersonatedBy: s.ImpersonatedBy,
		IdleSeconds: s.IdleSeconds, RefreshSeconds: s.RefreshSeconds, MaxExpiresAt: s.MaxExpiresAt,
		ReauthenticatedAt: s.ReauthenticatedAt, Data: s.Data, Read: read,
	})
	if err != nil {
		return "", fmt.Errorf("auth: encode session: %w", err)
	}
	return Token(base64.RawURLEncoding.EncodeToString(st.ring.sealRaw(plain, statelessAAD))), nil
}

// open returns the session a token carries, or ErrSessionNotFound for
// anything that does not open: a stored-session token, a tampered or foreign
// value, a token sealed with a previous key or under another version.
func (st *statelessSessions) open(t Token) (Session, error) {
	s, _, err := st.openWith(t)
	return s, err
}

// openWith is open that also returns the user of the last full read the
// token carries, or nil.
func (st *statelessSessions) openWith(t Token) (Session, *statelessRead, error) {
	raw, err := base64.RawURLEncoding.DecodeString(t.Reveal())
	if err != nil {
		return Session{}, nil, ErrSessionNotFound
	}
	plain, err := st.ring.openRaw(raw, statelessAAD)
	if err != nil {
		return Session{}, nil, ErrSessionNotFound
	}
	var c statelessClaims
	if err := json.Unmarshal(plain, &c); err != nil || c.Version != st.version {
		// A token from another version is a signed-out client, not an
		// attack: the same answer as an unknown token.
		return Session{}, nil, ErrSessionNotFound
	}
	return Session{
		ID: c.ID, UserID: c.UserID, CreatedAt: c.CreatedAt, ExpiresAt: c.ExpiresAt, LastSeenAt: c.LastSeenAt,
		SecondFactorPending: c.Pending, Tasks: c.Tasks, Transient: c.Transient, ImpersonatedBy: c.ImpersonatedBy,
		IdleSeconds: c.IdleSeconds, RefreshSeconds: c.RefreshSeconds, MaxExpiresAt: c.MaxExpiresAt,
		ReauthenticatedAt: c.ReauthenticatedAt, Data: c.Data,
	}, c.Read, nil
}

// currentSession returns the session of the request in ctx when it belongs
// to userID, pending or not. Stateless mode can answer for that session and
// no other.
func currentSession(ctx context.Context, userID string) (Session, bool) {
	st := stateFrom(ctx)
	if st == nil || st.session == nil || st.session.UserID != userID {
		return Session{}, false
	}
	return *st.session, true
}

// Bounds of WithStatelessRefreshWithoutRead's interval.
const (
	// DefaultStatelessReadInterval is used when the option gets 0: five
	// minutes between full reads is one user query per active session per
	// five minutes, and a ban that waits five minutes at most.
	//ds:def id=defaultstatelessreadinterval-3kq8vz2m owner=@khanakia stability=stable
	DefaultStatelessReadInterval = 5 * time.Minute
	// MaxStatelessReadInterval caps the interval: it is how long a banned
	// user, or a session cut off by "sign out everywhere" or a password
	// reset, keeps working, so it is the same bound as MaxSessionCacheTTL
	// whatever the option says.
	//ds:def id=maxstatelessreadinterval-7wm2pq4x owner=@khanakia stability=stable
	MaxStatelessReadInterval = MaxSessionCacheTTL
)

// WithStatelessRefreshWithoutRead lets a stateless request skip the user
// query: the token carries the user as the last full read found it, and for
// interval after that read (0 means DefaultStatelessReadInterval, more than
// MaxStatelessReadInterval is clamped to it) every request, and every
// sliding refresh, uses that copy. A token near expiry is then reissued
// without loading the user, as better-auth's refreshCache does; the first
// request after the interval loads the user again, applies every
// SessionChecker condition and the sessions_valid_after cutoff, and carries
// the fresh copy in a reissued token.
//
// The trade-off, stated plainly: a ban, a "sign out everywhere" and a
// password reset reach a token only at its next full read, so a session
// they end keeps working for up to interval. What does not wait: an
// operation that requires a FreshSignIn always loads the user (a password
// change or an account deletion never runs on a copy), a session revoked
// through WithSessionRevocations is refused at once, and raising
// WithStatelessVersion or replacing the key ends every token at once.
// Without the option every request loads the user, as before. New refuses
// it without WithStatelessSessions.
//
//ds:def id=opt-withstatelessrefreshwithoutread-9fz3kd7n owner=@khanakia stability=stable
func WithStatelessRefreshWithoutRead(interval time.Duration) Option {
	return func(s *settings) { s.statelessReadSet, s.statelessRead = true, interval }
}

// clampReadInterval applies the interval bounds.
func clampReadInterval(d time.Duration) time.Duration {
	if d <= 0 {
		return DefaultStatelessReadInterval
	}
	return min(d, MaxStatelessReadInterval)
}

// usableRead reports whether the token's copy of the user may stand in for
// a read at now: the option is on, the copy exists, and it was made within
// the interval. A copy dated after now (a clock moved back) is not used.
func (st *statelessSessions) usableRead(r *statelessRead, now time.Time) bool {
	return st.readEvery > 0 && r != nil && !r.At.After(now) && now.Sub(r.At) < st.readEvery
}
