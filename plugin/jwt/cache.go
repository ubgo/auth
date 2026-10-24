package jwt

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/ubgo/auth"
)

// Session-cache constants.
const (
	// SessionCacheType is the JWS "typ" header of a session-cache snapshot.
	// Verify refuses it and
	// the cache refuses every other typ, so an access token can never stand
	// in for a cached session, nor a snapshot for an access token.
	//ds:def id=sessioncachetype-w8d3kq6n owner=@khanakia stability=stable
	SessionCacheType = "ubgo-auth.session-cache+jwt"
	// SessionCacheAudience is the "aud" claim of a snapshot: a service whose
	// Verifier checks its own audience refuses a snapshot on that ground too.
	//ds:def id=sessioncacheaudience-v4m7zt2h owner=@khanakia stability=stable
	SessionCacheAudience = "ubgo-auth:session-cache"
	// cacheBindingLabel prefixes the token hash before it is hashed again
	// into the snapshot's binding claim, so the readable claim is never the
	// value the session store looks a token up by.
	cacheBindingLabel = "github.com/ubgo/auth/plugin/jwt session cache binding"
	// Snapshot claim names beyond the registered ones: the binding to the
	// session token, and the session and user the snapshot carries.
	claimBinding = "tbh"
	claimCachedS = "session"
	claimCachedU = "user"
)

// ErrCacheNotWired is a session cache whose plugin was not passed to
// auth.WithPlugins, so it has no issuer and no clock: every Put fails, and
// the first request says why instead of caching nothing silently.
var ErrCacheNotWired = errors.New("jwt: NewSessionCache's plugin is not in auth.WithPlugins")

// sessionCache is the SessionCache whose client copy is a JWT signed by the
// plugin; see NewSessionCache.
type sessionCache struct{ p *Plugin }

// NewSessionCache returns an auth.SessionCache whose client copy is a JWT
// signed with p's key: a value with typ
// SessionCacheType and kid in the header, and iss, aud
// (SessionCacheAudience), sub (the user id), sid (the session id), iat, exp
// (when the entry stops being used), the session, the user, and a binding to
// the session token among its claims. Pass it to auth.WithSessionCache, with
// p in auth.WithPlugins.
//
// It keeps every rule of auth.NewSnapshotCache, which stays the default: an
// entry is used only with the token it was made for (compared in constant
// time), only until its expiry, never past MaxSessionCacheTTL, and the core
// never renews one without reading the store. Get verifies the signature
// with the published key its kid names, under that key's algorithm and
// never the header's, and refuses every other typ; anything that does not
// verify is a miss, so the store is asked.
//
// The difference that matters: the claims are signed, not encrypted. Anyone
// holding the value (the browser, a bearer client, a log line) can read the
// session's IP, user agent and app data and the user's name and image;
// nobody can change them. Use NewSnapshotCache when that is not acceptable.
// With Rotating, a grace shorter than the cache TTL only turns a snapshot
// signed with a retired key into a miss.
//
//ds:def id=newsessioncache-k9r3vx7m owner=@khanakia stability=stable
func NewSessionCache(p *Plugin) auth.SessionCache { return &sessionCache{p: p} }

// binding is the snapshot's tie to the session token: a hash of the token
// hash under a fixed label, compared in constant time.
func binding(tokenHash []byte) []byte {
	h := sha256.Sum256(append([]byte(cacheBindingLabel), tokenHash...))
	return h[:]
}

// Put signs the entry for the client to hold, until until, never past
// MaxSessionCacheTTL from now.
func (c *sessionCache) Put(ctx context.Context, k auth.CacheKey, s auth.Session, u auth.User, until time.Time) (string, error) {
	if c.p.core == nil {
		return "", ErrCacheNotWired
	}
	now := c.p.core.Now()
	if limit := now.Add(auth.MaxSessionCacheTTL); until.After(limit) {
		until = limit
	}
	claims := map[string]any{
		claimIssuer: c.p.issuer, claimAudience: SessionCacheAudience, claimSubject: u.ID, claimSession: s.ID,
		// exp is whole seconds (RFC 7519), rounded down so the entry is
		// never used past until.
		claimIssuedAt: now.Unix(), claimExpires: until.Unix(),
		claimBinding: base64.RawURLEncoding.EncodeToString(binding(k.TokenHash)),
		claimCachedS: s, claimCachedU: u,
	}
	return signWith(ctx, c.p.signer, SessionCacheType, claims)
}

// snapshotClaims is what Get reads back from a verified snapshot.
type snapshotClaims struct {
	Iss     string       `json:"iss"`
	Aud     string       `json:"aud"`
	Sub     string       `json:"sub"`
	Sid     string       `json:"sid"`
	Exp     int64        `json:"exp"`
	Binding string       `json:"tbh"`
	Session auth.Session `json:"session"`
	User    auth.User    `json:"user"`
}

// Get verifies the client's snapshot and returns it, if it is for this token
// and still valid at now. Every failure is a miss, never an error: a
// snapshot the client tampered with, or one signed with a key no longer
// published, sends the request to the store.
func (c *sessionCache) Get(_ context.Context, k auth.CacheKey, now time.Time) (auth.Session, auth.User, bool, error) {
	snap, ok := c.open(k.Client)
	if !ok || !now.Before(time.Unix(snap.Exp, 0)) {
		return auth.Session{}, auth.User{}, false, nil
	}
	want := binding(k.TokenHash)
	got, err := base64.RawURLEncoding.Strict().DecodeString(snap.Binding)
	if err != nil || subtle.ConstantTimeCompare(got, want) != 1 {
		return auth.Session{}, auth.User{}, false, nil
	}
	return snap.Session, snap.User, true, nil
}

// open verifies a snapshot's header, key, algorithm, signature, issuer and
// audience, and that its sub and sid are the user and session it carries.
func (c *sessionCache) open(v string) (snapshotClaims, bool) {
	parts := strings.Split(v, segmentSeparator)
	if v == "" || len(parts) != segmentCount || c.p.core == nil {
		return snapshotClaims{}, false
	}
	enc := base64.RawURLEncoding.Strict()
	hb, err := enc.DecodeString(parts[0])
	if err != nil {
		return snapshotClaims{}, false
	}
	h, err := parseHeader(hb, SessionCacheType)
	if err != nil {
		return snapshotClaims{}, false
	}
	pub, ok := c.p.publishedKey(h.Kid)
	if !ok || checkSignature(pub, h.Alg, parts, enc) != nil {
		return snapshotClaims{}, false
	}
	pb, err := enc.DecodeString(parts[1])
	if err != nil {
		return snapshotClaims{}, false
	}
	var snap snapshotClaims
	if err := json.Unmarshal(pb, &snap); err != nil {
		return snapshotClaims{}, false
	}
	if snap.Iss != c.p.issuer || snap.Aud != SessionCacheAudience || snap.Sub != snap.User.ID || snap.Sid != snap.Session.ID || snap.Session.UserID != snap.User.ID || snap.Sub == "" || snap.Sid == "" {
		return snapshotClaims{}, false
	}
	return snap, true
}

// Drop is a no-op: the client's copy is cleared by the transport
// (auth.EffectClearCache), as for the sealed snapshot.
func (c *sessionCache) Drop(context.Context, auth.CacheKey) error { return nil }
