package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Plugin cookies: a plugin or a hook keeps a small value in the browser
// under a name of its own, as better-auth's ctx.setCookie, setSignedCookie
// and getCookie let a plugin do (the two_factor state cookie). The core
// records the cookie as an effect; the transport names it beside the core's
// cookies (authhttp: __Host-auth_<name>, under the same CookiePrefix and
// CookieDomain rules) and gives it the same fixed attributes: HttpOnly,
// Secure, Path=/, SameSite=Lax or stricter. A plugin chooses the name, the
// value and the expiry, never an attribute, so no plugin can weaken the
// rules every other cookie follows.

// CookieNamePattern is what a plugin cookie's name may look like: lower
// case, digits and underscores, starting with a letter, at most 32
// characters, so the transport can put it in a cookie name as is.
//
//ds:def id=core-cookienamepattern-4xk9wq2m owner=@khanakia stability=stable
var CookieNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// reservedCookieNames are the names of the core's own cookies, after the app
// prefix: a plugin cookie under one of them would overwrite the session.
var reservedCookieNames = []string{"session", "flow", "session_cache", "device"}

// reservedCookiePrefix starts the names of the multi-session account
// cookies, one per signed-in account.
const reservedCookiePrefix = "account_"

// ErrBadCookieName is the error for a plugin cookie name that does not match
// CookieNamePattern or is one of the core's own cookies.
var ErrBadCookieName = errors.New("auth: bad cookie name")

// CheckCookieName reports whether name may be a plugin cookie's name:
// CookieNamePattern, and none of the core's own cookies (session, flow,
// session_cache, device, account_*). A transport may call it to refuse a
// name before it reads one.
func CheckCookieName(name string) error {
	if !CookieNamePattern.MatchString(name) {
		return fmt.Errorf("%w: %q must match %s", ErrBadCookieName, name, CookieNamePattern)
	}
	for _, r := range reservedCookieNames {
		if name == r {
			return fmt.Errorf("%w: %q is one of the core's cookies", ErrBadCookieName, name)
		}
	}
	if strings.HasPrefix(name, reservedCookiePrefix) {
		return fmt.Errorf("%w: %q is in the core's %s* names", ErrBadCookieName, name, reservedCookiePrefix)
	}
	return nil
}

// SetCookie records a plugin cookie for the transport to set: name (see
// CheckCookieName), value, and expiresAt, when the browser drops it; a zero
// expiresAt deletes the cookie. Like every effect it reaches the client only
// if the call succeeds. The value is readable by nobody but the server
// (HttpOnly) but is NOT protected from the client changing it: anything the
// server must trust goes through Call.SetSignedCookie.
func (e *Effects) SetCookie(name, value string, expiresAt time.Time) error {
	if err := CheckCookieName(name); err != nil {
		return err
	}
	e.add(Effect{Kind: EffectCookie, Name: name, Value: value, ExpiresAt: expiresAt})
	return nil
}

// Cookie returns the value of plugin cookie name as the client sent it, and
// whether it sent one. A Go call, or a transport without cookies, has none.
func (c *Call) Cookie(name string) (string, bool) { return RequestCookie(c.ctx, name) }

// RequestCookie is Call.Cookie for code that holds only the context, such as
// a data hook.
func RequestCookie(ctx context.Context, name string) (string, bool) {
	st := stateFrom(ctx)
	if st == nil || st.req.Cookie == nil || CheckCookieName(name) != nil {
		return "", false
	}
	return st.req.Cookie(name)
}

// KeyLabelCookies is the WithSecret label of the key that signs plugin
// cookies (Call.SetSignedCookie).
//
//ds:def id=core-keylabelcookies-7nq2wd4k owner=@khanakia stability=stable
const KeyLabelCookies = "cookies"

// signedCookieSeparator splits a signed cookie's value from its MAC.
const signedCookieSeparator = "."

// cookieMAC signs value under key, bound to the cookie's name so a value
// signed for one cookie never verifies as another's.
func cookieMAC(key []byte, name, value string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(KeyLabelCookies + "\x00" + name + "\x00" + value))
	return m.Sum(nil)
}

// SetSignedCookie is SetCookie with the value signed, as better-auth's
// setSignedCookie is: base64url of the value, a dot, and an HMAC-SHA256 over
// the cookie's name and value under the key WithSecret derives for
// KeyLabelCookies. The client can read the value's encoding but not change
// it, and SignedCookie refuses any value it did not sign. Without WithSecret
// it is ErrNoSecret.
func (c *Call) SetSignedCookie(name, value string, expiresAt time.Time) error {
	if err := CheckCookieName(name); err != nil {
		return err
	}
	key, err := c.Auth.cfg.DeriveKey(KeyLabelCookies)
	if err != nil {
		return err
	}
	signed := base64.RawURLEncoding.EncodeToString([]byte(value)) + signedCookieSeparator + base64.RawURLEncoding.EncodeToString(cookieMAC(key, name, value))
	return c.Effects.SetCookie(name, signed, expiresAt)
}

// SignedCookie returns the value of a cookie SetSignedCookie set, and false
// when the client sent none, or one whose signature does not verify under
// any WithSecret key (the current one or one before a rotation), compared in
// constant time.
func (c *Call) SignedCookie(name string) (string, bool) {
	raw, ok := c.Cookie(name)
	if !ok {
		return "", false
	}
	enc, mac, ok := strings.Cut(raw, signedCookieSeparator)
	if !ok {
		return "", false
	}
	value, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return "", false
	}
	got, err := base64.RawURLEncoding.DecodeString(mac)
	if err != nil {
		return "", false
	}
	keys, err := c.Auth.cfg.DeriveKeys(KeyLabelCookies)
	if err != nil {
		return "", false
	}
	for _, key := range keys {
		if hmac.Equal(got, cookieMAC(key, name, string(value))) {
			return string(value), true
		}
	}
	return "", false
}
