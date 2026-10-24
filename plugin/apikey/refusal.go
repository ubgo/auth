package apikey

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/ubgo/auth"
)

// Errors that say why a key was refused, used only under DistinctErrors. By
// default every one of these cases is auth.ErrSignedOut, so whoever holds a
// key cannot learn whether it was revoked, paused or expired.
var (
	// ErrInvalidKey is a key that does not exist, failed PreCheck, or belongs
	// to another configuration than VerifyFor named. Verify reports it; over
	// HTTP an unknown key leaves the request signed out (401 auth.signed_out
	// on a route that needs a user), because a session token may start with
	// a key prefix by chance and is then looked up as a session, unless
	// RejectUnknownKeys makes it this error on every route.
	ErrInvalidKey = auth.NewError("apikey.invalid_key", http.StatusUnauthorized, "Invalid API key.")
	// ErrKeyDisabled is a key its owner paused (UpdateRequest.Disabled).
	ErrKeyDisabled = auth.NewError("apikey.key_disabled", http.StatusUnauthorized, "This API key is disabled.")
	// ErrKeyExpired is a key past its expiry.
	ErrKeyExpired = auth.NewError("apikey.key_expired", http.StatusUnauthorized, "This API key has expired.")
	// ErrKeyOwnerGone is a key whose user no longer exists.
	ErrKeyOwnerGone = auth.NewError("apikey.invalid_owner", http.StatusUnauthorized, "The account behind this API key no longer exists.")
	// ErrOwnerBlocked is a key whose owner exists but may not sign in (an
	// admin ban, or an app's own SessionChecker).
	ErrOwnerBlocked = auth.NewError("apikey.owner_blocked", http.StatusUnauthorized, "The account behind this API key cannot sign in.")
)

// DistinctErrors answers each refused key with its own code:
// apikey.key_disabled, apikey.key_expired, apikey.invalid_owner and
// apikey.owner_blocked (401) on every route, and apikey.invalid_key from Verify. The risk, which
// is why it is off by default: whoever holds a stolen key learns whether the
// owner paused it, let it expire or revoked it, and a request with a refused
// key fails with that 401 even on a route that would serve an anonymous
// caller, where the default lets it through signed out.
//
//ds:def id=distincterrors-m3wt9xhv owner=@khanakia stability=stable
func DistinctErrors() Option { return func(p *Plugin) { p.distinct = true } }

// OwnerRefused is auth.OwnerRefusalReporter: under DistinctErrors a banned
// owner's key answers ErrOwnerBlocked, otherwise nil keeps ErrSignedOut.
func (p *Plugin) OwnerRefused() error {
	switch {
	case p.distinct:
		return ErrOwnerBlocked
	case p.rejectUnknown:
		// The same answer as an unknown key, so a refused owner is not
		// told apart from a key that never existed.
		return ErrInvalidKey
	}
	return nil
}

// refuse is the error for a refused key: the distinct one when asked for,
// ErrInvalidKey under RejectUnknownKeys alone (every refusal then reads as
// an unknown key), auth.ErrSignedOut otherwise.
func (p *Plugin) refuse(distinct error) error {
	switch {
	case p.distinct:
		return distinct
	case p.rejectUnknown:
		return ErrInvalidKey
	}
	return auth.ErrSignedOut
}

// RejectUnknownKeys answers a bearer token that starts with a key prefix but
// is no key (unknown, revoked, or refused for a reason DistinctErrors would
// name) with 401 apikey.invalid_key instead of the default, which lets the
// request through signed out (401 auth.signed_out only on a route that needs
// a user). Without DistinctErrors every refusal, a banned owner's included,
// is that same apikey.invalid_key, so the answer still says nothing about
// why; with it, only a key that was never found is.
//
// The default exists because the core routes any bearer token that starts
// with a key prefix to this plugin, and when the plugin does not know the
// token it falls through to the sessions: a session token that happens to
// begin with the prefix must still work. Under this option nothing falls
// through, so auth.New refuses it unless every configuration's prefix holds a
// character no token the core issues can contain (core session tokens,
// stateless ones included, are base64url: letters, digits, "-" and "_"), such
// as "sk.live_" (ErrPrefixNotDistinct). That keeps the guarantee that no
// session is ever refused as a key.
//
// The cost: a request carrying a bad key now fails with that 401 even on a
// route that serves anonymous callers. It weakens nothing, so auth.New does
// not warn about it.
//
//ds:def id=apikey-rejectunknownkeys-p3r2kq7w owner=@khanakia stability=stable
func RejectUnknownKeys() Option { return func(p *Plugin) { p.rejectUnknown = true } }

// ErrPrefixNotDistinct is a configuration error: RejectUnknownKeys with a key
// prefix made only of base64url characters, which a core token could start
// with.
var ErrPrefixNotDistinct = errors.New("apikey: RejectUnknownKeys needs every key prefix to hold a character outside base64url (A-Z a-z 0-9 - _), such as \".\"")

// tokenAlphabet is every character a core-issued token can contain:
// base64.RawURLEncoding's (auth.NewToken and the stateless session token).
const tokenAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// checkDistinctPrefixes is Validate's check of RejectUnknownKeys: every
// configuration's prefix leaves the core's token alphabet somewhere, so no
// session token can start with it.
func (p *Plugin) checkDistinctPrefixes() error {
	if !p.rejectUnknown {
		return nil
	}
	for _, s := range p.configs {
		if strings.Trim(s.prefix, tokenAlphabet) == "" {
			return fmt.Errorf("%w: %q", ErrPrefixNotDistinct, s.prefix)
		}
	}
	return nil
}

// unknownKey is ResolveToken's answer under RejectUnknownKeys: a key that
// resolved to nobody (auth.ErrSignedOut, which the core would read as "not a
// key, try the sessions") becomes ErrInvalidKey, which the core returns.
func (p *Plugin) unknownKey(err error) error {
	if p.rejectUnknown && errors.Is(err, auth.ErrSignedOut) {
		return ErrInvalidKey
	}
	return err
}

// isRefusal reports whether err is an answer about the key rather than a
// failure: Verify reports these in Verification.Reason.
func isRefusal(err error) bool {
	for _, r := range []error{auth.ErrSignedOut, auth.ErrRateLimited, ErrUsageExceeded, ErrInvalidKey, ErrKeyDisabled, ErrKeyExpired, ErrKeyOwnerGone, ErrOrganizationKey} {
		if errors.Is(err, r) {
			return true
		}
	}
	return false
}
