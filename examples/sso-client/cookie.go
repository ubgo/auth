package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Cookie purposes. Each signature covers its purpose, so a value signed as
// one kind of cookie never opens as another: a login cookie pasted into the
// session cookie's place fails its check.
const (
	purposeLogin   = "login"
	purposeSession = "session"
	// sealSeparator joins the purpose, the payload and the signature.
	sealSeparator = "."
)

// errBadSeal is a cookie that is missing, malformed, signed with another
// key or for another purpose, or past its expiry. The app treats all of
// them the same way: as no cookie at all.
var errBadSeal = errors.New("sso-client: the cookie is missing, altered or expired")

// expiring is a cookie payload that carries its own expiry, so a copied
// cookie stops working on time even if the browser keeps it longer.
type expiring interface{ expiresAt() int64 }

// seal signs v as JSON with the app's own session secret. The value is
// readable (base64 is not encryption) but cannot be changed without the
// secret; nothing in it must be hidden from its own owner's browser.
//
//ds:def id=ssoclient-seal-yufauk2x owner=@khanakia stability=stable
func seal(secret []byte, purpose string, v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(raw)
	return payload + sealSeparator + sign(secret, purpose, payload), nil
}

// open checks the signature and the expiry of a sealed value and decodes
// it into v. The signature is compared in constant time.
//
//ds:def id=ssoclient-open-x8x2avc3 owner=@khanakia stability=stable
func open(secret []byte, purpose, sealed string, now time.Time, v expiring) error {
	payload, sig, ok := strings.Cut(sealed, sealSeparator)
	if !ok || !hmac.Equal([]byte(sig), []byte(sign(secret, purpose, payload))) {
		return errBadSeal
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil || json.Unmarshal(raw, v) != nil {
		return errBadSeal
	}
	if now.Unix() >= v.expiresAt() {
		return errBadSeal
	}
	return nil
}

// sign is HMAC-SHA256 over the purpose and the payload.
func sign(secret []byte, purpose, payload string) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(purpose + sealSeparator + payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// readCookie opens the named cookie of r into v.
func readCookie(r *http.Request, name string, secret []byte, purpose string, now time.Time, v expiring) error {
	c, err := r.Cookie(name)
	if err != nil {
		return errBadSeal
	}
	return open(secret, purpose, c.Value, now, v)
}

// setCookie writes a sealed cookie. HttpOnly keeps page scripts away from
// it, and SameSite=Lax still sends it on the top-level redirect back from
// the login server, which is a cross-site navigation.
func setCookie(w http.ResponseWriter, name, value string, maxAge time.Duration, secure bool) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: int(maxAge.Seconds()), HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
}

// deleteCookie tells the browser to drop the named cookie now.
func deleteCookie(w http.ResponseWriter, name string, secure bool) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
}
