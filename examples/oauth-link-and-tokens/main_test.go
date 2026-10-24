package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/oauth"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery staple"
	// shortLived is an access-token lifetime inside the plugin's refresh
	// margin, so every read refreshes.
	shortLived = 30
)

// TestLink_FromSettingsThenUnlink: a person with a password account links the
// provider from settings, sees it listed, and unlinks it. Someone else cannot
// link the same provider account, and unlinking twice is "not linked".
func TestLink_FromSettingsThenUnlink(t *testing.T) {
	idp, a, oa, box := newTestApp(t, issuerExpiresIn)
	h := newHandler(a, oa)
	alice := newBrowser(t, h)
	owner := alice.signUpVerified(t, a, box)

	alice.linkProvider(t, idp, "/tokens")
	accounts := get[oauth.AccountsResult](t, alice, "/auth/oauth/accounts", http.StatusOK)
	if len(accounts.Accounts) != 1 || accounts.Accounts[0].Provider != providerName || accounts.Accounts[0].Email != defaultEmail {
		t.Fatalf("accounts after linking = %+v", accounts.Accounts)
	}
	// Linking is a settings action for the signed-in user: the session is
	// unchanged, and /me is still the password account.
	if me := get[meResponse](t, alice, "/me", http.StatusOK); me.ID != owner.ID {
		t.Fatalf("/me after linking = %+v, want %s", me, owner.ID)
	}

	// Dave cannot link Carol's provider account to his own.
	dave := newBrowser(t, h)
	post[none](t, dave, "/auth/password/sign-up", fields{"identifier": "dave@example.com", "password": testPassword}, http.StatusOK)
	cb := dave.throughProvider(t, idp, "/auth/oauth/"+providerName+"/start?link="+oauth.LinkFlag)
	if e := get[errorAnswer](t, dave, cb, http.StatusConflict); e.Error.Code != oauth.ErrAccountLinkedElsewhere.Code {
		t.Fatalf("linking another user's provider account: %+v", e.Error)
	}

	post[auth.Done](t, alice, "/auth/oauth/unlink", fields{"provider": providerName}, http.StatusOK)
	if accounts := get[oauth.AccountsResult](t, alice, "/auth/oauth/accounts", http.StatusOK); len(accounts.Accounts) != 0 {
		t.Fatalf("accounts after unlinking = %+v", accounts.Accounts)
	}
	if e := post[errorAnswer](t, alice, "/auth/oauth/unlink", fields{"provider": providerName}, http.StatusNotFound); e.Error.Code != oauth.ErrNotLinked.Code {
		t.Fatalf("unlinking twice: %+v", e.Error)
	}
	if e := get[errorAnswer](t, alice, "/tokens", http.StatusNotFound); e.Error.Code != oauth.ErrNoTokens.Code {
		t.Fatalf("tokens after unlinking: %+v", e.Error)
	}
}

// TestTokens_StoredAndRefreshedBeforeExpiry: the provider's tokens are kept
// and read back; with a long-lived access token no refresh happens, with one
// about to expire every read refreshes and keeps the rotated refresh token.
func TestTokens_StoredAndRefreshedBeforeExpiry(t *testing.T) {
	t.Run("long-lived", func(t *testing.T) {
		idp, a, oa, box := newTestApp(t, issuerExpiresIn)
		alice := newBrowser(t, newHandler(a, oa))
		alice.signUpVerified(t, a, box)
		alice.linkProvider(t, idp, "/tokens")
		ts := get[tokensResponse](t, alice, "/tokens", http.StatusOK)
		if ts.AccessToken != "access-1" || ts.RefreshToken != "refresh-1" || ts.ExpiresAt.IsZero() {
			t.Fatalf("stored tokens = %+v", ts)
		}
		if idp.refreshes != 0 {
			t.Fatalf("a token with an hour left was refreshed %d times", idp.refreshes)
		}
	})
	t.Run("about to expire", func(t *testing.T) {
		idp, a, oa, box := newTestApp(t, shortLived)
		alice := newBrowser(t, newHandler(a, oa))
		alice.signUpVerified(t, a, box)
		alice.linkProvider(t, idp, "/tokens")
		first := get[tokensResponse](t, alice, "/tokens", http.StatusOK)
		second := get[tokensResponse](t, alice, "/tokens", http.StatusOK)
		if first.AccessToken != "access-2" || first.RefreshToken != "refresh-2" || second.AccessToken != "access-3" || idp.refreshes != 2 {
			t.Fatalf("reads = %+v then %+v after %d refreshes", first, second, idp.refreshes)
		}
	})
}

// TestSignIn_VerifiedAddressReachesTheExistingAccount: the issuer vouches for
// the address a password user verified, so signing in with it lands in that
// account and links the provider on the way.
func TestSignIn_VerifiedAddressReachesTheExistingAccount(t *testing.T) {
	idp, a, oa, box := newTestApp(t, issuerExpiresIn)
	idp.person.Email = testEmail
	h := newHandler(a, oa)
	alice := newBrowser(t, h)
	owner := alice.signUpVerified(t, a, box)

	fresh := newBrowser(t, h)
	cb := fresh.throughProvider(t, idp, "/auth/oauth/"+providerName+"/start?returnTo=/me")
	if loc := fresh.redirect(t, cb); loc != "/me" {
		t.Fatalf("callback redirected to %q, want /me", loc)
	}
	if me := get[meResponse](t, fresh, "/me", http.StatusOK); me.ID != owner.ID {
		t.Fatalf("provider sign-in reached %s, want the password account %s", me.ID, owner.ID)
	}
}

// TestTokenKey_FromTheEnvironment: a set key is used as given, so tokens
// stored before a restart still open; a malformed one is refused.
func TestTokenKey_FromTheEnvironment(t *testing.T) {
	want := bytes.Repeat([]byte{7}, auth.SealKeySize)
	got, err := tokenKey(func(string) string { return base64.RawURLEncoding.EncodeToString(want) })
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("key from the environment = %x, %v", got, err)
	}
	if _, err := tokenKey(func(string) string { return "too-short" }); err == nil {
		t.Fatal("a malformed key must be refused")
	}
	if _, _, err := personFromEnv(func(name string) string {
		if name == envIssuerExpiresIn {
			return "soon"
		}
		return ""
	}); err == nil {
		t.Fatal("a malformed lifetime must be refused")
	}
}

// newTestApp runs the development issuer on httptest, builds the app around
// it and migrates a fresh SQLite file.
func newTestApp(t *testing.T, expiresIn int) (*issuer, *auth.Auth, *oauth.Plugin, *mailbox) {
	t.Helper()
	person, _, err := personFromEnv(func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	var idp *issuer
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { idp.handler().ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	idp = newIssuer(srv.URL, person, expiresIn)

	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	box := &mailbox{}
	oa := newOAuth(srv.URL, bytes.Repeat([]byte{1}, auth.SealKeySize))
	a, err := newAuth(db, box, oa)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return idp, a, oa, box
}

// mailbox records every mail sent.
type mailbox struct {
	mu   sync.Mutex
	sent []email.Mail
}

// Send records m.
func (m *mailbox) Send(_ context.Context, mail email.Mail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, mail)
	return nil
}

// lastToken returns the token of the newest link mailed to addr. Mail goes
// out after the transaction commits, so it waits for deliveries first.
func (m *mailbox) lastToken(t *testing.T, a *auth.Auth, addr string) string {
	t.Helper()
	a.WaitDeliveries()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.sent) - 1; i >= 0; i-- {
		if m.sent[i].To != addr {
			continue
		}
		for _, field := range strings.Fields(m.sent[i].Text) {
			if u, err := url.Parse(field); err == nil && u.Query().Get("token") != "" {
				return u.Query().Get("token")
			}
		}
	}
	t.Fatalf("no link mailed to %s", addr)
	return ""
}

// browser is an HTTPS test server and a client with a cookie jar that sends
// the Origin a page of the app would, and does not follow redirects, so each
// step of the provider dance is checked.
type browser struct {
	srv    *httptest.Server
	client *http.Client
}

// newBrowser serves h over TLS, because the session cookie is __Host- and
// Secure, and a cookie jar keeps such a cookie only for an https URL.
func newBrowser(t *testing.T, h http.Handler) *browser {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := srv.Client()
	client.Jar = jar
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &browser{srv: srv, client: client}
}

// signUpVerified signs alice up with a password and verifies her address.
func (b *browser) signUpVerified(t *testing.T, a *auth.Auth, box *mailbox) meResponse {
	t.Helper()
	post[none](t, b, "/auth/password/sign-up", fields{"identifier": testEmail, "password": testPassword, "name": "Alice"}, http.StatusOK)
	post[none](t, b, "/auth/email/verify", fields{"token": box.lastToken(t, a, testEmail)}, http.StatusOK)
	return get[meResponse](t, b, "/me", http.StatusOK)
}

// linkProvider runs a link flow for the signed-in user and checks it lands
// on returnTo.
func (b *browser) linkProvider(t *testing.T, idp *issuer, returnTo string) {
	t.Helper()
	cb := b.throughProvider(t, idp, "/auth/oauth/"+providerName+"/start?link="+oauth.LinkFlag+"&returnTo="+url.QueryEscape(returnTo))
	if loc := b.redirect(t, cb); loc != returnTo {
		t.Fatalf("link callback redirected to %q, want %q", loc, returnTo)
	}
}

// throughProvider starts a flow and follows the issuer's consent redirect,
// returning the app's callback path and query. The callback URL names
// baseURL, where main would be listening; the test server is elsewhere, so
// only its path and query are kept.
func (b *browser) throughProvider(t *testing.T, idp *issuer, start string) string {
	t.Helper()
	consent := b.redirect(t, start)
	if !strings.HasPrefix(consent, idp.url+"/authorize?") {
		t.Fatalf("start sent the browser to %s, not the issuer", consent)
	}
	back, err := url.Parse(b.redirect(t, consent))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(back.String(), baseURL+authPrefix+"/oauth/"+providerName+"/callback") {
		t.Fatalf("the issuer sent the browser to %s, not the registered callback", back)
	}
	return back.RequestURI()
}

// fields is a JSON request body as a client writes it.
type fields map[string]string

// none is the request body of a route that takes no input, and the answer
// of a call whose body the test does not read.
type none struct{}

// errorAnswer is the JSON shape of every error the library answers.
type errorAnswer struct {
	Error auth.ErrorInfo `json:"error"`
}

// redirect gets u (a path on the app, or an absolute URL), checks the answer
// is a 302 and returns its Location.
func (b *browser) redirect(t *testing.T, u string) string {
	t.Helper()
	if strings.HasPrefix(u, "/") {
		u = b.srv.URL + u
	}
	res, err := b.client.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusFound {
		var body bytes.Buffer
		_, _ = body.ReadFrom(res.Body)
		t.Fatalf("GET %s = %d %s, want 302", u, res.StatusCode, body.String())
	}
	return res.Header.Get("Location")
}

// get decodes a GET of path into T after checking the status.
func get[T any](t *testing.T, b *browser, path string, want int) T {
	t.Helper()
	res, err := b.client.Get(b.srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	return decode[T](t, res, want, http.MethodGet+" "+path)
}

// post sends body as JSON with the app's Origin and decodes the answer.
func post[T any](t *testing.T, b *browser, path string, body any, want int) T {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, b.srv.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", baseURL)
	res, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return decode[T](t, res, want, http.MethodPost+" "+path)
}

func decode[T any](t *testing.T, res *http.Response, want int, what string) T {
	t.Helper()
	defer res.Body.Close()
	var body bytes.Buffer
	_, _ = body.ReadFrom(res.Body)
	if res.StatusCode != want {
		t.Fatalf("%s = %d %s, want %d", what, res.StatusCode, body.String(), want)
	}
	var out T
	if body.Len() > 0 {
		if err := json.Unmarshal(body.Bytes(), &out); err != nil {
			t.Fatalf("%s: %v in %s", what, err, body.String())
		}
	}
	return out
}
