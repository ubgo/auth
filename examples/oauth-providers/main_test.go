package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/oauth/oauthtest"
)

// TestCorpProvider_PassesTheConformanceKit: the hand-written provider is
// driven against the kit's fake server, with the profile API answering in
// the corporate shape, and keeps every rule the plugin relies on.
//
//ds:def id=oauthproviders-conformance-n7w2xk5r
func TestCorpProvider_PassesTheConformanceKit(t *testing.T) {
	oauthtest.Run(t, func(u string) oauth.Provider {
		return corpProvider(u, oauthtest.ClientID, oauthtest.ClientSecret)
	}, oauthtest.WantScopes(corpScopes...),
		oauthtest.Route(corpProfilePath, func(p oauthtest.Person) any { // any: the kit's Route signature
			return corpUser{ID: p.Subject, Mail: p.Email, MailConfirmed: p.EmailVerified, DisplayName: p.Name}
		}))
}

// TestProviders_ABrokenIssuerIsLeftOut: the backup issuer is unreachable,
// so SkipBrokenProviders leaves it out: the app starts, the providers list
// offers the other two, and the backup's start route is gone.
func TestProviders_ABrokenIssuerIsLeftOut(t *testing.T) {
	w := newWorld(t)
	got := newBrowser().get(t, w.h, baseURL+"/auth/oauth/providers")
	var list oauth.ProvidersResult
	if err := json.Unmarshal([]byte(got.body), &list); err != nil || got.status != http.StatusOK {
		t.Fatalf("providers = %d %s", got.status, got.body)
	}
	var ids []string
	for _, p := range list.Providers {
		ids = append(ids, p.ID)
	}
	if len(ids) != 2 || ids[0] != corpName || ids[1] != partnerName {
		t.Fatalf("providers offered = %v", ids)
	}
	if got := newBrowser().get(t, w.h, baseURL+"/auth/oauth/"+backupName+"/start"); got.status != http.StatusNotFound {
		t.Fatalf("the broken provider's start = %d", got.status)
	}
}

// TestProviders_SignUpMustBeAsked: under ExplicitSignUp a sign-in by a
// person nobody holds is refused; the sign-up button's flow creates the
// account and lands on the onboarding page; after that a plain sign-in
// finds the account and lands on returnTo.
func TestProviders_SignUpMustBeAsked(t *testing.T) {
	w := newWorld(t)
	b := newBrowser()

	refused := b.get(t, w.h, w.corp.consent(t, b.redirect(t, w.h, startURL(corpName, url.Values{"returnTo": {"/me"}}))))
	if refused.status != oauth.ErrSignUpNotRequested.Status {
		t.Fatalf("an unasked sign-up = %d %s", refused.status, refused.body)
	}

	signUp := startURL(corpName, url.Values{"returnTo": {"/me"}, "signUp": {"true"}, "newUserTo": {"/welcome"}})
	if landing := b.redirect(t, w.h, w.corp.consent(t, b.redirect(t, w.h, signUp))); landing != "/welcome" {
		t.Fatalf("a new user landed on %s", landing)
	}
	again := newBrowser()
	if landing := again.redirect(t, w.h, w.corp.consent(t, again.redirect(t, w.h, startURL(corpName, url.Values{"returnTo": {"/me"}})))); landing != "/me" {
		t.Fatalf("a returning user landed on %s", landing)
	}
	if who := w.me(t, again); who.Name != "Hana" {
		t.Fatalf("/me = %+v", who)
	}
}

// TestProviders_GothPartnerSignsIn: the goth provider's flow carries no PKCE
// challenge, and still signs the person in through the plugin's callback.
func TestProviders_GothPartnerSignsIn(t *testing.T) {
	w := newWorld(t)
	b := newBrowser()
	authURL := b.redirect(t, w.h, startURL(partnerName, url.Values{"returnTo": {"/me"}, "signUp": {"true"}}))
	if u, err := url.Parse(authURL); err != nil || u.Query().Get("code_challenge") != "" {
		t.Fatalf("goth's authorization URL = %s", authURL)
	}
	if landing := b.redirect(t, w.h, w.partner.consent(t, authURL)); landing != "/me" {
		t.Fatalf("the partner callback landed on %s", landing)
	}
	if who := w.me(t, b); who.Name != "Ivan" {
		t.Fatalf("/me = %+v", who)
	}
}

// world is the app with its three providers' issuers.
type world struct {
	h       http.Handler
	corp    *fakeIssuer
	partner *fakeIssuer
}

// newWorld starts the corporate server and the partner issuer, points the
// backup at an address where nothing listens, and builds the app.
func newWorld(t *testing.T) world {
	t.Helper()
	corp := newFakeIssuer(t, callbackURL(corpName), userInfo{Sub: "c-1", Email: "hana@example.com", EmailVerified: true, Name: "Hana"}, false)
	partner := newFakeIssuer(t, callbackURL(partnerName), userInfo{Sub: "p-1", Email: "ivan@example.com", EmailVerified: true, Name: "Ivan"}, true)
	gp, err := partnerProvider(partner.srv.URL, testClientID, testClientSecret)
	if err != nil {
		t.Fatal(err)
	}
	down := httptest.NewServer(http.NotFoundHandler())
	down.Close() // a closed server: every request to it fails

	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	a, err := newAuth(db,
		corpProvider(corp.srv.URL, testClientID, testClientSecret),
		gp,
		oauth.OIDC(backupName, down.URL, testClientID, testClientSecret))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return world{h: newHandler(a), corp: corp, partner: partner}
}

// startURL is a provider's start route with query q.
func startURL(provider string, q url.Values) string {
	return baseURL + authPrefix + "/" + oauth.PluginName + "/" + provider + "/start?" + q.Encode()
}

// me reads /me with b's session.
func (w world) me(t *testing.T, b *browser) meResponse {
	t.Helper()
	if b.jar[authhttp.CookieName] == "" {
		t.Fatal("the browser holds no session")
	}
	got := b.get(t, w.h, baseURL+"/me")
	var who meResponse
	if got.status != http.StatusOK || json.Unmarshal([]byte(got.body), &who) != nil {
		t.Fatalf("/me = %d %s", got.status, got.body)
	}
	return who
}
