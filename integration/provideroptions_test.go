package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/oauthprovider"
)

// The options of the provider's "everything is an option" pass, each with
// its default, its off or "no limit" value where it has one, and a value in
// between, against every engine.

// claimsOf decodes a compact JWT's payload, unverified.
func claimsOf(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	b := must[[]byte](t)(base64.RawURLEncoding.DecodeString(parts[1]))
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// consentAsked reports whether authorize sends the signed-in user to the
// consent page rather than straight back with a code.
func (o opEnv) consentAsked(t *testing.T, in oauthprovider.AuthorizeRequest) bool {
	t.Helper()
	res := must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(request(o.a, o.token), in))
	return strings.HasPrefix(res.RedirectTo, "/consent?")
}

// ConsentTTL: a consent is asked again once it is d old, renewed by
// approving, and an approval after expiry replaces the old grant. Without
// the option a consent never expires.
func TestOAuthProvider_ConsentTTL(t *testing.T) {
	const ttl = 24 * time.Hour
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e, oauthprovider.ConsentTTL(ttl))
		reg := o.client(t, oauthprovider.ClientSpec{})
		if !o.consentAsked(t, authzReq(reg.ClientID)) {
			t.Fatal("first authorization did not ask for consent")
		}
		o.code(t, authzReq(reg.ClientID))
		e.clock.Advance(ttl - time.Minute)
		if o.consentAsked(t, authzReq(reg.ClientID)) {
			t.Fatal("a consent inside its lifetime was asked again")
		}
		e.clock.Advance(time.Minute)
		if !o.consentAsked(t, authzReq(reg.ClientID)) {
			t.Fatal("an expired consent was not asked again")
		}
		// prompt=none cannot ask: consent_required at the redirect URI.
		none := authzReq(reg.ClientID)
		none.Prompt = "none"
		if _, err := o.op.Authorize(request(o.a, o.token), none); !errors.Is(err, oauthprovider.ErrConsentRequired) {
			t.Fatalf("prompt=none after expiry: %v", err)
		}
		// Approving a narrower set after expiry replaces the grant: the
		// wider request asks again.
		narrow := authzReq(reg.ClientID)
		narrow.Scope = "openid"
		o.code(t, narrow)
		if !o.consentAsked(t, authzReq(reg.ClientID)) {
			t.Fatal("an expired consent's scopes were renewed by approving fewer")
		}
		o.code(t, authzReq(reg.ClientID))
		if o.consentAsked(t, authzReq(reg.ClientID)) {
			t.Fatal("a renewed consent was asked again")
		}
	})
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e)
		reg := o.client(t, oauthprovider.ClientSpec{})
		o.code(t, authzReq(reg.ClientID))
		e.clock.Advance(10 * 365 * 24 * time.Hour)
		if o.consentAsked(t, authzReq(reg.ClientID)) {
			t.Fatal("without ConsentTTL a consent expired")
		}
	})
}

// endSessionPage runs end-session over HTTP as a signed-in browser and
// returns the signed confirmation cookie's value.
func (o opEnv) endSessionPage(t *testing.T, clientID string) string {
	t.Helper()
	w := c1Do(o.op.Handler(), http.MethodGet, "/oauth2/end-session?client_id="+url.QueryEscape(clientID), "", "", http.Header{"Accept": {"text/html"}, "Cookie": {"__Host-auth_session=" + o.token.Reveal()}})
	if w.Code != http.StatusOK || len(w.Result().Cookies()) == 0 {
		t.Fatalf("end-session page: %d %s", w.Code, w.Body.String())
	}
	return w.Result().Cookies()[0].Value
}

// confirmCtx is the signed-in browser's context carrying the confirmation
// cookie.
func (o opEnv) confirmCtx(state string) context.Context {
	return o.a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP, Client: auth.Client{Origin: testBaseURL}, Credential: auth.CredentialCookie, Token: o.token,
		Cookie: func(string) (string, bool) { return state, true }})
}

// EndSessionConfirmTTL: the confirmation is refused once it is older than
// the option's value, and accepted inside it.
func TestOAuthProvider_EndSessionConfirmTTL(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e, oauthprovider.EndSessionConfirmTTL(time.Minute))
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, EnableEndSession: true})
		state := o.endSessionPage(t, reg.ClientID)
		e.clock.Advance(time.Minute + time.Second)
		if _, err := o.op.ConfirmEndSession(o.confirmCtx(state), oauthprovider.EndSessionConfirmRequest{Action: "confirm", Browser: true}); !errors.Is(err, oauthprovider.ErrInvalidRequest) {
			t.Fatalf("a confirmation past EndSessionConfirmTTL: %v", err)
		}
		state = o.endSessionPage(t, reg.ClientID)
		e.clock.Advance(time.Minute - time.Second)
		res, err := o.op.ConfirmEndSession(o.confirmCtx(state), oauthprovider.EndSessionConfirmRequest{Action: "confirm", Browser: true})
		if err != nil || res.Page != oauthprovider.PageSuccess {
			t.Fatalf("a confirmation inside EndSessionConfirmTTL: %+v %v", res, err)
		}
	})
}

// EndSessionHintGrace: an expired id_token_hint ends the session it names
// up to the grace past its exp; without the option, or past the grace, it
// is refused.
func TestOAuthProvider_EndSessionHintGrace(t *testing.T) {
	for _, c := range []struct {
		name    string
		grace   time.Duration
		advance time.Duration
		ok      bool
	}{
		{"default refuses an expired hint", 0, 10 * time.Minute, false},
		{"inside the grace", time.Hour, 10 * time.Minute, true},
		{"past the grace", time.Hour, 2 * time.Hour, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			eachEngine(t, func(t *testing.T, e *env) {
				opts := []oauthprovider.Option{oauthprovider.IDTokenTTL(time.Minute)}
				if c.grace > 0 {
					opts = append(opts, oauthprovider.EndSessionHintGrace(c.grace))
				}
				o := newOPEnv(t, e, opts...)
				reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, EnableEndSession: true})
				tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
				e.clock.Advance(c.advance)
				_, err := o.op.EndSession(anon(o.a), oauthprovider.EndSessionRequest{IDTokenHint: tok.IDToken})
				s, _, _, rerr := o.a.ResolveSession(context.Background(), o.token)
				ended := rerr != nil || s == nil
				switch {
				case c.ok && (err != nil || !ended):
					t.Fatalf("hint inside the grace: err %v, session ended %v", err, ended)
				case !c.ok && !errors.Is(err, oauthprovider.ErrInvalidToken):
					t.Fatalf("hint refused: %v", err)
				case !c.ok && ended:
					t.Fatalf("a refused hint ended the session: %v", rerr)
				}
			})
		})
	}
}

// ValidatePostLogoutRedirectURI widens the exact match, and a URI it
// accepts must still be a valid redirect URI.
func TestOAuthProvider_ValidatePostLogoutRedirectURI(t *testing.T) {
	const after = "https://client.example/bye"
	eachEngine(t, func(t *testing.T, e *env) {
		var gotRegistered []string
		o := newOPEnv(t, e, oauthprovider.ValidatePostLogoutRedirectURI(func(uri string, registered []string, exact bool) bool {
			gotRegistered = registered
			return exact || strings.HasPrefix(uri, after+"?") || strings.Contains(uri, "#")
		}))
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, EnableEndSession: true, ClientMetadata: oauthprovider.ClientMetadata{PostLogoutRedirectURIs: []string{after}}})
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		for uri, want := range map[string]string{
			after:                         after + "?state=s",
			after + "?from=op":            after + "?from=op&state=s",
			"https://other.example/bye":   "",
			"https://client.example/x#fr": "",
		} {
			res, err := o.op.EndSession(anon(o.a), oauthprovider.EndSessionRequest{IDTokenHint: tok.IDToken, PostLogoutRedirectURI: uri, State: "s"})
			if err != nil || res.RedirectTo != want {
				t.Fatalf("%s: %+v %v, want redirect %q", uri, res, err, want)
			}
		}
		if len(gotRegistered) != 1 || gotRegistered[0] != after {
			t.Fatalf("validator saw registered %v", gotRegistered)
		}
	})
}

// BackchannelDelivery takes over each logout token, signed with
// BackchannelLogoutTokenTTL, naming the client, URI, session and user.
func TestOAuthProvider_BackchannelDeliveryAndTTL(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var mu sync.Mutex
		var got []oauthprovider.BackchannelLogout
		o := newOPEnv(t, e, oauthprovider.BackchannelLogoutTokenTTL(30*time.Second), oauthprovider.BackchannelDelivery(func(_ context.Context, l oauthprovider.BackchannelLogout) error {
			mu.Lock()
			defer mu.Unlock()
			got = append(got, l)
			return errors.New("queued elsewhere")
		}))
		const bc = "https://client.example/bc"
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, ClientMetadata: oauthprovider.ClientMetadata{BackchannelLogoutURI: bc}})
		o.code(t, authzReq(reg.ClientID))
		must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		sess := must[*auth.Session](t)(func() (*auth.Session, error) {
			s, _, _, err := o.a.ResolveSession(context.Background(), o.token)
			return s, err
		}())
		if err := o.a.SignOut(request(o.a, o.token)); err != nil {
			t.Fatal(err)
		}
		o.a.WaitDeliveries()
		mu.Lock()
		defer mu.Unlock()
		if len(got) != 1 {
			t.Fatalf("deliveries = %d, want 1", len(got))
		}
		l := got[0]
		if l.ClientID != reg.ClientID || l.URI != bc || l.SessionID != sess.ID || l.UserID != o.user.ID {
			t.Fatalf("delivery = %+v", l)
		}
		v := jwt.Verifier{Keys: jwt.KeysFromJWKS(o.jw.PublicKeys()), Issuer: testBaseURL, Audience: reg.ClientID, Now: e.clock.Now, Types: []string{oauthprovider.LogoutTokenType}}
		if _, err := v.Verify(l.LogoutToken); err != nil {
			t.Fatalf("logout token: %v", err)
		}
		c := claimsOf(t, l.LogoutToken)
		if c["exp"].(float64)-c["iat"].(float64) != 30 {
			t.Fatalf("logout token lifetime = %v s, want 30", c["exp"].(float64)-c["iat"].(float64))
		}
	})
}

// edClient registers a private_key_jwt client_credentials client with an
// inline Ed25519 key.
func (o opEnv) edClient(t *testing.T) (oauthprovider.Registration, ed25519.PrivateKey) {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	jwks := must[[]byte](t)(json.Marshal(map[string]any{"keys": []map[string]string{{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub), "kid": "k1", "alg": "EdDSA", "use": "sig"}}}))
	reg := o.client(t, oauthprovider.ClientSpec{ClientCredentialsScopes: []string{"api:read"}, ClientMetadata: oauthprovider.ClientMetadata{AuthMethod: oauthprovider.AuthMethodPrivateKeyJWT, JWKS: jwks, GrantTypes: []string{"client_credentials"}, Scope: "api:read"}})
	return reg, key
}

// ClockSkew: an assertion 10 s past its exp passes the default 30 s skew
// and fails with none; a jti stays recorded for the skew past exp, so a
// sweep in between cannot free it for a replay.
func TestOAuthProvider_ClockSkew(t *testing.T) {
	for _, c := range []struct {
		name string
		opts []oauthprovider.Option
		ok   bool
	}{
		{"default 30s", nil, true},
		{"none", []oauthprovider.Option{oauthprovider.ClockSkew(0)}, false},
		{"one minute", []oauthprovider.Option{oauthprovider.ClockSkew(time.Minute)}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			eachEngine(t, func(t *testing.T, e *env) {
				o := newOPEnv(t, e, append([]oauthprovider.Option{oauthprovider.Scopes("openid", "api:read")}, c.opts...)...)
				reg, key := o.edClient(t)
				now := e.clock.Now()
				a := assertion(t, key, "k1", map[string]any{"iss": reg.ClientID, "sub": reg.ClientID, "aud": testBaseURL + "/oauth2/token", "jti": "j1", "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(-10 * time.Second).Unix()})
				err := o.op.ConsumeClientAssertion(anon(o.a), reg.ClientID, a, testBaseURL+"/oauth2/token")
				if (err == nil) != c.ok {
					t.Fatalf("assertion 10 s past exp: %v, want ok %v", err, c.ok)
				}
			})
		})
	}
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e, oauthprovider.Scopes("openid", "api:read"), oauthprovider.ClockSkew(time.Hour))
		reg, key := o.edClient(t)
		now := e.clock.Now()
		a := assertion(t, key, "k1", map[string]any{"iss": reg.ClientID, "sub": reg.ClientID, "aud": testBaseURL + "/oauth2/token", "jti": "j2", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()})
		if err := o.op.ConsumeClientAssertion(anon(o.a), reg.ClientID, a, testBaseURL+"/oauth2/token"); err != nil {
			t.Fatal(err)
		}
		e.clock.Advance(10 * time.Minute)
		if _, err := o.op.Sweep(context.Background(), e.clock.Now()); err != nil {
			t.Fatal(err)
		}
		if err := o.op.ConsumeClientAssertion(anon(o.a), reg.ClientID, a, testBaseURL+"/oauth2/token"); !errors.Is(err, oauthprovider.ErrInvalidClient) {
			t.Fatalf("a replay inside the skew after a sweep: %v", err)
		}
	})
}

// DPoPClockSkew: a proof 10 s in the future fails the default 5 s and
// passes a minute; with none, 1 s ahead already fails.
func TestOAuthProvider_DPoPClockSkew(t *testing.T) {
	for _, c := range []struct {
		name  string
		opts  []oauthprovider.Option
		shift time.Duration
		ok    bool
	}{
		{"default refuses 10s ahead", nil, 10 * time.Second, false},
		{"default accepts 4s ahead", nil, 4 * time.Second, true},
		{"a minute accepts 10s ahead", []oauthprovider.Option{oauthprovider.DPoPClockSkew(time.Minute)}, 10 * time.Second, true},
		{"none refuses 1s ahead", []oauthprovider.Option{oauthprovider.DPoPClockSkew(0)}, time.Second, false},
		{"none accepts now", []oauthprovider.Option{oauthprovider.DPoPClockSkew(0)}, 0, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			eachEngine(t, func(t *testing.T, e *env) {
				o := newOPEnv(t, e, c.opts...)
				key := newDPoPKey(t, e.clock.Now)
				reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, ClientMetadata: oauthprovider.ClientMetadata{DPoPBoundAccessTokens: true}})
				req := exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)
				req.DPoPProof = key.proof(t, "POST", testBaseURL+"/oauth2/token", "", c.shift, nil)
				_, err := o.op.Token(anon(o.a), req)
				if c.ok && err != nil || !c.ok && !errors.Is(err, oauthprovider.ErrInvalidDPoPProof) {
					t.Fatalf("proof %v ahead: %v, want ok %v", c.shift, err, c.ok)
				}
			})
		})
	}
}

// ScopeClaims replaces which scope releases which built-in claim, in the
// ID token and at userinfo.
func TestOAuthProvider_ScopeClaims(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e, oauthprovider.Scopes("openid", "profile", "email", "offline_access", "contact"),
			oauthprovider.ScopeClaims(map[string][]string{"contact": {"email", "email_verified"}, "email": {"email"}}))
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		for scope, want := range map[string]map[string]bool{
			"openid email":   {"email": true, "email_verified": false},
			"openid contact": {"email": true, "email_verified": true},
			"openid profile": {"email": false, "email_verified": false},
		} {
			in := authzReq(reg.ClientID)
			in.Scope = scope
			tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, in), opVerifier)))
			info := must[map[string]any](t)(o.op.UserInfo(anon(o.a), tok.AccessToken))
			for name, src := range map[string]map[string]any{"id token": claimsOf(t, tok.IDToken), "userinfo": info} {
				for claim, present := range want {
					if _, ok := src[claim]; ok != present {
						t.Fatalf("%s, %s: %s present %v, want %v (%v)", scope, name, claim, ok, present, src)
					}
				}
			}
		}
	})
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e)
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		in := authzReq(reg.ClientID)
		in.Scope = "openid email"
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, in), opVerifier)))
		if c := claimsOf(t, tok.IDToken); c["email"] == nil || c["email_verified"] == nil {
			t.Fatalf("default email scope = %v", c)
		}
	})
}

// RenderPage takes over the error and logout pages with the data the
// built-in ones show; without it the built-in pages keep their headers.
func TestOAuthProvider_RenderPage(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var pages []oauthprovider.PageData
		o := newOPEnv(t, e, oauthprovider.RenderPage(func(w http.ResponseWriter, _ *http.Request, d oauthprovider.PageData) {
			pages = append(pages, d)
			w.WriteHeader(d.Status)
			_, _ = w.Write([]byte("app page " + d.Page))
		}))
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, EnableEndSession: true})
		w := c1Do(o.op.Handler(), http.MethodGet, "/oauth2/authorize?response_type=code&client_id=unknown&redirect_uri="+url.QueryEscape(opRedirect), "", "", http.Header{"Accept": {"text/html"}})
		if w.Code != http.StatusBadRequest || w.Body.String() != "app page error" || w.Header().Get("Content-Security-Policy") == "" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("error page: %d %q %v", w.Code, w.Body.String(), w.Header())
		}
		o.endSessionPage(t, reg.ClientID)
		if len(pages) != 2 || pages[0].Page != oauthprovider.PageError || pages[0].Code != "invalid_client" || pages[0].Description == "" ||
			pages[1].Page != oauthprovider.PageConfirm || pages[1].ConfirmAction != testBaseURL+"/oauth2/end-session/confirm" || pages[1].Status != http.StatusOK {
			t.Fatalf("pages = %+v", pages)
		}
	})
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e)
		w := c1Do(o.op.Handler(), http.MethodGet, "/oauth2/authorize?response_type=code&client_id=unknown&redirect_uri="+url.QueryEscape(opRedirect), "", "", http.Header{"Accept": {"text/html"}})
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "<code>invalid_client</code>") || !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Fatalf("built-in error page: %d %q %v", w.Code, w.Body.String(), w.Header())
		}
	})
}

// MaxRequestBytes: a token request over the limit is refused before it is
// read; the default takes one far larger.
func TestOAuthProvider_MaxRequestBytes(t *testing.T) {
	body := "grant_type=client_credentials&scope=" + strings.Repeat("a", 600)
	for _, c := range []struct {
		name    string
		opts    []oauthprovider.Option
		refused bool
	}{
		{"default", nil, false},
		{"512 bytes", []oauthprovider.Option{oauthprovider.MaxRequestBytes(512)}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			eachEngine(t, func(t *testing.T, e *env) {
				o := newOPEnv(t, e, c.opts...)
				w := c1Do(o.op.Handler(), http.MethodPost, "/oauth2/token", "application/x-www-form-urlencoded", body, nil)
				// Without credentials the request fails either way; the size
				// decides whether it fails as malformed or as unauthenticated.
				if got := c1Error(w); (got == "invalid_request") != c.refused {
					t.Fatalf("answer %d %s", w.Code, w.Body.String())
				}
			})
		})
	}
}

// tokenEvents records OnTokenEvent.
type tokenEvents struct {
	mu sync.Mutex
	ev []oauthprovider.TokenEvent
}

func (r *tokenEvents) add(_ context.Context, e oauthprovider.TokenEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ev = append(r.ev, e)
}

// take returns the events since the last take.
func (r *tokenEvents) take() []oauthprovider.TokenEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.ev
	r.ev = nil
	return out
}

// OnTokenEvent reports each issuance and revocation with what identifies
// it, and nothing for an issuance that rolled back; a refresh token's reuse
// also reaches the security stream.
func TestOAuthProvider_OnTokenEvent(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		rec := &tokenEvents{}
		sink := &auth.MemorySecuritySink{}
		veto := false
		o := newOPEnvWith(t, e, []auth.Option{
			auth.WithSecret([]byte(strings.Repeat("s", auth.MinSecretSize))),
			auth.WithSecuritySink(sink, auth.SecurityQueue{}),
			auth.WithOperationHooks(auth.OperationHook{Match: []auth.EndpointID{oauthprovider.EndpointToken}, After: func(context.Context, *auth.Call, any) error {
				if veto {
					return errors.New("vetoed")
				}
				return nil
			}}),
		}, oauthprovider.OnTokenEvent(rec.add))
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		ev := rec.take()
		if len(ev) != 1 || ev[0].Kind != oauthprovider.TokenEventIssued || ev[0].GrantType != "authorization_code" || ev[0].ClientID != reg.ClientID ||
			ev[0].UserID != o.user.ID || ev[0].SessionID == "" || ev[0].Family == "" || ev[0].TokenID == "" || ev[0].RefreshExpiresAt.IsZero() ||
			!ev[0].AccessExpiresAt.Equal(e.clock.Now().Add(time.Hour)) || strings.Join(ev[0].Scopes, " ") != opScopes {
			t.Fatalf("code exchange events = %+v", ev)
		}
		family := ev[0].Family
		refresh := func(r string) (oauthprovider.TokenResponse, error) {
			return o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "refresh_token", RefreshToken: r, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic})
		}
		next := must[oauthprovider.TokenResponse](t)(refresh(tok.RefreshToken))
		if ev = rec.take(); len(ev) != 1 || ev[0].GrantType != "refresh_token" || ev[0].Family != family {
			t.Fatalf("refresh events = %+v", ev)
		}
		// An issuance the pipeline rolls back is not reported.
		veto = true
		if _, err := refresh(next.RefreshToken); err == nil {
			t.Fatal("the vetoed refresh succeeded")
		}
		veto = false
		if ev = rec.take(); len(ev) != 0 {
			t.Fatalf("a rolled-back issuance was reported: %+v", ev)
		}
		// Reuse of the first, rotated token revokes the family.
		if _, err := refresh(tok.RefreshToken); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
			t.Fatalf("reuse: %v", err)
		}
		if ev = rec.take(); len(ev) != 1 || ev[0].Kind != oauthprovider.TokenEventRevoked || ev[0].Reason != oauthprovider.RevokeReasonReuse || ev[0].Family != family || ev[0].ClientID != reg.ClientID || ev[0].UserID != o.user.ID {
			t.Fatalf("reuse events = %+v", ev)
		}
		if err := o.a.FlushSecurity(context.Background()); err != nil {
			t.Fatal(err)
		}
		if rs := sink.OfKind(auth.SecurityTokenReplay); len(rs) != 1 || rs[0].Severity != auth.SeverityAlert || rs[0].Attrs[oauthprovider.AttrClientID] != reg.ClientID ||
			rs[0].Attrs[oauthprovider.AttrGrantKind] != "refresh_token" || rs[0].UserID != o.user.ID {
			t.Fatalf("security events = %+v", rs)
		}
		// A code presented twice is a replay too.
		code := o.code(t, authzReq(reg.ClientID))
		second := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, code, opVerifier)))
		rec.take()
		if _, err := o.op.Token(anon(o.a), exchange(reg, code, opVerifier)); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
			t.Fatalf("code reuse: %v", err)
		}
		if ev = rec.take(); len(ev) != 1 || ev[0].Reason != oauthprovider.RevokeReasonReuse {
			t.Fatalf("code reuse events = %+v", ev)
		}
		if err := o.a.FlushSecurity(context.Background()); err != nil {
			t.Fatal(err)
		}
		if rs := sink.OfKind(auth.SecurityTokenReplay); len(rs) != 2 || rs[1].Attrs[oauthprovider.AttrGrantKind] != "authorization_code" {
			t.Fatalf("code replay security events = %+v", rs)
		}
		// The client revokes an access token: one row, by its id.
		third := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		rec.take()
		if err := o.op.Revoke(anon(o.a), oauthprovider.RevokeRequest{Token: third.AccessToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}); err != nil {
			t.Fatal(err)
		}
		if ev = rec.take(); len(ev) != 1 || ev[0].Reason != oauthprovider.RevokeReasonClientRequest || ev[0].TokenID == "" || ev[0].Family != "" {
			t.Fatalf("revoke events = %+v", ev)
		}
		// Revoking it again changes nothing and reports nothing.
		if err := o.op.Revoke(anon(o.a), oauthprovider.RevokeRequest{Token: third.AccessToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}); err != nil {
			t.Fatal(err)
		}
		if ev = rec.take(); len(ev) != 0 {
			t.Fatalf("a repeated revoke was reported: %+v", ev)
		}
		_ = second
		// Signing out ends the session's live access token; under
		// offline_access its refresh token stays (AccessOnly).
		must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, authzReq(reg.ClientID)), opVerifier)))
		live := rec.take()
		if err := o.a.SignOut(request(o.a, o.token)); err != nil {
			t.Fatal(err)
		}
		if ev = rec.take(); len(ev) != 1 || ev[0].Reason != oauthprovider.RevokeReasonSessionEnded || !ev[0].AccessOnly || ev[0].TokenID != live[0].TokenID || ev[0].SessionID == "" {
			t.Fatalf("sign-out events = %+v", ev)
		}
		// The app's own revocation of everything one user holds.
		must[oauthprovider.RevokeUserResult](t)(o.op.RevokeUserForClient(context.Background(), oauthprovider.RevokeUserRequest{ClientID: reg.ClientID, UserID: o.user.ID}))
		if ev = rec.take(); len(ev) != 1 || ev[0].Reason != oauthprovider.RevokeReasonAdmin || ev[0].UserID != o.user.ID {
			t.Fatalf("admin revoke events = %+v", ev)
		}
	})
}

// ClientJWKSCacheTTL: a jwks_uri set is used for the whole TTL and fetched
// again after it.
func TestOAuthProvider_ClientJWKSCacheTTL(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		const jwksURL = testBaseURL + "/client/jwks.json"
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		served := string(must[[]byte](t)(json.Marshal(map[string]any{"keys": []map[string]string{p1JWK(t, key, "k1", "EdDSA")}})))
		fetches := 0
		o := newOPEnv(t, e, oauthprovider.Scopes("openid", "api:read"), oauthprovider.ClientJWKSCacheTTL(time.Hour), oauthprovider.ClientJWKSFetch(func(context.Context, string) ([]byte, error) {
			fetches++
			return []byte(served), nil
		}))
		meta := oauthprovider.ClientMetadata{Name: "K", AuthMethod: oauthprovider.AuthMethodPrivateKeyJWT, JWKSURI: jwksURL, GrantTypes: []string{"client_credentials"}, Scope: "api:read"}
		reg := o.client(t, oauthprovider.ClientSpec{ClientCredentialsScopes: []string{"api:read"}, ClientMetadata: meta})
		n := 0
		cc := func() error {
			n++
			now := e.clock.Now()
			a := p1JWS(t, key, "EdDSA", map[string]any{"kid": "k1", "typ": "JWT"}, map[string]any{"iss": reg.ClientID, "sub": reg.ClientID, "aud": testBaseURL, "jti": "j" + strings.Repeat("x", n), "exp": now.Add(time.Minute).Unix()})
			_, err := o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "client_credentials", ClientID: reg.ClientID, ClientAuthMethod: oauthprovider.AuthMethodPrivateKeyJWT, ClientAssertion: a})
			return err
		}
		for _, step := range []struct {
			advance time.Duration
			fetches int
		}{{0, 1}, {30 * time.Minute, 1}, {29 * time.Minute, 1}, {2 * time.Minute, 2}} {
			e.clock.Advance(step.advance)
			if err := cc(); err != nil || fetches != step.fetches {
				t.Fatalf("after %v: %v, fetches %d, want %d", step.advance, err, fetches, step.fetches)
			}
		}
	})
}

// CIMDFetchLimits: the document size cap applies whichever fetcher fetched
// it; a 6 KB document fails the default 5 KB and passes a 16 KB cap.
func TestOAuthProvider_CIMDFetchLimits(t *testing.T) {
	const id = "https://tool.example.com/oauth/client.json"
	doc := `{"client_id":"` + id + `","client_name":"Tool","redirect_uris":["` + opRedirect + `"]}` + strings.Repeat(" ", 6<<10)
	fetch := oauthprovider.CIMDFetch(func(context.Context, string) ([]byte, error) { return []byte(doc), nil })
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e, oauthprovider.ClientIDMetadataDocuments(fetch))
		if _, err := o.op.Authorize(request(o.a, o.token), authzReq(id)); !errors.Is(err, oauthprovider.ErrBadRedirectTarget) {
			t.Fatalf("a 6 KB document under the default cap: %v", err)
		}
	})
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e, oauthprovider.ClientIDMetadataDocuments(fetch, oauthprovider.CIMDFetchLimits(5*time.Second, 16<<10)))
		o.code(t, authzReq(id))
	})
}
