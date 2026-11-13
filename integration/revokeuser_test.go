package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authcli"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/oauthprovider"
	"github.com/ubgo/auth/plugin/password"
)

// The operator's revoke (RevokeUserForClient and `auth oauth-client
// revoke-user`): one user's tokens, unredeemed codes and consent at one
// client end at once, the client hears it on the back channel, and nothing
// of another user or another client moves.

// Paths of the relying parties' back-channel logout endpoints on the test
// receiver, one per client so a notice names the client it reached.
const (
	revokePathMain   = "/bc/main"
	revokePathOther  = "/bc/other"
	revokePathStrict = "/bc/strict"
)

// revokeGrantType is the grant IssueTokens names for the token issued on no
// session.
const revokeGrantType = "urn:example:operator-test"

// The users the revoke tests add beside alice: bob verified, carol with an
// address she never verified.
const (
	bobEmail   = "bob@example.com"
	carolEmail = "carol@example.com"
)

// logoutNotice is one back-channel logout request the receiver got.
type logoutNotice struct {
	path, token string
}

// logoutReceiver is a relying party's back channel: it keeps every logout
// token posted to it, by path.
type logoutReceiver struct {
	srv  *httptest.Server
	mu   sync.Mutex
	got  []logoutNotice
	seen int
}

func newLogoutReceiver(t *testing.T) *logoutReceiver {
	t.Helper()
	r := &logoutReceiver{}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_ = req.ParseForm()
		r.mu.Lock()
		r.got = append(r.got, logoutNotice{path: req.URL.Path, token: req.PostForm.Get("logout_token")})
		r.mu.Unlock()
	}))
	t.Cleanup(r.srv.Close)
	return r
}

// since returns the notices received after the previous call, once a's
// background deliveries have finished.
func (r *logoutReceiver) since(a *auth.Auth) []logoutNotice {
	a.WaitDeliveries()
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]logoutNotice(nil), r.got[r.seen:]...)
	r.seen = len(r.got)
	return out
}

// signUpOther signs up raw (verifying the address when verify is set) and
// returns the sign-in result: the user and a session.
func (w *revokeWorld) signUpOther(t *testing.T, raw string, verify bool) password.SignInResult {
	t.Helper()
	o := w.o
	o.a.WaitDeliveries()
	res, err := o.pw.SignUp(anon(o.a), password.SignUpRequest{Identifier: raw, Password: secret, Name: raw})
	if err != nil {
		t.Fatalf("sign up %s: %v", raw, err)
	}
	if verify {
		if _, err := w.em.Verify(anon(o.a), o.e.mail.LastToken(t, o.a, raw)); err != nil {
			t.Fatalf("verify %s: %v", raw, err)
		}
	}
	return res
}

// revokeWorld is a provider with three clients that consent is asked for,
// each with a back channel on one receiver, and alice and bob holding
// tokens at them.
type revokeWorld struct {
	o                   opEnv
	em                  *email.Plugin
	rp                  *logoutReceiver
	main, other, strict oauthprovider.Registration
	bob                 password.SignInResult
	// alice's at main: two pairs on her session, one on no session, and a
	// code she never exchanged; at other and strict, one pair each.
	aliceMain, aliceMain2, aliceNoSession oauthprovider.TokenResponse
	aliceCode                             string
	aliceOther, aliceStrict, bobMain      oauthprovider.TokenResponse
	aliceSession                          string
}

func newRevokeWorld(t *testing.T, e *env) *revokeWorld {
	t.Helper()
	rp := newLogoutReceiver(t)
	// newOPEnv, keeping the email plugin, which signUpOther verifies with.
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	jw := jwt.New(jwt.WithSigningKey(key), jwt.Issuer(testBaseURL))
	op := oauthprovider.New(jw, oauthprovider.Issuer(testBaseURL), oauthprovider.LoginPage("/login"), oauthprovider.ConsentPage("/consent"), oauthprovider.BackchannelHTTPClient(rp.srv.Client()))
	em, pw := e.emailPlugin(), e.passwordPlugin()
	a := e.newAuth(t, nil, em, pw, jw, op)
	up := signUpVerified(t, e, a, pw, em)
	o := opEnv{pw: pw, e: e, a: a, jw: jw, op: op, user: up.User, token: up.Token}
	w := &revokeWorld{o: o, em: em, rp: rp}
	bc := func(path string, sessionRequired bool) oauthprovider.ClientSpec {
		return oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{BackchannelLogoutURI: rp.srv.URL + path, BackchannelLogoutSessionRequired: sessionRequired}}
	}
	w.main, w.other, w.strict = o.client(t, bc(revokePathMain, false)), o.client(t, bc(revokePathOther, false)), o.client(t, bc(revokePathStrict, true))
	pair := func(as opEnv, reg oauthprovider.Registration) oauthprovider.TokenResponse {
		return must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, as.code(t, authzReq(reg.ClientID)), opVerifier)))
	}
	w.aliceMain, w.aliceMain2 = pair(o, w.main), pair(o, w.main)
	w.aliceCode = o.code(t, authzReq(w.main.ClientID))
	w.aliceNoSession = must[oauthprovider.TokenResponse](t)(o.op.IssueTokens(context.Background(), oauthprovider.IssueRequest{GrantType: revokeGrantType, ClientID: w.main.ClientID, UserID: o.user.ID, Scopes: []string{"openid"}}))
	w.aliceOther, w.aliceStrict = pair(o, w.other), pair(o, w.strict)
	must[oauthprovider.TokenResponse](t)(o.op.IssueTokens(context.Background(), oauthprovider.IssueRequest{GrantType: revokeGrantType, ClientID: w.strict.ClientID, UserID: o.user.ID, Scopes: []string{"openid"}}))
	w.bob = w.signUpOther(t, bobEmail, true)
	asBob := o
	asBob.user, asBob.token = w.bob.User, w.bob.Token
	w.bobMain = pair(asBob, w.main)
	sess, _, _, err := o.a.ResolveSession(context.Background(), o.token)
	if err != nil {
		t.Fatal(err)
	}
	w.aliceSession = sess.ID
	rp.since(o.a) // nothing so far; start counting from here
	return w
}

// refresh presents a refresh token for reg.
func (w *revokeWorld) refresh(reg oauthprovider.Registration, rt string) error {
	_, err := w.o.op.Token(anon(w.o.a), oauthprovider.TokenRequest{GrantType: oauthprovider.GrantRefreshToken, RefreshToken: rt, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic})
	return err
}

// active reports what introspection by reg says about tok.
func (w *revokeWorld) active(t *testing.T, reg oauthprovider.Registration, tok string) bool {
	t.Helper()
	in := must[oauthprovider.Introspection](t)(w.o.op.Introspect(anon(w.o.a), oauthprovider.IntrospectRequest{Token: tok, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}))
	return in.Active
}

// asksConsent reports whether as's next authorization at reg goes to the
// consent page, that is whether no consent is stored.
func (w *revokeWorld) asksConsent(t *testing.T, as opEnv, reg oauthprovider.Registration) bool {
	t.Helper()
	res := must[oauthprovider.AuthorizeResult](t)(w.o.op.Authorize(request(w.o.a, as.token), authzReq(reg.ClientID)))
	return must[*url.URL](t)(url.Parse(res.RedirectTo)).Path == "/consent"
}

// assertRevoked checks that a pair is dead everywhere: its access token
// fails verification and introspection, and its refresh token is refused.
func (w *revokeWorld) assertRevoked(t *testing.T, name string, reg oauthprovider.Registration, tok oauthprovider.TokenResponse) {
	t.Helper()
	if _, err := w.o.op.VerifyAccessToken(context.Background(), tok.AccessToken); !errors.Is(err, oauthprovider.ErrInvalidToken) {
		t.Errorf("%s: access token = %v, want invalid_token", name, err)
	}
	if w.active(t, reg, tok.AccessToken) {
		t.Errorf("%s: introspection says the access token is active", name)
	}
	if tok.RefreshToken != "" {
		if w.active(t, reg, tok.RefreshToken) {
			t.Errorf("%s: introspection says the refresh token is active", name)
		}
		if err := w.refresh(reg, tok.RefreshToken); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
			t.Errorf("%s: refresh = %v, want invalid_grant", name, err)
		}
	}
}

// assertAlive checks that a pair still works: verification, introspection
// and a refresh.
func (w *revokeWorld) assertAlive(t *testing.T, name string, reg oauthprovider.Registration, tok oauthprovider.TokenResponse) {
	t.Helper()
	if _, err := w.o.op.VerifyAccessToken(context.Background(), tok.AccessToken); err != nil {
		t.Errorf("%s: access token = %v, want valid", name, err)
	}
	if !w.active(t, reg, tok.AccessToken) {
		t.Errorf("%s: introspection says the access token is inactive", name)
	}
	if err := w.refresh(reg, tok.RefreshToken); err != nil {
		t.Errorf("%s: refresh = %v, want a new pair", name, err)
	}
}

// RevokeUserForClient ends alice's tokens (on her session and on none), her
// unexchanged code and her consent at one client, in one go; the client is
// sent one logout token per session and one without a session; alice's
// tokens at the other clients and bob's at the same client are untouched;
// a second run changes nothing and notifies nobody.
//
//ds:def id=testoauthprovider-revokeuserforclient-h7c2mv4q owner=@khanakia stability=stable
func TestOAuthProvider_RevokeUserForClient(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newRevokeWorld(t, e)
		o := w.o
		got, err := o.op.RevokeUserForClient(context.Background(), oauthprovider.RevokeUserRequest{ClientID: w.main.ClientID, UserID: o.user.ID})
		if err != nil {
			t.Fatal(err)
		}
		want := oauthprovider.RevokeUserResult{Tokens: 3, Codes: 1, Consent: true, LogoutNotices: 2}
		if got != want {
			t.Fatalf("result = %+v, want %+v", got, want)
		}

		// The client heard it: one notice for alice's session (sub and sid),
		// one for the token issued on no session (sub alone).
		notices := w.rp.since(o.a)
		if len(notices) != 2 {
			t.Fatalf("logout notices = %d, want 2: %+v", len(notices), notices)
		}
		v := jwt.Verifier{Keys: jwt.KeysFromJWKS(o.jw.PublicKeys()), Issuer: testBaseURL, Audience: w.main.ClientID, Now: e.clock.Now, Types: []string{oauthprovider.LogoutTokenType}}
		sids := map[string]bool{}
		for _, n := range notices {
			if n.path != revokePathMain {
				t.Fatalf("a notice reached %s, want only %s", n.path, revokePathMain)
			}
			lt, err := v.Verify(n.token)
			if err != nil || lt.Subject != o.user.ID || !strings.Contains(string(lt.Extra["events"]), "backchannel-logout") {
				t.Fatalf("logout token = %+v %v", lt, err)
			}
			sids[lt.SessionID] = true
		}
		if !sids[w.aliceSession] || !sids[""] {
			t.Fatalf("logout token sids = %v, want alice's session %q and none", sids, w.aliceSession)
		}

		for name, tok := range map[string]oauthprovider.TokenResponse{"alice at main": w.aliceMain, "alice's second pair at main": w.aliceMain2, "alice's sessionless token at main": w.aliceNoSession} {
			w.assertRevoked(t, name, w.main, tok)
		}
		if _, err := o.op.Token(anon(o.a), exchange(w.main, w.aliceCode, opVerifier)); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
			t.Errorf("alice's unexchanged code after the revoke = %v, want invalid_grant", err)
		}
		if !w.asksConsent(t, o, w.main) {
			t.Error("alice's consent to main survived the revoke")
		}

		// Untouched: alice elsewhere, bob here, and their consents.
		w.assertAlive(t, "alice at other", w.other, w.aliceOther)
		w.assertAlive(t, "alice at strict", w.strict, w.aliceStrict)
		w.assertAlive(t, "bob at main", w.main, w.bobMain)
		asBob := o
		asBob.token = w.bob.Token
		if w.asksConsent(t, asBob, w.main) || w.asksConsent(t, o, w.other) {
			t.Error("a consent of another user or another client was deleted")
		}
		if n := w.rp.since(o.a); len(n) != 0 {
			t.Fatalf("the checks above sent logout notices: %+v", n)
		}

		// Idempotent: nothing left, so all zero and no notice.
		again, err := o.op.RevokeUserForClient(context.Background(), oauthprovider.RevokeUserRequest{ClientID: w.main.ClientID, UserID: o.user.ID})
		if err != nil || again != (oauthprovider.RevokeUserResult{}) {
			t.Fatalf("second revoke = %+v %v, want all zero", again, err)
		}
		if n := w.rp.since(o.a); len(n) != 0 {
			t.Fatalf("the second revoke sent logout notices: %+v", n)
		}
	})
}

// A client that requires sid (backchannel_logout_session_required) is sent
// no notice for a token issued on no session; a disabled client is sent
// none at all, and its tokens are revoked all the same.
func TestOAuthProvider_RevokeUserForClientNotices(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newRevokeWorld(t, e)
		o := w.o
		got := must[oauthprovider.RevokeUserResult](t)(o.op.RevokeUserForClient(context.Background(), oauthprovider.RevokeUserRequest{ClientID: w.strict.ClientID, UserID: o.user.ID}))
		if got.Tokens != 2 || got.LogoutNotices != 1 {
			t.Fatalf("strict client = %+v, want 2 tokens and 1 notice (the sessionless token needs a sid)", got)
		}
		if n := w.rp.since(o.a); len(n) != 1 || n[0].path != revokePathStrict {
			t.Fatalf("strict client notices = %+v", n)
		}
		if err := o.op.SetClientDisabled(context.Background(), w.other.ClientID, true); err != nil {
			t.Fatal(err)
		}
		got = must[oauthprovider.RevokeUserResult](t)(o.op.RevokeUserForClient(context.Background(), oauthprovider.RevokeUserRequest{ClientID: w.other.ClientID, UserID: o.user.ID}))
		if got.Tokens != 1 || got.LogoutNotices != 0 {
			t.Fatalf("disabled client = %+v, want 1 token and no notice", got)
		}
		if n := w.rp.since(o.a); len(n) != 0 {
			t.Fatalf("a disabled client was notified: %+v", n)
		}
		if err := o.op.SetClientDisabled(context.Background(), w.other.ClientID, false); err != nil {
			t.Fatal(err)
		}
		w.assertRevoked(t, "alice at the re-enabled client", w.other, w.aliceOther)
	})
}

// An unknown or empty client is ErrClientNotFound and an unknown or empty
// user auth.ErrUserNotFound, and none of them revokes anything.
func TestOAuthProvider_RevokeUserForClientUnknown(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newRevokeWorld(t, e)
		o := w.o
		for name, c := range map[string]struct {
			in   oauthprovider.RevokeUserRequest
			want error
		}{
			"unknown client": {oauthprovider.RevokeUserRequest{ClientID: "cl_nobody", UserID: o.user.ID}, oauthprovider.ErrClientNotFound},
			"empty client":   {oauthprovider.RevokeUserRequest{UserID: o.user.ID}, oauthprovider.ErrClientNotFound},
			"unknown user":   {oauthprovider.RevokeUserRequest{ClientID: w.main.ClientID, UserID: "usr_nobody"}, auth.ErrUserNotFound},
			"empty user":     {oauthprovider.RevokeUserRequest{ClientID: w.main.ClientID}, auth.ErrUserNotFound},
		} {
			if got, err := o.op.RevokeUserForClient(context.Background(), c.in); !errors.Is(err, c.want) || got != (oauthprovider.RevokeUserResult{}) {
				t.Errorf("%s: %+v %v, want %v and nothing revoked", name, got, err, c.want)
			}
		}
		w.assertAlive(t, "alice at main", w.main, w.aliceMain)
	})
}

// Every database call RevokeUserForClient makes, failed in turn, reaches
// the caller, and the transaction leaves nothing half revoked.
func TestOAuthProvider_RevokeUserForClientFaults(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(ctx context.Context) error {
		w := newRevokeWorld(t, e.env)
		return func(ctx context.Context) error {
			_, err := w.o.op.RevokeUserForClient(ctx, oauthprovider.RevokeUserRequest{ClientID: w.main.ClientID, UserID: w.o.user.ID})
			if err != nil {
				// Rolled back: alice's first pair at main still works.
				if _, verr := w.o.op.VerifyAccessToken(context.Background(), w.aliceMain.AccessToken); verr != nil {
					t.Errorf("a failed revoke left the token revoked: %v", verr)
				}
			}
			return err
		}
	})
}

// `auth oauth-client revoke-user` names the client by id or name and the
// user by id or verified email; an unverified email, an unknown user or
// client and a bad argument list are refused with their exit codes; --json
// prints the result; a second run is success with all zero.
//
//ds:def id=testoauthclientcli-revokeuser-p5d8kz3n owner=@khanakia stability=stable
func TestOAuthClientCLI_RevokeUser(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newRevokeWorld(t, e)
		o := w.o
		carol := w.signUpOther(t, carolEmail, false)
		cli := func(args ...string) (int, string, string) {
			var out, errb bytes.Buffer
			code := authcli.MainWithStdin(context.Background(), o.a, append([]string{oauthprovider.CmdOAuthClient, oauthprovider.SubClientRevokeUser}, args...), strings.NewReader(""), &out, &errb)
			return code, out.String(), errb.String()
		}

		for name, args := range map[string][]string{
			"no arguments":   nil,
			"one argument":   {w.main.ClientID},
			"three":          {w.main.ClientID, o.user.ID, "extra"},
			"flag first":     {"--json", w.main.ClientID, o.user.ID},
			"unknown flag":   {w.main.ClientID, o.user.ID, "--force"},
			"flag as client": {"-x", o.user.ID},
		} {
			if code, _, _ := cli(args...); code != authcli.ExitUsage {
				t.Errorf("%s: exit %d, want ExitUsage", name, code)
			}
		}
		for name, c := range map[string]struct {
			args []string
			msg  string
		}{
			"unknown client":   {[]string{"Nobody", o.user.ID}, "oauthprovider.not_found"},
			"unknown user id":  {[]string{w.main.ClientID, "usr_nobody"}, "auth.user_not_found"},
			"unknown email":    {[]string{w.main.ClientID, "dave@example.com"}, "auth.user_not_found"},
			"unverified email": {[]string{w.main.ClientID, carolEmail}, "auth.user_not_found"},
		} {
			if code, _, errOut := cli(c.args...); code != authcli.ExitFailed || !strings.Contains(errOut, c.msg) {
				t.Errorf("%s: exit %d %q, want ExitFailed naming %s", name, code, errOut, c.msg)
			}
		}
		if _, err := o.op.RevokeUserForClient(context.Background(), oauthprovider.RevokeUserRequest{ClientID: w.main.ClientID, UserID: carol.User.ID}); err != nil {
			t.Fatalf("carol by id: %v", err)
		}
		w.assertAlive(t, "alice at main after the refusals", w.main, w.aliceMain)

		// By verified email (any case) and client name: alice at main.
		code, out, errOut := cli("Client", "  ALICE@example.com ")
		if code != authcli.ExitFailed || !strings.Contains(errOut, "use the client id") {
			// Every client of the world is named "Client": the name is ambiguous.
			t.Fatalf("ambiguous client name: %d %q %q", code, out, errOut)
		}
		code, out, errOut = cli(w.main.ClientID, "ALICE@example.com")
		if code != authcli.ExitOK {
			t.Fatalf("revoke by email: %d %q", code, errOut)
		}
		// 4 rows: the refresh in the check above rotated alice's first pair.
		wantLine := "revoked 4 tokens, 1 code and the consent of user " + o.user.ID + " (ALICE@example.com) at client " + w.main.ClientID + " (Client); 2 logout notices scheduled\n"
		if out != wantLine {
			t.Fatalf("output = %q, want %q", out, wantLine)
		}
		w.assertRevoked(t, "alice at main", w.main, w.aliceMain)

		// By user id with --json: bob at main.
		code, out, errOut = cli(w.main.ClientID, w.bob.User.ID, "--json")
		var res oauthprovider.RevokeUserResult
		if code != authcli.ExitOK || json.Unmarshal([]byte(out), &res) != nil || res != (oauthprovider.RevokeUserResult{Tokens: 1, Consent: true, LogoutNotices: 1}) {
			t.Fatalf("revoke --json: %d %q %q", code, out, errOut)
		}
		w.assertRevoked(t, "bob at main", w.main, w.bobMain)

		// Again: nothing left is success, all zero.
		code, out, _ = cli(w.main.ClientID, w.bob.User.ID)
		if code != authcli.ExitOK || out != "revoked 0 tokens, 0 codes and no consent of user "+w.bob.User.ID+" at client "+w.main.ClientID+" (Client); 0 logout notices scheduled\n" {
			t.Fatalf("second run: %d %q", code, out)
		}
		w.assertAlive(t, "alice at other", w.other, w.aliceOther)
	})
}
