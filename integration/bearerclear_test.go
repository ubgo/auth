package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/twofactor"
)

// A bearer client keeps its own token, so the server must tell it when that
// token is dead: authhttp answers an empty Set-Auth-Token. These tests pin
// when it does (a token naming no session, a session the call ended) and,
// as importantly, when it does not: a pending second-factor token and a live
// token are refused with the same auth.signed_out, and clearing either would
// sign a user out mid-flow.

// bearerCall sends one bearer-mode request with tok and returns the response
// with its body read.
func bearerCall(t *testing.T, web *app, method, path string, tok auth.Token, body any) (*http.Response, string) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, _ := http.NewRequest(method, web.srv.URL+path, rd)
	req.Header.Set(authhttp.TokenModeHeader, authhttp.TokenModeBearer)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok.Reveal())
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res, readAll(t, res)
}

// tokenCleared reports whether res told the client to forget its token: the
// header present with an empty value.
func tokenCleared(res *http.Response) bool {
	v, ok := res.Header[authhttp.SetTokenHeader]
	return ok && len(v) == 1 && v[0] == ""
}

func TestBearerClear_DeadTokenIsForgotten(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		web := newApp(t, a)
		up := signUpVerified(t, e, a, pw, em)
		signIn := func() auth.Token {
			return must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: aliceRaw, Password: secret})).Token
		}
		dead := func(name string, tok auth.Token) {
			t.Helper()
			res, body := bearerCall(t, web, http.MethodGet, "/auth/session", tok, nil)
			if res.StatusCode != http.StatusUnauthorized || !strings.Contains(body, "auth.signed_out") || !tokenCleared(res) {
				t.Fatalf("%s: %d %s header=%q", name, res.StatusCode, body, res.Header.Values(authhttp.SetTokenHeader))
			}
			// The same answer from the middleware in front of an app route.
			res, body = bearerCall(t, web, http.MethodGet, "/app/me", tok, nil)
			if res.StatusCode != http.StatusUnauthorized || !tokenCleared(res) {
				t.Fatalf("%s through RequireUser: %d %s header=%q", name, res.StatusCode, body, res.Header.Values(authhttp.SetTokenHeader))
			}
		}

		dead("unknown token", "not-a-session-token")

		revoked := signIn()
		sess, _, _, err := a.ResolveSession(context.Background(), revoked)
		if err != nil {
			t.Fatal(err)
		}
		if err := a.DeleteSession(context.Background(), up.User.ID, sess.ID); err != nil {
			t.Fatal(err)
		}
		dead("revoked token", revoked)

		// A live token is answered without the header.
		if res, body := bearerCall(t, web, http.MethodGet, "/auth/session", up.Token, nil); res.StatusCode != http.StatusOK || len(res.Header.Values(authhttp.SetTokenHeader)) != 0 {
			t.Fatalf("live token: %d %s header=%q", res.StatusCode, body, res.Header.Values(authhttp.SetTokenHeader))
		}

		// A wrong password on a live session is a refusal, not a dead token.
		res, body := bearerCall(t, web, http.MethodPost, "/auth/password/reauthenticate", up.Token, map[string]string{"password": "not the password"})
		if res.StatusCode == http.StatusOK || len(res.Header.Values(authhttp.SetTokenHeader)) != 0 {
			t.Fatalf("wrong password: %d %s header=%q", res.StatusCode, body, res.Header.Values(authhttp.SetTokenHeader))
		}

		// Signing in with a dead token still sends: the new token wins.
		res, body = bearerCall(t, web, http.MethodPost, "/auth/password/sign-in", revoked, map[string]string{"identifier": aliceRaw, "password": secret})
		if got := res.Header.Values(authhttp.SetTokenHeader); res.StatusCode != http.StatusOK || len(got) != 1 || got[0] == "" {
			t.Fatalf("sign-in with a dead token: %d %s header=%q", res.StatusCode, body, got)
		}

		e.clock.Advance(auth.DefaultSessionConfig.MaxLifetime + 1)
		dead("expired token", up.Token)

		// Cookie mode is unchanged: a dead cookie gets its 401 and no header.
		res = web.get(t, "/auth/session")
		if res.StatusCode != http.StatusUnauthorized || len(res.Header.Values(authhttp.SetTokenHeader)) != 0 {
			t.Fatalf("cookie mode: %d header=%q", res.StatusCode, res.Header.Values(authhttp.SetTokenHeader))
		}
	})
}

func TestBearerClear_SessionsValidAfterIsForgotten(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, []auth.Option{auth.WithStatelessSessions([]byte(strings.Repeat("s", auth.SealKeySize)))}, em, pw)
		web := newApp(t, a)
		up := signUpVerified(t, e, a, pw, em)
		other := must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: aliceRaw, Password: secret})).Token
		e.clock.Advance(time.Second)
		// Sign out everywhere from the other device: in stateless mode that
		// moves auth_user.sessions_valid_after, the only thing that ends
		// up.Token.
		if res, body := bearerCall(t, web, http.MethodPost, "/auth/sign-out-all", other, nil); res.StatusCode != http.StatusOK || !tokenCleared(res) {
			t.Fatalf("sign-out-all: %d %s header=%q", res.StatusCode, body, res.Header.Values(authhttp.SetTokenHeader))
		}
		res, body := bearerCall(t, web, http.MethodGet, "/auth/session", up.Token, nil)
		if res.StatusCode != http.StatusUnauthorized || !tokenCleared(res) {
			t.Fatalf("token older than sessions_valid_after: %d %s header=%q", res.StatusCode, body, res.Header.Values(authhttp.SetTokenHeader))
		}
	})
}

func TestBearerClear_LiveTokensAreKept(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		tf := twofactor.New(twofactor.WithEncryptionKey(twoFactorKey))
		a := e.newAuth(t, nil, em, pw, tf)
		web := newApp(t, a)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)
		enr := must[twofactor.EnrollResult](t)(tf.Enroll(ctx))
		must[twofactor.RecoveryCodes](t)(tf.Confirm(ctx, totpAt(t, enr.Secret, e.clock.Now())))

		res, body := bearerCall(t, web, http.MethodPost, "/auth/password/sign-in", "", map[string]string{"identifier": aliceRaw, "password": secret})
		pending := auth.Token(res.Header.Get(authhttp.SetTokenHeader))
		if res.StatusCode != http.StatusOK || pending == "" || !strings.Contains(body, `"secondFactorRequired":true`) {
			t.Fatalf("pending sign-in: %d %s", res.StatusCode, body)
		}
		// A pending token calling a SignedIn operation: auth.signed_out, but
		// the token is what twofactor.verify needs next.
		res, body = bearerCall(t, web, http.MethodGet, "/auth/session", pending, nil)
		if res.StatusCode != http.StatusUnauthorized || !strings.Contains(body, "auth.signed_out") || len(res.Header.Values(authhttp.SetTokenHeader)) != 0 {
			t.Fatalf("pending token on a signed-in operation: %d %s header=%q", res.StatusCode, body, res.Header.Values(authhttp.SetTokenHeader))
		}
		// A full token calling the pending-only operation: refused the same
		// way, and still alive.
		res, body = bearerCall(t, web, http.MethodPost, "/auth/twofactor/verify", up.Token, map[string]string{"code": "000000"})
		if res.StatusCode != http.StatusUnauthorized || !strings.Contains(body, "auth.signed_out") || len(res.Header.Values(authhttp.SetTokenHeader)) != 0 {
			t.Fatalf("full token on a pending operation: %d %s header=%q", res.StatusCode, body, res.Header.Values(authhttp.SetTokenHeader))
		}
		if _, _, _, err := a.ResolveSession(context.Background(), up.Token); err != nil {
			t.Fatalf("the full token died: %v", err)
		}
	})
}

func TestBearerClear_EndedSessionIsForgotten(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, []auth.Option{auth.WithAccountDeletion(auth.AccountDeletion{})}, em, pw)
		web := newApp(t, a)
		up := signUpVerified(t, e, a, pw, em)
		must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: aliceRaw, Password: secret}))

		// Revoking another session ends nothing of this one.
		var list auth.SessionsResult
		res, body := bearerCall(t, web, http.MethodGet, "/auth/sessions", up.Token, nil)
		if res.StatusCode != http.StatusOK || json.Unmarshal([]byte(body), &list) != nil {
			t.Fatalf("sessions: %d %s", res.StatusCode, body)
		}
		var own, theirs string
		for _, s := range list.Sessions {
			if s.Current {
				own = s.ID
			} else {
				theirs = s.ID
			}
		}
		res, body = bearerCall(t, web, http.MethodPost, "/auth/sessions/revoke", up.Token, map[string]string{"id": theirs})
		if res.StatusCode != http.StatusOK || len(res.Header.Values(authhttp.SetTokenHeader)) != 0 {
			t.Fatalf("revoke another session: %d %s header=%q", res.StatusCode, body, res.Header.Values(authhttp.SetTokenHeader))
		}
		res, body = bearerCall(t, web, http.MethodPost, "/auth/sessions/revoke", up.Token, map[string]string{"id": own})
		if res.StatusCode != http.StatusOK || !tokenCleared(res) {
			t.Fatalf("revoke own session: %d %s header=%q", res.StatusCode, body, res.Header.Values(authhttp.SetTokenHeader))
		}

		third := must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: aliceRaw, Password: secret})).Token
		res, body = bearerCall(t, web, http.MethodPost, "/auth/account/delete", third, nil)
		if res.StatusCode != http.StatusOK || !strings.Contains(body, `"deleted":true`) || !tokenCleared(res) {
			t.Fatalf("delete account: %d %s header=%q", res.StatusCode, body, res.Header.Values(authhttp.SetTokenHeader))
		}
	})
}
