package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/jwt"
)

// jwtKey makes a signing key for alg, failing the test if it cannot.
func jwtKey(t *testing.T, alg jwt.Alg) jwt.Option {
	t.Helper()
	k, err := jwt.GenerateKey(alg)
	if err != nil {
		t.Fatal(err)
	}
	return jwt.WithSigningKey(k)
}

// TestJWT_IssueOnSessionHeader: with IssueOnSession, the session read hands
// out the token the token route would, readable cross-origin; signed out,
// or with the option off, there is none. A Go caller of Auth.Session reads
// it with SessionJWT.
func TestJWT_IssueOnSessionHeader(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		jw := jwt.New(jwtKey(t, jwt.RS256), jwt.Audience("orders-api"), jwt.IssueOnSession())
		a := e.newAuth(t, nil, em, pw, jw)
		web := newApp(t, a)
		if res := web.post(t, "/auth/password/sign-up", map[string]string{"identifier": alice, "password": secret}); res.StatusCode != http.StatusOK {
			t.Fatalf("sign-up: %d", res.StatusCode)
		}
		v := jwt.Verifier{Keys: jwt.KeysFromJWKS(jw.PublicKeys()), Issuer: testBaseURL, Audience: "orders-api", Now: e.clock.Now}
		res := web.get(t, "/auth/session")
		tok := res.Header.Get(jwt.SetJWTHeader)
		if res.StatusCode != http.StatusOK || tok == "" || !strings.Contains(res.Header.Get("Access-Control-Expose-Headers"), jwt.SetJWTHeader) {
			t.Fatalf("session read = %d, %s=%q, expose %q", res.StatusCode, jwt.SetJWTHeader, tok, res.Header.Get("Access-Control-Expose-Headers"))
		}
		fromHeader, err := v.Verify(tok)
		if err != nil {
			t.Fatal(err)
		}
		// The token route's token names the same user and session.
		var route jwt.TokenResult
		rr := web.post(t, "/auth/jwt/token", nil)
		if err := json.Unmarshal([]byte(readAll(t, rr)), &route); err != nil || rr.StatusCode != http.StatusOK {
			t.Fatalf("token route: %d %v", rr.StatusCode, err)
		}
		fromRoute, err := v.Verify(route.Token)
		if err != nil || fromRoute.Subject != fromHeader.Subject || fromRoute.SessionID != fromHeader.SessionID || fromHeader.SessionID == "" {
			t.Fatalf("header %+v, route %+v, %v", fromHeader, fromRoute, err)
		}
		// The token route itself sets no header; only the session read does.
		if rr.Header.Get(jwt.SetJWTHeader) != "" {
			t.Fatal("the token route also set the header")
		}
		// Signed out: 401 and no token.
		res = newApp(t, a).get(t, "/auth/session")
		if res.StatusCode != http.StatusUnauthorized || res.Header.Get(jwt.SetJWTHeader) != "" {
			t.Fatalf("signed out = %d %q", res.StatusCode, res.Header.Get(jwt.SetJWTHeader))
		}
		// From Go, through the same operation.
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)
		if _, err := a.Session(ctx); err != nil {
			t.Fatal(err)
		}
		gtok, ok := jwt.SessionJWT(ctx)
		if c, err := v.Verify(gtok); !ok || err != nil || c.Subject != up.User.ID {
			t.Fatalf("SessionJWT = %v %+v %v", ok, c, err)
		}
		// Off by default.
		plain := jwt.New(jwtKey(t, jwt.EdDSA))
		b := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), plain)
		web = newApp(t, b)
		if res := web.post(t, "/auth/password/sign-up", map[string]string{"identifier": "bob@example.com", "password": secret}); res.StatusCode != http.StatusOK {
			t.Fatalf("sign-up: %d", res.StatusCode)
		}
		if res := web.get(t, "/auth/session"); res.StatusCode != http.StatusOK || res.Header.Get(jwt.SetJWTHeader) != "" {
			t.Fatalf("option off = %d %q", res.StatusCode, res.Header.Get(jwt.SetJWTHeader))
		}
	})
}

// TestJWT_SessionCacheEndToEnd: the JWT session cache hands the client a
// signed snapshot, the next request is answered from it, and sign-out
// clears it, on every engine and with every algorithm.
func TestJWT_SessionCacheEndToEnd(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		for _, alg := range jwt.AlgValues {
			t.Run(string(alg), func(t *testing.T) {
				em, pw := e.emailPlugin(), e.passwordPlugin()
				jw := jwt.New(jwtKey(t, alg))
				a := e.newAuth(t, []auth.Option{auth.WithSessionCache(jwt.NewSessionCache(jw), time.Minute)}, em, pw, jw)
				web := newApp(t, a)
				if res := web.post(t, "/auth/password/sign-up", map[string]string{"identifier": alice, "password": secret}); res.StatusCode != http.StatusOK {
					t.Fatalf("sign-up: %d", res.StatusCode)
				}
				if res := web.get(t, "/app/me"); res.StatusCode != http.StatusOK {
					t.Fatalf("first /app/me: %d", res.StatusCode)
				}
				c := transportCookie(web, authhttp.CacheCookieName)
				if c == nil || strings.Count(c.Value, ".") != 2 {
					t.Fatalf("cache cookie = %v", c)
				}
				hb, err := base64.RawURLEncoding.DecodeString(strings.Split(c.Value, ".")[0])
				if err != nil || !strings.Contains(string(hb), `"typ":"`+jwt.SessionCacheType+`"`) || !strings.Contains(string(hb), `"alg":"`+string(alg)+`"`) {
					t.Fatalf("snapshot header = %s %v", hb, err)
				}
				if res := web.get(t, "/app/me"); res.StatusCode != http.StatusOK {
					t.Fatalf("/app/me from the snapshot: %d", res.StatusCode)
				}
				if res := web.post(t, "/auth/sign-out", nil); res.StatusCode != http.StatusOK {
					t.Fatalf("sign-out: %d", res.StatusCode)
				}
				if c := transportCookie(web, authhttp.CacheCookieName); c != nil {
					t.Fatalf("the snapshot survived sign-out: %v", c)
				}
				if res := web.get(t, "/app/me"); res.StatusCode != http.StatusUnauthorized {
					t.Fatalf("/app/me after sign-out: %d", res.StatusCode)
				}
			})
		}
	})
}

// TestJWT_SessionCacheSkipsTheDatabase: with the snapshot, a request makes
// no database call at all, which is the cache's whole point.
func TestJWT_SessionCacheSkipsTheDatabase(t *testing.T) {
	e := newFaultEnv(t)
	em, pw := e.emailPlugin(), e.passwordPlugin()
	jw := jwt.New(jwtKey(t, jwt.ES256))
	a := e.newAuth(t, []auth.Option{auth.WithSessionCache(jwt.NewSessionCache(jw), time.Minute)}, em, pw, jw)
	web := newApp(t, a)
	if res := web.post(t, "/auth/password/sign-up", map[string]string{"identifier": alice, "password": secret}); res.StatusCode != http.StatusOK {
		t.Fatalf("sign-up: %d", res.StatusCode)
	}
	if res := web.get(t, "/app/me"); res.StatusCode != http.StatusOK {
		t.Fatalf("first /app/me: %d", res.StatusCode)
	}
	e.f.arm(1)
	res := web.get(t, "/app/me")
	if hit := e.f.disarm(); res.StatusCode != http.StatusOK || hit {
		t.Fatalf("/app/me with the snapshot: %d, database reached=%v", res.StatusCode, hit)
	}
}

// TestJWT_IssueOnSessionSurfacesDatabaseFailures: the hook adds no database
// call, and every failure of the session read still reaches the caller.
func TestJWT_IssueOnSessionSurfacesDatabaseFailures(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(ctx context.Context) error {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		jw := jwt.New(jwtKey(t, jwt.EdDSA), jwt.IssueOnSession())
		a := e.newAuth(t, nil, em, pw, jw)
		up := signUpVerified(t, e.env, a, pw, em)
		return func(context.Context) error {
			ctx := request(a, up.Token)
			if _, err := a.Session(ctx); err != nil {
				return err
			}
			if _, ok := jwt.SessionJWT(ctx); !ok {
				t.Fatal("a successful session read handed out no token")
			}
			return nil
		}
	})
}
