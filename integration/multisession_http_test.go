package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

// cookieJar is the minimal jar a test needs: Set-Cookie with a negative
// Max-Age deletes, anything else stores, and every stored cookie is sent.
type cookieJar map[string]string

func (j cookieJar) update(rec *httptest.ResponseRecorder) {
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(j, c.Name)
		} else {
			j[c.Name] = c.Value
		}
	}
}

func (j cookieJar) accounts() int {
	n := 0
	for name := range j {
		if strings.HasPrefix(name, authhttp.AccountCookiePrefix) {
			n++
		}
	}
	return n
}

// TestMultiSession_CookiesEndToEnd: with the real core under
// WithMultiSession, a second sign-up keeps the first account in an account
// cookie, the device-sessions list shows both, a switch makes the other
// active and swaps the cookies, a revoke drops one, and sign-out ends every
// account and clears every cookie. On every engine, because the core reads
// the device's other sessions from the database.
func TestMultiSession_CookiesEndToEnd(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a := e.newAuth(t, []auth.Option{auth.WithMultiSession(3)}, e.emailPlugin(), e.passwordPlugin())
		h := authhttp.Handler(a, authhttp.Prefix("/auth"))
		jar := cookieJar{}
		do := func(method, path, body string) *httptest.ResponseRecorder {
			req := httptest.NewRequest(method, path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", testBaseURL)
			for name, v := range jar {
				req.AddCookie(&http.Cookie{Name: name, Value: v})
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			jar.update(rec)
			return rec
		}
		signUp := func(addr string) {
			if rec := do(http.MethodPost, "/auth/password/sign-up", `{"identifier":"`+addr+`","password":"`+secret+`"}`); rec.Code != http.StatusOK {
				t.Fatalf("sign-up %s: %d %s", addr, rec.Code, rec.Body.String())
			}
		}
		list := func() auth.DeviceSessionsResult {
			rec := do(http.MethodGet, "/auth/device-sessions", "")
			if rec.Code != http.StatusOK {
				t.Fatalf("device-sessions: %d %s", rec.Code, rec.Body.String())
			}
			var out auth.DeviceSessionsResult
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			return out
		}

		signUp("ada@example.com")
		ada := jar[authhttp.CookieName]
		if jar.accounts() != 0 {
			t.Fatalf("first sign-up wrote an account cookie: %v", jar)
		}
		signUp("bo@example.com")
		bo := jar[authhttp.CookieName]
		if bo == ada || jar.accounts() != 1 {
			t.Fatalf("second sign-up: active changed=%v accounts=%d", bo != ada, jar.accounts())
		}
		sessions := list()
		if len(sessions.Sessions) != 2 || !sessions.Sessions[0].Active || sessions.Sessions[1].Active {
			t.Fatalf("device-sessions = %+v", sessions)
		}
		adaID := sessions.Sessions[1].ID

		// Switch to Ada: her token becomes the active cookie, Bo's moves
		// into an account cookie.
		if rec := do(http.MethodPost, "/auth/device-sessions/switch", `{"id":"`+adaID+`"}`); rec.Code != http.StatusOK {
			t.Fatalf("switch: %d %s", rec.Code, rec.Body.String())
		}
		if jar[authhttp.CookieName] != ada || jar.accounts() != 1 {
			t.Fatalf("after switch: active is ada=%v accounts=%d", jar[authhttp.CookieName] == ada, jar.accounts())
		}
		sessions = list()
		if len(sessions.Sessions) != 2 || sessions.Sessions[0].ID != adaID {
			t.Fatalf("device-sessions after switch = %+v", sessions)
		}
		boID := sessions.Sessions[1].ID

		// Revoke Bo: his account cookie goes, Ada stays active.
		if rec := do(http.MethodPost, "/auth/device-sessions/revoke", `{"id":"`+boID+`"}`); rec.Code != http.StatusOK {
			t.Fatalf("revoke: %d %s", rec.Code, rec.Body.String())
		}
		if jar[authhttp.CookieName] != ada || jar.accounts() != 0 {
			t.Fatalf("after revoke: %v", jar)
		}
		if got := list(); len(got.Sessions) != 1 {
			t.Fatalf("device-sessions after revoke = %+v", got)
		}
		_ = bo

		// A third account, then sign-out ends both and clears every cookie.
		signUp("cy@example.com")
		if jar.accounts() != 1 {
			t.Fatalf("third sign-up: %v", jar)
		}
		if rec := do(http.MethodPost, "/auth/sign-out", ""); rec.Code != http.StatusOK {
			t.Fatalf("sign-out: %d %s", rec.Code, rec.Body.String())
		}
		if _, active := jar[authhttp.CookieName]; active || jar.accounts() != 0 {
			t.Fatalf("after sign-out: %v", jar)
		}
		// Neither old token opens any more.
		req := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
		req.AddCookie(&http.Cookie{Name: authhttp.CookieName, Value: ada})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("ada's token after sign-out: %d", rec.Code)
		}
	})
}
