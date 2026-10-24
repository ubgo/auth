package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/sso"
	"github.com/ubgo/auth/plugin/sso/ssotest"
)

// Round 31, third part: the AuthnRequest POST binding and the first
// sign-in race.

func TestR31_SAMLAuthnRequestPOSTBinding(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := r31Setup(t, e)
		idp := ssotest.NewSAMLIdP(t, "https://idp.example.com/acme")
		key, _, certPEM := ssotest.KeyPair(t, "sp")
		w.registerSAML(t, idp, "acme-saml", map[string]any{"privateKey": ssotest.KeyPEM(key), "spCertificate": certPEM, "authnRequestsSigned": true,
			"signatureAlgorithm": "sha512", "digestAlgorithm": sso.DigestSHA512, "spMetadata": map[string]any{"entityID": r31SP, "binding": "post"}})
		res := w.web.post(t, "/auth/sso/sign-in", map[string]any{"providerId": "acme-saml"})
		var out sso.SignInResult
		_ = json.NewDecoder(res.Body).Decode(&out)
		res.Body.Close()
		if res.StatusCode != http.StatusOK || out.Redirect || out.Form == nil || out.Form.Action != idp.SSOURL || out.Form.SAMLRequest == "" || out.Form.RelayState == "" {
			t.Fatalf("post binding: %d %+v", res.StatusCode, out)
		}
		// A digest the signature would not use is refused, not ignored.
		st, body := w.call(t, w.admin, http.MethodPost, "/auth/sso/register", map[string]any{"providerId": "bad-digest", "issuer": r31SP, "domain": "d.test",
			"samlConfig": map[string]any{"entryPoint": idp.SSOURL, "cert": idp.CertPEM, "idpMetadata": map[string]any{"entityID": idp.EntityID}, "digestAlgorithm": sso.DigestSHA512}})
		if st != http.StatusBadRequest || r31Code(body) != "sso.bad_provider" {
			t.Fatalf("ineffective digest: %d %v", st, body)
		}
	})
}

// Two first sign-ins of one IdP account at once (two browsers, two codes):
// exactly one user and one link, and neither request may fail with
// anything but a clean conflict.
func TestR31_FirstSignInRace(t *testing.T) {
	for _, mail := range []string{"ada@" + r31Domain, ""} {
		t.Run("email="+mail, func(t *testing.T) { r31Race(t, mail) })
	}
}

// r31Race races first sign-ins of one person; with no email only the
// (provider_id, subject) UNIQUE stands between the racers and two users.
func r31Race(t *testing.T, mail string) {
	eachEngine(t, func(t *testing.T, e *env) {
		// Every racer waits here, inside its sign-in transaction and after
		// its "is this account linked?" read, until all have arrived or a
		// short timeout passes: without serialization they all decide
		// "new user" at once, which is the race the guards must survive.
		const n = 4
		var mu sync.Mutex
		arrived := 0
		all := make(chan struct{})
		barrier := sso.WithResolveUser(func(context.Context, *auth.Call, sso.ResolveInput) (sso.Decision, error) {
			mu.Lock()
			arrived++
			if arrived == n {
				close(all)
			}
			mu.Unlock()
			select {
			case <-all:
			case <-time.After(300 * time.Millisecond):
			}
			return sso.Decision{Action: sso.ResolveContinue}, nil
		})
		w := r31Setup(t, e, barrier)
		w.idp.Person.Email = mail
		w.registerOIDC(t, w.admin, "acme-okta", nil)
		browsers := make([]*app, n)
		queries := make([]string, n)
		for i := range browsers {
			browsers[i] = newApp(t, w.a)
			res := browsers[i].post(t, "/auth/sso/sign-in", map[string]any{"providerId": "acme-okta"})
			var out sso.SignInResult
			_ = json.NewDecoder(res.Body).Decode(&out)
			res.Body.Close()
			queries[i] = w.idp.Authorize(t, out.URL).Encode()
		}
		var wg sync.WaitGroup
		codes := make([]int, n)
		bodies := make([]string, n)
		for i := range browsers {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				res, err := browsers[i].client.Get(browsers[i].srv.URL + "/auth/sso/callback?" + queries[i])
				if err != nil {
					t.Error(err)
					return
				}
				codes[i], bodies[i] = res.StatusCode, readAll(t, res)
			}(i)
		}
		wg.Wait()
		ok := 0
		for i, c := range codes {
			switch c {
			case http.StatusFound:
				ok++
			case http.StatusConflict:
			case http.StatusInternalServerError:
				// SQLite has one writer: a racer may meet SQLITE_BUSY in the
				// core's session insert (a transient error to retry). The
				// data rules below hold regardless; other engines must not.
				if e.engine != auth.EngineSQLite {
					t.Fatalf("callback %d: %d %s", i, c, bodies[i])
				}
			default:
				t.Fatalf("callback %d: %d %s", i, c, bodies[i])
			}
		}
		if ok == 0 {
			t.Fatal("no sign-in succeeded")
		}
		if u := r31Count(t, e, "auth_user", ""); u != 2 {
			t.Fatalf("%d users (admin + one)", u)
		}
		if a := r31Count(t, e, "auth_sso_account", ""); a != 1 {
			t.Fatalf("%d links", a)
		}
		if id := r31Count(t, e, "auth_identity", " WHERE value = 'ada@"+r31Domain+"'"); mail != "" && id != 1 {
			t.Fatalf("%d identities for the address", id)
		}
	})
}
