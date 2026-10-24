package integration

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/apikey"
	"github.com/ubgo/auth/plugin/deviceauth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/scim"
)

// TestP3Tokens_APIKeyExpiresIn: a key's expiry can be given in seconds
// (expiresIn), at create and update; the WithExpiry day bounds
// hold for it, and sending it with expiresInDays is refused.
func TestP3Tokens_APIKeyExpiresIn(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a, ak, up := r6Keyed(t, e, apikey.Scopes("read"), apikey.WithExpiry(apikey.Expiry{MinDays: 1, MaxDays: 30}))
		ctx := request(a, up.Token)
		now := e.clock.Now()
		k := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Name: "s", ExpiresIn: 2 * 86400}))
		if k.Key.ExpiresAt == nil || !k.Key.ExpiresAt.Equal(now.Add(48*time.Hour)) {
			t.Fatalf("expiresIn 2 days = %v", k.Key.ExpiresAt)
		}
		if _, err := ak.Create(ctx, apikey.CreateRequest{Name: "h", ExpiresIn: 3600}); !errors.Is(err, apikey.ErrExpiryOutOfRange) {
			t.Fatalf("an hour under a one-day minimum: %v", err)
		}
		if _, err := ak.Create(ctx, apikey.CreateRequest{Name: "b", ExpiresIn: 86400, ExpiresInDays: 1}); !errors.Is(err, apikey.ErrExpiryConflict) {
			t.Fatalf("both units: %v", err)
		}
		week := int64(7 * 86400)
		got, err := ak.Update(ctx, apikey.UpdateRequest{ID: k.Key.ID, ExpiresIn: &week})
		if err != nil || got.ExpiresAt == nil || !got.ExpiresAt.Equal(now.Add(7*24*time.Hour)) {
			t.Fatalf("update to a week = %v %v", got.ExpiresAt, err)
		}
		one := 1
		if _, err := ak.Update(ctx, apikey.UpdateRequest{ID: k.Key.ID, ExpiresIn: &week, ExpiresInDays: &one}); !errors.Is(err, apikey.ErrExpiryConflict) {
			t.Fatalf("update with both units: %v", err)
		}
	})
}

// TestP3Tokens_APIKeyStampEveryUse: under StampEveryUse every use of a key
// without limits stamps last_used_at and updated_at, and a key deleted behind
// a cache entry is refused (and its entry dropped) instead of answered from
// the stale entry, which is what the default does.
func TestP3Tokens_APIKeyStampEveryUse(t *testing.T) {
	for _, stamp := range []bool{false, true} {
		eachEngine(t, func(t *testing.T, e *env) {
			opts := []apikey.Option{apikey.Scopes("read"), apikey.DistinctErrors(), apikey.WithCache(apikey.NewMemoryCacheAt(e.clock.Now), 10*time.Minute)}
			if stamp {
				opts = append(opts, apikey.StampEveryUse())
			}
			a, ak, up := r6Keyed(t, e, opts...)
			ctx := request(a, up.Token)
			k := must[apikey.CreateResult](t)(ak.Create(ctx, apikey.CreateRequest{Name: "k"}))
			if v, err := ak.Verify(context.Background(), k.Secret); err != nil || !v.Valid {
				t.Fatalf("first use: %+v %v", v, err)
			}
			e.clock.Advance(5 * time.Second)
			if v, err := ak.Verify(context.Background(), k.Secret); err != nil || !v.Valid {
				t.Fatalf("second use: %+v %v", v, err)
			}
			got := must[apikey.Key](t)(ak.Get(ctx, k.Key.ID))
			// The second use, 5s after the first, is inside the default's
			// once-a-minute window and also a cache hit: only StampEveryUse
			// writes it.
			if stamped := got.LastUsedAt != nil && got.LastUsedAt.Equal(e.clock.Now()); stamped != stamp {
				t.Fatalf("stamp=%v: last used %v, now %v", stamp, got.LastUsedAt, e.clock.Now())
			}
			if !stamp {
				return
			}
			// The row goes behind the cache entry, as a revoke on another
			// instance would: the stamp finds no row and refuses the key.
			r6DeleteRow(t, a, k.Key.ID)
			v, err := ak.Verify(context.Background(), k.Secret)
			if err != nil || v.Valid || !errors.Is(v.Reason, apikey.ErrInvalidKey) {
				t.Fatalf("a deleted key behind the cache: %+v %v", v, err)
			}
			// The entry went with it: the next use misses the cache and the
			// database alike.
			if v, err := ak.Verify(context.Background(), k.Secret); err != nil || v.Valid {
				t.Fatalf("the deleted key's cache entry survived: %+v %v", v, err)
			}
		})
	}
}

// TestP3Tokens_DeviceClient: deviceauth.Client walks the flow against the
// real CodeHandler and TokenHandler: it is pending until the user claims and
// approves the code, and the token it ends with is a session; a denied code
// ends the poll with access_denied.
func TestP3Tokens_DeviceClient(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newDeviceWorld(t, e)
		mux := http.NewServeMux()
		mux.Handle("POST /auth/device/code", w.dp.CodeHandler())
		mux.Handle("POST /auth/device/token", w.dp.TokenHandler())
		srv := httptest.NewServer(mux)
		defer srv.Close()
		for _, approve := range []bool{true, false} {
			var userCode string
			polls := 0
			c := &deviceauth.Client{CodeURL: srv.URL + "/auth/device/code", TokenURL: srv.URL + "/auth/device/token", ClientID: "cli", HTTP: srv.Client(),
				// The wait moves the server's clock instead of sleeping; the
				// user decides after the second poll.
				Sleep: func(_ context.Context, d time.Duration) error {
					e.clock.Advance(d)
					if polls++; polls == 3 {
						if _, err := w.dp.Verify(request(w.a, w.aliceTok), userCode); err != nil {
							return err
						}
						if approve {
							return w.dp.Approve(request(w.a, w.aliceTok), userCode)
						}
						return w.dp.Deny(request(w.a, w.aliceTok), userCode)
					}
					return nil
				}}
			code, err := c.RequestCode(context.Background(), "read")
			if err != nil {
				t.Fatal(err)
			}
			userCode = code.UserCode
			tok, err := c.Poll(context.Background(), code)
			if !approve {
				var ce *deviceauth.ClientError
				if !errors.As(err, &ce) || ce.ErrorName != deviceauth.RFCAccessDenied {
					t.Fatalf("denied = %v", err)
				}
				continue
			}
			if err != nil || tok.AccessToken == "" || polls != 3 {
				t.Fatalf("approved = %+v %v after %d waits", tok, err, polls)
			}
			if !identSignedIn(t, w.a, auth.Token(tok.AccessToken)) {
				t.Fatal("the device's token signs nobody in")
			}
		}
	})
}

// TestP3Tokens_SCIMProfileSource: the profile authority. A link
// with ProfileManage writes the linked user's name and email and becomes its
// one profile source; a second manager from another connection is 409 while
// a preserve link is not; deleting the source hands the profile over to the
// next manager, which adopts the identity already holding its address; and
// reviving the old source while the new one holds the profile is 409.
func TestP3Tokens_SCIMProfileSource(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var target string
		mode := scim.ProfileManage
		w := newSCIMWorld(t, e, scim.ResolveUser(func(context.Context, scim.ResolveInput) (scim.Resolution, error) {
			return scim.Resolution{UserID: target, Profile: mode}, nil
		}))
		ctx := context.Background()
		target, _ = identUser(t, w.a, "owner@acme.test")
		emails := func() []string {
			var out []string
			for _, idn := range must[[]auth.Identity](t)(w.a.Identities(ctx, target)) {
				if idn.Kind == email.KindEmail {
					out = append(out, idn.Value)
				}
			}
			return out
		}

		code, ada := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("ada@acme.test", "ada@acme.test", "ext-a"))
		if code != http.StatusCreated {
			t.Fatalf("manage link = %d %v", code, ada)
		}
		if u := must[auth.User](t)(w.a.User(ctx, target)); u.Name != "Ada Lovelace" || strings.Join(emails(), ",") != "ada@acme.test" {
			t.Fatalf("managed profile: name %q, emails %v", u.Name, emails())
		}
		if code, body := w.do(t, http.MethodPost, "/Users", scimOther, scimUser("g@globex.test", "g@globex.test", "")); code != http.StatusConflict || !strings.Contains(body["detail"].(string), "managing this User profile") {
			t.Fatalf("second manager = %d %v", code, body)
		}
		mode = scim.ProfilePreserve
		code, kept := w.do(t, http.MethodPost, "/Users", scimOther, scimUser("g@globex.test", "g@globex.test", ""))
		if code != http.StatusCreated || strings.Join(emails(), ",") != "ada@acme.test" {
			t.Fatalf("preserve link = %d, emails %v", code, emails())
		}

		// The hand-over: the source goes, and the next manager takes the
		// profile, adopting the identity that already holds its address.
		w.do(t, http.MethodDelete, "/Users/"+kept["id"].(string), scimOther, "")
		w.do(t, http.MethodDelete, "/Users/"+ada["id"].(string), scimToken, "")
		mode = scim.ProfileManage
		if code, body := w.do(t, http.MethodPost, "/Users", scimOther, scimUser("ada2@globex.test", "ada@acme.test", "")); code != http.StatusCreated {
			t.Fatalf("hand-over = %d %v", code, body)
		}
		if got := emails(); strings.Join(got, ",") != "ada@acme.test" {
			t.Fatalf("hand-over emails = %v", got)
		}
		// The old source comes back through its tombstone while the new one
		// holds the profile.
		target = ""
		if code, body := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("ada@acme.test", "ada@acme.test", "ext-a")); code != http.StatusConflict || !strings.Contains(body["detail"].(string), "managing this User profile") {
			t.Fatalf("revived source = %d %v", code, body)
		}
	})
}

// TestP3Tokens_SCIMProfileRefusals: an unknown profile mode is the app's
// error (500); a manage link whose address another user holds is 409, and
// leaves the linked user as it was.
func TestP3Tokens_SCIMProfileRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var target string
		mode := scim.Profile("bogus")
		w := newSCIMWorld(t, e, scim.ResolveUser(func(context.Context, scim.ResolveInput) (scim.Resolution, error) {
			return scim.Resolution{UserID: target, Profile: mode}, nil
		}))
		target, _ = identUser(t, w.a, "owner@acme.test")
		identUser(t, w.a, "taken@acme.test")
		if code, _ := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("x@acme.test", "x@acme.test", "")); code != http.StatusInternalServerError {
			t.Fatalf("bogus mode = %d", code)
		}
		mode = scim.ProfileManage
		if code, body := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("t@acme.test", "taken@acme.test", "")); code != http.StatusConflict || !strings.Contains(body["detail"].(string), "with this email") {
			t.Fatalf("taken address = %d %v", code, body)
		}
		if _, ok := libraryUser(t, w.a, "owner@acme.test"); !ok {
			t.Fatal("a refused manage link changed the user's email")
		}
		if code, body := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("bad@acme.test", "not an address", "")); code != http.StatusBadRequest {
			t.Fatalf("a manage link without an address = %d %v", code, body)
		}
		// A user with no email at all gets the IdP's as its first.
		target, _ = identUser(t, w.a, "")
		if code, body := w.do(t, http.MethodPost, "/Users", scimToken, scimUser("new@acme.test", "new@acme.test", "")); code != http.StatusCreated {
			t.Fatalf("manage link to a user without email = %d %v", code, body)
		}
		if idn, ok := libraryUser(t, w.a, "new@acme.test"); !ok || idn.UserID != target {
			t.Fatalf("the managed address = %+v %v", idn, ok)
		}
	})
}
