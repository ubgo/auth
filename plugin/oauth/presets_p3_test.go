package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// TestPresetsP3_Constructors: the four presets have their route segment as
// id, a display name, and pass auth.New's validation.
func TestPresetsP3_Constructors(t *testing.T) {
	oauth2s := map[string]*OAuth2{"dub": Dub("id", "s"), "instagram": Instagram("id", "s"), "snapchat": Snapchat("id", "s")}
	for name, o := range oauth2s {
		if o.ID != name || o.DisplayName == "" || o.Label() != o.DisplayName || o.DisplayName == o.ID {
			t.Errorf("%s: id %q display %q", name, o.ID, o.DisplayName)
		}
		if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(New(WithProviders(o)))); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	z := Zoho(ZohoEU, "id", "s")
	if z.ID != "zoho" || z.Issuer != string(ZohoEU) || z.DisplayName != "Zoho" || strings.Join(z.Scopes, " ") != "openid email profile" {
		t.Fatalf("zoho = %+v", z)
	}
	if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(New(WithProviders(z)))); err != nil {
		t.Fatal(err)
	}
	if Snapchat("id", "s").TokenAuth != ClientSecretBasic || Instagram("id", "s").NoPKCE != true || Dub("id", "s").NoPKCE || Snapchat("id", "s").NoPKCE {
		t.Fatal("token auth or PKCE per preset")
	}
}

// TestZohoRegions: every data centre is an https issuer with no trailing
// slash, listed once in ZohoRegionValues.
func TestZohoRegions(t *testing.T) {
	seen := map[ZohoRegion]bool{}
	for _, r := range ZohoRegionValues {
		if !strings.HasPrefix(string(r), httpsPrefix) || strings.HasSuffix(string(r), "/") || seen[r] {
			t.Errorf("region %q", r)
		}
		seen[r] = true
	}
	if len(seen) != 9 || !seen[ZohoUS] || !seen[ZohoChina] {
		t.Fatalf("regions = %v", ZohoRegionValues)
	}
}

func TestDub_PKCEUserReadAndUserInfo(t *testing.T) {
	f, base, hc := newFixtureProvider(t, map[string]string{
		"/token":    `{"access_token":"dub_at","refresh_token":"dub_rt","expires_in":7200,"token_type":"Bearer","scope":"user.read"}`,
		"/userinfo": `{"id":"user_1","name":"Ann","image":"https://d/a.png","workspace":{"id":"ws_1","slug":"acme","name":"Acme"}}`,
	})
	o := Dub("cid", "sec")
	o.AuthURL, o.TokenURL, o.FetchProfile = base+"/a", base+"/token", DubProfile(base+"/userinfo")
	q, _ := authURLQuery(t, o.AuthCodeURL("st", "ch", "https://app/cb"))
	if q.Get(paramScope) != "user.read" || q.Get(paramChallenge) != "ch" || q.Get(paramClientID) != "cid" {
		t.Fatalf("dub URL = %v", q)
	}
	p, err := o.Exchange(context.Background(), hc, "code-1", "verifier-1", "https://app/cb")
	if err != nil || p.Subject != "user_1" || p.Name != "Ann" || p.Image != "https://d/a.png" || p.Email != "" || p.Tokens.ExpiresAt.IsZero() || p.Claims["workspace"] == nil {
		t.Fatalf("dub profile = %+v %v", p, err)
	}
	if form := mustQuery(t, f.last(t, "/token").body); form.Get("code_verifier") != "verifier-1" || form.Get(paramCode) != "code-1" {
		t.Fatalf("dub token form = %v", form)
	}
	if f.last(t, "/userinfo").auth != "Bearer dub_at" {
		t.Fatal("dub userinfo without the bearer token")
	}
	_, base, hc = newFixtureProvider(t, map[string]string{"/userinfo": `[]`})
	if _, err := DubProfile(base+"/userinfo")(context.Background(), hc, "at"); !errors.Is(err, ErrExchange) {
		t.Fatalf("a non-object answer: %v", err)
	}
}

func TestInstagram_CommaScopesWrappedOrFlatTokenAndProfile(t *testing.T) {
	for _, tc := range []struct{ name, token, scope string }{
		{"documented data array", `{"data":[{"access_token":"ig_at","user_id":"178","permissions":"instagram_business_basic,instagram_business_manage_messages"}]}`, "instagram_business_basic instagram_business_manage_messages"},
		{"flat with an array", `{"access_token":"ig_at","user_id":178,"permissions":["instagram_business_basic"]}`, "instagram_business_basic"},
		{"flat without permissions", `{"access_token":"ig_at"}`, ""},
		{"permissions of another shape", `{"access_token":"ig_at","permissions":7}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, base, hc := newFixtureProvider(t, map[string]string{
				"/token": tc.token,
				"/me":    `{"id":"9001","user_id":"178","username":"ann.ig","profile_picture_url":"https://ig/a.jpg","account_type":"BUSINESS"}`,
			})
			o := Instagram("app-1", "sec-1")
			o.AuthURL, o.TokenURL, o.FetchProfile = base+"/a", base+"/token", InstagramProfile(base+"/me")
			o.OptionalScopes = []string{"instagram_business_manage_messages"}
			q, _ := authURLQuery(t, o.AuthCodeURLWithParams("st", "ch", "https://app/cb", RequestParams{Scopes: []string{"instagram_business_manage_messages"}, Extra: url.Values{instagramForceReauth: {"true"}}}))
			if q.Get(paramScope) != "instagram_business_basic,instagram_business_manage_messages" || q.Has(paramChallenge) || q.Get(instagramForceReauth) != "true" {
				t.Fatalf("instagram URL = %v", q)
			}
			before := time.Now()
			p, err := o.Exchange(context.Background(), hc, "code-1", "", "https://app/cb")
			if err != nil || p.Subject != "9001" || p.Name != "ann.ig" || p.Image != "https://ig/a.jpg" || p.Email != "" {
				t.Fatalf("instagram profile = %+v %v", p, err)
			}
			if p.Tokens.AccessToken.Reveal() != "ig_at" || p.Tokens.Scope != tc.scope || p.Tokens.ExpiresAt.Before(before.Add(InstagramTokenLifetime-time.Minute)) {
				t.Fatalf("instagram tokens = %+v", p.Tokens)
			}
			tok := f.last(t, "/token")
			want := url.Values{"client_id": {"app-1"}, "client_secret": {"sec-1"}, "code": {"code-1"}, "grant_type": {"authorization_code"}, "redirect_uri": {"https://app/cb"}}
			if form := mustQuery(t, tok.body); form.Encode() != want.Encode() || tok.ctype != contentTypeForm || tok.auth != "" {
				t.Fatalf("instagram token request = %+v", tok)
			}
		})
	}
}

func TestInstagram_Refusals(t *testing.T) {
	ctx := context.Background()
	exchange := func(t *testing.T, answer string) error {
		t.Helper()
		_, base, hc := newFixtureProvider(t, map[string]string{"/token": answer, "/me": `{"id":"1"}`})
		o := Instagram("app", "sec")
		o.TokenURL, o.FetchProfile = base+"/token", InstagramProfile(base+"/me")
		_, err := o.Exchange(ctx, hc, "c", "", "https://app/cb")
		return err
	}
	for name, answer := range map[string]string{
		"not JSON":             `<html>`,
		"data of another kind": `{"data":[1]}`,
		"no access token":      `{"error_type":"OAuthException","code":400,"error_message":"Invalid code"}`,
	} {
		if err := exchange(t, answer); !errors.Is(err, ErrExchange) {
			t.Errorf("%s: %v", name, err)
		}
	}
	o := Instagram("app", "")
	o.ClientSecretFunc = func(context.Context) (string, error) { return "", errors.New("vault down") }
	if _, err := o.Exchange(ctx, http.DefaultClient, "c", "", "https://app/cb"); !errors.Is(err, ErrExchange) || !strings.Contains(err.Error(), "vault down") {
		t.Fatalf("secret failure: %v", err)
	}
	o = Instagram("app", "sec")
	o.TokenURL = "http://bad host/token"
	if _, err := o.Exchange(ctx, http.DefaultClient, "c", "", "https://app/cb"); !errors.Is(err, ErrExchange) {
		t.Fatalf("bad token URL: %v", err)
	}
	_, base, hc := newFixtureProvider(t, map[string]string{})
	o.TokenURL = base + "/missing"
	if _, err := o.Exchange(ctx, hc, "c", "", "https://app/cb"); !errors.Is(err, ErrExchange) {
		t.Fatalf("a 404 token endpoint: %v", err)
	}
	if _, err := Instagram("app", "sec").Refresh(ctx, http.DefaultClient, "rt"); !errors.Is(err, ErrExchange) {
		t.Fatalf("refresh of a short-lived token: %v", err)
	}
	_, base, hc = newFixtureProvider(t, map[string]string{"/me": `{"error":{"message":"Invalid OAuth access token","type":"OAuthException","code":190}}`})
	if _, err := InstagramProfile(base+"/me")(ctx, hc, "at"); !errors.Is(err, ErrExchange) || !strings.Contains(err.Error(), "Invalid OAuth") {
		t.Fatalf("graph error: %v", err)
	}
	_, base, hc = newFixtureProvider(t, map[string]string{"/me": `[]`})
	if _, err := InstagramProfile(base+"/me")(ctx, hc, "at"); !errors.Is(err, ErrExchange) {
		t.Fatalf("a non-object profile: %v", err)
	}
}

func TestInstagramHelpers(t *testing.T) {
	if obj, err := instagramTokenObject([]byte(`{"data":[]}`)); err != nil || string(obj) != `{"data":[]}` {
		t.Fatalf("an empty data array falls back to the answer: %s %v", obj, err)
	}
	if instagramPermissions([]byte(`[]`)) != "" || instagramPermissions([]byte(`{}`)) != "" {
		t.Fatal("permissions of a non-object or a missing field")
	}
}

func TestSnapchat_FullScopeURLsBasicPKCEAndMe(t *testing.T) {
	f, base, hc := newFixtureProvider(t, map[string]string{
		"/token":  `{"access_token":"sc_at","refresh_token":"sc_rt","expires_in":3600,"token_type":"Bearer"}`,
		"/me":     `{"data":{"me":{"externalId":"CAESIP","displayName":"Ann","bitmoji":{"avatar":"https://sdk.bitmoji.com/a.png"}}}}`,
		"/revoke": `{}`,
	})
	o := Snapchat("cid", "sec")
	o.AuthURL, o.TokenURL, o.RevokeURL, o.FetchProfile = base+"/a", base+"/token", base+"/revoke", SnapchatProfile(base+"/me")
	q, _ := authURLQuery(t, o.AuthCodeURL("st", "ch", "https://app/cb"))
	wantScopes := []string{SnapchatScopePrefix + "user.external_id", SnapchatScopePrefix + "user.display_name", SnapchatScopePrefix + "user.bitmoji.avatar"}
	if !slices.Equal(strings.Split(q.Get(paramScope), " "), wantScopes) || q.Get(paramChallenge) != "ch" {
		t.Fatalf("snapchat URL = %v", q)
	}
	p, err := o.Exchange(context.Background(), hc, "code-1", "verifier-1", "https://app/cb")
	if err != nil || p.Subject != "CAESIP" || p.Name != "Ann" || p.Image != "https://sdk.bitmoji.com/a.png" || p.Email != "" {
		t.Fatalf("snapchat profile = %+v %v", p, err)
	}
	tok := f.last(t, "/token")
	if tok.auth != basic("cid", "sec") || mustQuery(t, tok.body).Get("code_verifier") != "verifier-1" || mustQuery(t, tok.body).Has(paramClientSecret) {
		t.Fatalf("snapchat token request = %+v", tok)
	}
	if me := f.last(t, "/me"); mustQuery(t, me.query).Get(snapchatQueryParam) != snapchatMeQuery || me.auth != "Bearer sc_at" {
		t.Fatalf("snapchat me request = %+v", me)
	}
	if err := o.Revoke(context.Background(), hc, p.Tokens); err != nil {
		t.Fatal(err)
	}
	if rv := f.last(t, "/revoke"); rv.auth != basic("cid", "sec") || mustQuery(t, rv.body).Get("token") != "sc_rt" {
		t.Fatalf("snapchat revoke = %+v", rv)
	}
}

func TestSnapchatProfile_Refusals(t *testing.T) {
	for name, answer := range map[string]string{
		"graphql error": `{"errors":[{"message":"unauthorized"}]}`,
		"no externalId": `{"data":{"me":{"displayName":"Ann"}}}`,
		"not an object": `[]`,
	} {
		_, base, hc := newFixtureProvider(t, map[string]string{"/me": answer})
		if _, err := SnapchatProfile(base+"/me")(context.Background(), hc, "at"); !errors.Is(err, ErrExchange) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
