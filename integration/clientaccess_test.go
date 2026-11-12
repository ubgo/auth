package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/oauthprovider"
)

// ClientAccess is asked on every route that can hand the user's identity to
// a client: authorize (the no-access page, or prompt=none's access_denied),
// continue and consent with the page's signed query, the code exchange and
// the refresh. Withdrawing access stops the next refresh.
//
//ds:def id=testoauthprovider-clientaccess-fyceyruw owner=@khanakia stability=stable
func TestOAuthProvider_ClientAccess(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		lists := map[string]oauthprovider.AllowList{}
		o := newOPEnv(t, e,
			oauthprovider.ClientAccess(oauthprovider.AllowListAccess(func(_ context.Context, c oauthprovider.Client) (oauthprovider.AllowList, bool) {
				l, ok := lists[c.Name]
				return l, ok
			})),
			oauthprovider.NoAccessPage("/no-access"))
		first := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, ClientMetadata: oauthprovider.ClientMetadata{Name: "first"}})
		asked := o.client(t, oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{Name: "asked"}})
		ctx := request(o.a, o.token)

		// No list for the client: refused at authorize, to the page, which
		// names the client in its signed query.
		res := must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(ctx, authzReq(first.ClientID)))
		q := pageQuery(t, res, "/no-access")
		if v := must[url.Values](t)(url.ParseQuery(q)); v.Get("client_id") != first.ClientID {
			t.Fatalf("no-access query = %s", q)
		}
		// The page's query posted onward gets nowhere.
		if r, err := o.op.Continue(ctx, oauthprovider.ContinueRequest{Query: q, PostLogin: true}); err != nil || !strings.HasPrefix(r.RedirectTo, "/no-access?") {
			t.Fatalf("continue while refused = %+v, %v", r, err)
		}
		if r, err := o.op.Consent(ctx, oauthprovider.ConsentRequest{Query: q, Accept: true}); err != nil || !strings.HasPrefix(r.RedirectTo, "/no-access?") {
			t.Fatalf("consent while refused = %+v, %v", r, err)
		}
		// prompt=none cannot show the page: access_denied at the client.
		none := authzReq(first.ClientID)
		none.Prompt = "none"
		var re *oauthprovider.RedirectError
		if _, err := o.op.Authorize(ctx, none); !errors.As(err, &re) || !strings.Contains(re.RedirectTo, "error=access_denied") {
			t.Fatalf("prompt=none refused: %v", err)
		}

		// Another domain's list still refuses; the user's verified address
		// on the list (any case) lets them on.
		lists["first"] = oauthprovider.AllowList{Domains: []string{"elsewhere.io"}}
		pageQuery(t, must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(ctx, authzReq(first.ClientID))), "/no-access")
		lists["first"] = oauthprovider.AllowList{Emails: []string{strings.ToUpper(alice)}}
		code := o.code(t, authzReq(first.ClientID))

		// Withdrawn between the code and its exchange: no token.
		delete(lists, "first")
		if _, err := o.op.Token(anon(o.a), exchange(first, code, opVerifier)); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
			t.Fatalf("exchange after withdrawal: %v", err)
		}
		lists["first"] = oauthprovider.AllowList{Emails: []string{alice}}
		tok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(first, o.code(t, authzReq(first.ClientID)), opVerifier)))
		refresh := func() error {
			r, err := o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "refresh_token", RefreshToken: tok.RefreshToken, ClientID: first.ClientID, ClientSecret: first.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic})
			if err == nil {
				tok = r
			}
			return err
		}
		if err := refresh(); err != nil {
			t.Fatalf("refresh while allowed: %v", err)
		}
		// Withdrawn: the next refresh fails.
		lists["first"] = oauthprovider.AllowList{Domains: []string{"elsewhere.io"}}
		if err := refresh(); !errors.Is(err, oauthprovider.ErrInvalidGrant) {
			t.Fatalf("refresh after withdrawal: %v", err)
		}

		// A client with a consent screen: refused before the consent page,
		// and a consent page's query answered after access is withdrawn
		// issues no code.
		pageQuery(t, must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(ctx, authzReq(asked.ClientID))), "/no-access")
		lists["asked"] = oauthprovider.AllowList{Domains: []string{"example.com"}}
		cq := pageQuery(t, must[oauthprovider.AuthorizeResult](t)(o.op.Authorize(ctx, authzReq(asked.ClientID))), "/consent")
		delete(lists, "asked")
		if r, err := o.op.Consent(ctx, oauthprovider.ConsentRequest{Query: cq, Accept: true}); err != nil || strings.Contains(r.RedirectTo, "code=") {
			t.Fatalf("consent after withdrawal = %+v, %v", r, err)
		}
	})
}

// Without a NoAccessPage the refusal itself is the answer (403).
func TestOAuthProvider_ClientAccessWithoutPage(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e, oauthprovider.ClientAccess(func(context.Context, oauthprovider.Client, oauthprovider.AccessUser) error {
			return errors.New("not on the list")
		}))
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		if _, err := o.op.Authorize(request(o.a, o.token), authzReq(reg.ClientID)); !errors.Is(err, oauthprovider.ErrNoAccess) {
			t.Fatalf("authorize refused without a page: %v", err)
		}
	})
}

// PatchClient changes the named fields and keeps every other one, refuses
// an unknown client, and stores only what a whole update could.
//
//ds:def id=testoauthprovider-patchclient-ctwjkqxc owner=@khanakia stability=stable
func TestOAuthProvider_PatchClient(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e)
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true, EnableEndSession: true, ReferenceID: "org_1", Metadata: []byte(`{"team":"a"}`),
			ClientMetadata: oauthprovider.ClientMetadata{Name: "App", Scope: "openid email", PostLogoutRedirectURIs: []string{"https://client.example/out"}, ClientURI: "https://client.example"}})
		before := must[oauthprovider.Client](t)(o.op.Client(context.Background(), reg.ClientID))
		out := []string{"https://client.example/bye", "https://client.example/out"}
		after := must[oauthprovider.Client](t)(o.op.PatchClient(context.Background(), reg.ClientID, oauthprovider.ClientPatch{PostLogoutRedirectURIs: &out}))
		if strings.Join(after.PostLogoutRedirectURIs, " ") != strings.Join(out, " ") {
			t.Fatalf("post-logout URIs = %v", after.PostLogoutRedirectURIs)
		}
		after.PostLogoutRedirectURIs, after.UpdatedAt = before.PostLogoutRedirectURIs, before.UpdatedAt
		if a, b := must[[]byte](t)(json.Marshal(after)), must[[]byte](t)(json.Marshal(before)); string(a) != string(b) {
			t.Fatalf("other fields changed:\n%s\n%s", a, b)
		}
		name := "Renamed"
		if c := must[oauthprovider.Client](t)(o.op.PatchClient(context.Background(), reg.ClientID, oauthprovider.ClientPatch{Name: &name})); c.Name != name || len(c.PostLogoutRedirectURIs) != 2 {
			t.Fatalf("rename = %+v", c)
		}
		bad := []string{"not a url"}
		if _, err := o.op.PatchClient(context.Background(), reg.ClientID, oauthprovider.ClientPatch{RedirectURIs: &bad}); err == nil {
			t.Fatal("a patch stored an invalid redirect URI")
		}
		if _, err := o.op.PatchClient(context.Background(), "oac_missing", oauthprovider.ClientPatch{Name: &name}); !errors.Is(err, oauthprovider.ErrClientNotFound) {
			t.Fatalf("unknown client: %v", err)
		}
		second := o.client(t, oauthprovider.ClientSpec{})
		all := must[[]oauthprovider.Client](t)(o.op.AllClients(context.Background()))
		// Oldest first; the test clock stands still, so the id breaks the tie.
		ids := []string{all[0].ClientID, all[1].ClientID}
		if len(all) != 2 || !slices.Contains(ids, reg.ClientID) || !slices.Contains(ids, second.ClientID) || ids[0] > ids[1] {
			t.Fatalf("all clients = %+v", all)
		}
	})
}

// A no-access page on an origin the app does not trust is refused at
// auth.New: the provider would send signed queries there.
func TestOAuthProvider_NoAccessPageUntrusted(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		jw := jwt.New(jwt.WithSigningKey(key), jwt.Issuer(testBaseURL))
		op := oauthprovider.New(jw, oauthprovider.Issuer(testBaseURL), oauthprovider.LoginPage("/login"), oauthprovider.NoAccessPage("https://evil.example/no"))
		if _, err := auth.New(e.withDB(), auth.WithBaseURL(testBaseURL), auth.WithPlugins(e.emailPlugin(), e.passwordPlugin(), jw, op)); err == nil || !strings.Contains(err.Error(), "NoAccessPage") {
			t.Fatalf("untrusted no-access page: %v", err)
		}
	})
}
