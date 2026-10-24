package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/oauthprovider"
	"github.com/ubgo/auth/plugin/password"
)

// TokenResponseFields adds envelope members (never replacing a standard
// one), an initial access token admits a registration, software ids are
// kept, and a resource can pin its tokens' signing algorithm.
func TestOAuthProvider_ResponseFieldsIATSoftwareSigning(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		jw := jwt.New(jwt.WithSigningKey(key), jwt.Issuer(testBaseURL), jwt.AlgorithmKeys(ec))
		const api = "https://api.example.com/es"
		op := oauthprovider.New(jw, oauthprovider.Issuer(testBaseURL), oauthprovider.LoginPage("/login"),
			oauthprovider.Scopes("openid", "api:read"),
			oauthprovider.TokenResponseFields(func(_ context.Context, in oauthprovider.TokenFieldsInfo) (map[string]any, error) {
				return map[string]any{"tenant": "t1", "access_token": "forged", "grant": in.GrantType}, nil
			}),
			oauthprovider.ValidateInitialAccessToken(func(_ context.Context, tok string) (string, bool) { return "org_7", tok == "iat-good" }))
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, []auth.Option{auth.WithSecret([]byte(strings.Repeat("s", auth.MinSecretSize)))}, em, pw, jw, op)
		reg := must[oauthprovider.Registration](t)(op.CreateClient(ctx, oauthprovider.ClientSpec{ClientCredentialsScopes: []string{"api:read"},
			ClientMetadata: oauthprovider.ClientMetadata{Name: "M", GrantTypes: []string{"client_credentials"}}}))
		cc := oauthprovider.TokenRequest{GrantType: "client_credentials", ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}
		tok := must[oauthprovider.TokenResponse](t)(op.Token(anon(a), cc))
		b := must[[]byte](t)(json.Marshal(tok))
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		if m["tenant"] != "t1" || m["grant"] != "client_credentials" || m["access_token"] != tok.AccessToken {
			t.Fatalf("response = %s", b)
		}
		// Initial access tokens: a bad one is refused, a good one admits
		// registration while open registration is off, with its reference.
		meta := oauthprovider.ClientMetadata{Name: "IAT", RedirectURIs: []string{opRedirect}, SoftwareID: "sw-1", SoftwareVersion: "2.0", SoftwareStatement: "eyJ.stmt"}
		meta.InitialAccessToken = "iat-bad"
		if _, err := op.Register(anon(a), meta); !errors.Is(err, oauthprovider.ErrInvalidToken) {
			t.Fatalf("bad initial access token: %v", err)
		}
		meta.InitialAccessToken = "iat-good"
		r := must[oauthprovider.Registration](t)(op.Register(anon(a), meta))
		if r.ReferenceID != "org_7" {
			t.Fatalf("reference = %+v", r)
		}
		got := must[oauthprovider.Client](t)(op.Client(ctx, r.ClientID))
		if got.SoftwareID != "sw-1" || got.SoftwareVersion != "2.0" || got.SoftwareStatement != "eyJ.stmt" {
			t.Fatalf("software = %+v", got)
		}
		meta.InitialAccessToken = ""
		if _, err := op.Register(anon(a), meta); !errors.Is(err, oauthprovider.ErrRegistrationClosed) {
			t.Fatalf("no token, registration closed: %v", err)
		}
		// A resource pins ES256 for its tokens.
		must[oauthprovider.Resource](t)(op.CreateResource(ctx, oauthprovider.Resource{Identifier: api, SigningAlgorithm: "ES256"}))
		must[bool](t)(op.LinkClient(ctx, api, reg.ClientID))
		cc.Resource = api
		es := must[oauthprovider.TokenResponse](t)(op.Token(anon(a), cc))
		hb := must[[]byte](t)(base64Raw(strings.Split(es.AccessToken, ".")[0]))
		if !strings.Contains(string(hb), `"alg":"ES256"`) {
			t.Fatalf("pinned header = %s", hb)
		}
	})
}

func base64Raw(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// ClientReference makes clients belong to a reference (an organization)
// shared by its members, and ClientPrivileges gates each owner action.
func TestOAuthProvider_ClientReferenceAndPrivileges(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e,
			oauthprovider.ClientReference(func(context.Context, *auth.Call) string { return "org_shared" }),
			oauthprovider.ClientPrivileges(func(_ context.Context, action string, _ *auth.Call, _ *oauthprovider.Client) bool {
				return action != oauthprovider.ActionDelete
			}))
		ctx := request(o.a, o.token)
		reg := must[oauthprovider.Registration](t)(o.op.CreateOwnedClient(ctx, oauthprovider.ClientMetadata{Name: "Org app", RedirectURIs: []string{opRedirect}}))
		if reg.ReferenceID != "org_shared" || reg.OwnerID != "" {
			t.Fatalf("referenced client = %+v", reg)
		}
		bob := must[password.SignInResult](t)(o.pw.SignUp(anon(o.a), password.SignUpRequest{Identifier: "bob@example.com", Password: secret}))
		list := must[oauthprovider.ClientList](t)(o.op.Clients(request(o.a, bob.Token)))
		if len(list.Clients) != 1 || list.Clients[0].ClientID != reg.ClientID {
			t.Fatalf("a member of the reference sees = %+v", list)
		}
		if err := o.op.DeleteOwnedClient(ctx, reg.ClientID); !errors.Is(err, oauthprovider.ErrForbidden) {
			t.Fatalf("delete refused by privileges: %v", err)
		}
		if _, err := o.op.OwnedClient(request(o.a, bob.Token), reg.ClientID); err != nil {
			t.Fatalf("read by a member: %v", err)
		}
	})
}
