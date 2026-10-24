package oauthtest_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/oauth/oauthtest"
)

// The plugin's own providers run the kit: the two built-ins, the generic
// OAuth2 and OIDC shapes (userinfo, ID-token profile, public client) and a
// sample of presets covering each token-endpoint authentication and profile
// parser family. Each preset keeps its own profile parser and is only
// pointed at the fake server.

// pointAt aims an *OAuth2 at the fake server's endpoints.
func pointAt(o *oauth.OAuth2, u string) *oauth.OAuth2 {
	o.AuthURL, o.TokenURL = u+oauthtest.AuthorizePath, u+oauthtest.TokenPath
	return o
}

// numericID renders a subject as the JSON number GitHub-shaped APIs use,
// leaving it out for the person with no subject.
func numericID(out map[string]any, subject string) map[string]any {
	if n, err := strconv.ParseInt(subject, 10, 64); err == nil {
		out["id"] = n
	}
	return out
}

// stringID puts the subject under key when there is one.
func stringID(out map[string]any, key, subject string) map[string]any {
	if subject != "" {
		out[key] = subject
	}
	return out
}

func TestConformance_Google(t *testing.T) {
	rep := oauthtest.Run(t, func(u string) oauth.Provider {
		g := pointAt(oauth.Google(oauthtest.ClientID, oauthtest.ClientSecret), u)
		g.FetchProfile = oauth.GoogleProfile(u + oauthtest.UserInfoPath)
		return g
	}, oauthtest.WantScopes("openid", "email", "profile"))
	if !rep.PKCE || !rep.ReportsVerified || !rep.ProfileCall {
		t.Fatalf("report = %+v", rep)
	}
}

// ds:def id=testconformance-github-8d2nun37 owner=@khanakia stability=stable
func TestConformance_GitHub(t *testing.T) {
	oauthtest.Run(t, func(u string) oauth.Provider {
		g := pointAt(oauth.GitHub(oauthtest.ClientID, oauthtest.ClientSecret), u)
		g.FetchProfile = oauth.GitHubProfile(u + "/github")
		return g
	}, oauthtest.WantScopes("user:email"),
		oauthtest.Route("/github/user", func(p oauthtest.Person) any {
			return numericID(map[string]any{"login": "octo", "name": p.Name}, p.Subject)
		}),
		oauthtest.Route("/github/user/emails", func(p oauthtest.Person) any {
			return []map[string]any{{"email": "old@example.com", "primary": false, "verified": true}, {"email": p.Email, "primary": true, "verified": p.EmailVerified}}
		}))
}

// ds:def id=testconformance-oauth2userinfo-z75vqp6t owner=@khanakia stability=stable
func TestConformance_OAuth2UserInfo(t *testing.T) {
	oauthtest.Run(t, func(u string) oauth.Provider {
		return pointAt(&oauth.OAuth2{ID: "corp", ClientID: oauthtest.ClientID, ClientSecret: oauthtest.ClientSecret, Scopes: []string{"openid", "email"},
			FetchProfile: oauth.UserInfoProfile(u+oauthtest.UserInfoPath, "")}, u)
	}, oauthtest.WantScopes("openid", "email"))
}

func TestConformance_OAuth2ProfileFromIDToken(t *testing.T) {
	rep := oauthtest.Run(t, func(u string) oauth.Provider {
		return pointAt(&oauth.OAuth2{ID: "corp", ClientID: oauthtest.ClientID, ClientSecret: oauthtest.ClientSecret, Scopes: []string{"openid", "email"},
			IDToken: oauth.IDTokenConfig{JWKSURL: u + oauthtest.JWKSPath, Issuers: []string{u}, ProfileFromToken: true}}, u)
	})
	if rep.ProfileCall {
		t.Fatalf("a provider reading the ID token made a profile call: %+v", rep)
	}
}

func TestConformance_OAuth2PublicClientBasic(t *testing.T) {
	oauthtest.Run(t, func(u string) oauth.Provider {
		return pointAt(&oauth.OAuth2{ID: "spa", ClientID: oauthtest.ClientID, TokenAuth: oauth.PublicClient,
			FetchProfile: oauth.UserInfoProfile(u+oauthtest.UserInfoPath, "")}, u)
	}, oauthtest.PublicClient())
}

func TestConformance_OIDC(t *testing.T) {
	for name, build := range map[string]func(issuer, id, secret string) *oauth.OIDCProvider{
		"oidc": func(issuer, id, secret string) *oauth.OIDCProvider { return oauth.OIDC("corp", issuer, id, secret) },
		"okta": oauth.Okta, "keycloak": oauth.Keycloak, "gitlab": oauth.GitLab, "zitadel": oauth.Zitadel,
	} {
		t.Run(name, func(t *testing.T) {
			oauthtest.Run(t, func(u string) oauth.Provider { return build(u, oauthtest.ClientID, oauthtest.ClientSecret) },
				oauthtest.WantScopes("openid", "email", "profile"))
		})
	}
}

func TestConformance_Discord(t *testing.T) {
	oauthtest.Run(t, func(u string) oauth.Provider {
		d := pointAt(oauth.Discord(oauthtest.ClientID, oauthtest.ClientSecret), u)
		d.FetchProfile = oauth.DiscordProfile(u + "/discord/users/@me")
		return d
	}, oauthtest.WantScopes("identify", "email"),
		oauthtest.Route("/discord/users/@me", func(p oauthtest.Person) any {
			return stringID(map[string]any{"username": "ada", "global_name": p.Name, "email": p.Email, "verified": p.EmailVerified}, "id", p.Subject)
		}))
}

// Zoom authenticates to the token endpoint with HTTP Basic and sets no
// scope in the URL.
func TestConformance_Zoom(t *testing.T) {
	oauthtest.Run(t, func(u string) oauth.Provider {
		z := pointAt(oauth.Zoom(oauthtest.ClientID, oauthtest.ClientSecret), u)
		z.FetchProfile = oauth.ZoomProfile(u + "/zoom/me")
		return z
	}, oauthtest.Route("/zoom/me", func(p oauthtest.Person) any {
		verified := 0
		if p.EmailVerified {
			verified = 1
		}
		return stringID(map[string]any{"email": p.Email, "display_name": p.Name, "verified": verified}, "id", p.Subject)
	}))
}

// TestConformance_OAuth2GetToken runs a provider whose code exchange is a
// GetToken hook: the hook posts the grant itself, and the kit's cases (the
// endpoint's error answer, a wrong verifier, a body that is not JSON, no
// access token) prove the plugin's side keeps every rule around it.
// ds:def id=testconformance-oauth2gettoken-8mz8ze65 owner=@khanakia stability=stable
func TestConformance_OAuth2GetToken(t *testing.T) {
	oauthtest.Run(t, func(u string) oauth.Provider {
		o := pointAt(&oauth.OAuth2{ID: "custom", ClientID: oauthtest.ClientID, ClientSecret: oauthtest.ClientSecret, Scopes: []string{"openid", "email"},
			FetchProfile: oauth.UserInfoProfile(u+oauthtest.UserInfoPath, "")}, u)
		o.TokenURL = "" // the hook is the only way to the token endpoint
		o.GetToken = func(ctx context.Context, code, verifier, redirectURI string) (oauth.TokenSet, error) {
			return postGrant(ctx, u+oauthtest.TokenPath, url.Values{
				"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {redirectURI},
				"client_id": {oauthtest.ClientID}, "client_secret": {oauthtest.ClientSecret},
			})
		}
		return o
	}, oauthtest.WantScopes("openid", "email"))
}

// errGrant is a token endpoint that refused the grant or answered nonsense.
var errGrant = errors.New("custom token endpoint refused the grant")

// postGrant is a GetToken body: the grant posted by hand, as an app whose
// provider needs another request shape would write it.
func postGrant(ctx context.Context, tokenURL string, form url.Values) (oauth.TokenSet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return oauth.TokenSet{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return oauth.TokenSet{}, err
	}
	defer res.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil || out.Error != "" {
		return oauth.TokenSet{}, errGrant
	}
	return oauth.TokenSet{AccessToken: auth.Token(out.AccessToken)}, nil
}

// TestConformance_OIDCFallback runs an OIDC provider whose discovery
// document is missing (the issuer path serves none), so every case runs on
// its Fallback endpoints.
// ds:def id=testconformance-oidcfallback-9hh5cuuv owner=@khanakia stability=stable
func TestConformance_OIDCFallback(t *testing.T) {
	oauthtest.Run(t, func(u string) oauth.Provider {
		o := oauth.OIDC("corp", u+"/no-discovery", oauthtest.ClientID, oauthtest.ClientSecret)
		o.Fallback = oauth.Endpoints{AuthURL: u + oauthtest.AuthorizePath, TokenURL: u + oauthtest.TokenPath, UserInfoURL: u + oauthtest.UserInfoPath}
		o.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
		return o
	}, oauthtest.WantScopes("openid", "email", "profile"))
}
