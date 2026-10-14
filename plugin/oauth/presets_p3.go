package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ubgo/auth"
)

// Dub endpoints (dub.co/docs/integrations/quickstart, read 2026-10-08), the
// ones @dub/better-auth's oauth option configures.
const (
	//ds:def id=dubauthurl-p3d7kx2m owner=@khanakia stability=stable
	DubAuthURL = "https://app.dub.co/oauth/authorize"
	//ds:def id=dubtokenurl-p3d4wq8n owner=@khanakia stability=stable
	DubTokenURL = "https://api.dub.co/oauth/token"
	//ds:def id=dubuserinfourl-p3d9mx3k owner=@khanakia stability=stable
	DubUserInfoURL = "https://api.dub.co/oauth/userinfo"
)

// Dub is Sign in with Dub, better-auth's dub plugin oauth option: PKCE
// (Dub enables it by default) and the user.read scope. The profile is
// /oauth/userinfo: id, name and image, no email, so a Dub sign-up creates a
// user with no address; the workspace the user authorized comes with it in
// Profile.Claims ("workspace"). Add Dub's API scopes (links.read, …) with
// Scopes or OptionalScopes and keep the tokens with StoreTokens to call the
// Dub API for the user.
//
//ds:def id=dub-p3k8wn2x owner=@khanakia stability=stable
func Dub(clientID, clientSecret string) *OAuth2 {
	return &OAuth2{
		ID: "dub", DisplayName: "Dub", ClientID: clientID, ClientSecret: clientSecret,
		AuthURL: DubAuthURL, TokenURL: DubTokenURL, Scopes: []string{"user.read"},
		FetchProfile: DubProfile(DubUserInfoURL),
	}
}

// DubProfile reads Dub's /oauth/userinfo answer from u: id, name, image.
func DubProfile(u string) func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
	return profileReader(http.MethodGet, u, nil, func(body json.RawMessage) (Profile, error) {
		var d struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			Image string `json:"image"`
		}
		if err := json.Unmarshal(body, &d); err != nil {
			return Profile{}, err
		}
		return Profile{Subject: d.ID, Name: d.Name, Image: d.Image}, nil
	})
}

// Instagram endpoints: the Instagram API with Instagram Login
// (developers.facebook.com/docs/instagram-platform/instagram-api-with-instagram-login,
// read 2026-10-08), the ones better-auth-instagram configures.
const (
	//ds:def id=instagramauthurl-p3i2kw7q owner=@khanakia stability=stable
	InstagramAuthURL = "https://www.instagram.com/oauth/authorize"
	//ds:def id=instagramtokenurl-p3i8nx4t owner=@khanakia stability=stable
	InstagramTokenURL = "https://api.instagram.com/oauth/access_token"
	// InstagramMeURL is the Graph API profile of the token's account, with
	// the fields the preset reads.
	//ds:def id=instagrammeurl-p3i5qk9w owner=@khanakia stability=stable
	InstagramMeURL = "https://graph.instagram.com/me?fields=id,user_id,username,name,profile_picture_url,account_type"
	// InstagramTokenLifetime is the life of the short-lived token the code
	// exchange returns, which carries no expires_in (one hour, as Instagram
	// documents it).
	//ds:def id=instagramtokenlifetime-p3i3wn6k owner=@khanakia stability=stable
	InstagramTokenLifetime = time.Hour
	// instagramForceReauth is the authorization parameter that makes
	// Instagram ask for the credentials again, better-auth-instagram's
	// forceReAuth, forwarded only when a start request asks for it.
	instagramForceReauth = "force_reauth"
)

// Instagram is sign-in with an Instagram professional (business or creator)
// account through the Instagram API with Instagram Login, as
// better-auth-instagram configures it: scopes comma-joined
// (instagram_business_basic), no PKCE (NoPKCE; Instagram documents none),
// and a token answer that is not RFC 6749: Instagram documents it wrapped in
// a data array ({"data":[{"access_token","user_id","permissions"}]}) and has
// answered it flat, so the exchange reads either. The token is the one-hour
// short-lived token (InstagramTokenLifetime) and cannot be refreshed: the
// long-lived exchange is a separate Graph API call the app makes with the
// stored token when it needs one. Instagram sends no email, so a sign-up
// creates a user with no address; better-auth-instagram invents
// "<id>@instagram.com" instead, which this preset does not, because an
// address nobody receives mail at would be verified-looking data that is
// false. "force_reauth" is an allowed per-request parameter
// (StartRequest.Params).
//
//ds:def id=instagram-p3n6xk2q owner=@khanakia stability=stable
func Instagram(appID, appSecret string) *OAuth2 {
	o := &OAuth2{
		ID: "instagram", DisplayName: "Instagram", ClientID: appID, ClientSecret: appSecret,
		NoPKCE: true, ScopeSeparator: commaScopes, TokenLifetime: InstagramTokenLifetime,
		AuthURL: InstagramAuthURL, TokenURL: InstagramTokenURL, Scopes: []string{"instagram_business_basic"},
		OptionalParams: []string{instagramForceReauth},
		FetchProfile:   InstagramProfile(InstagramMeURL),
	}
	o.exchange = func(ctx context.Context, hc *http.Client, code, redirectURI string) (TokenSet, error) {
		return o.instagramGrant(ctx, hc, code, redirectURI)
	}
	o.renew = func(context.Context, *http.Client, auth.Token) (TokenSet, error) {
		return TokenSet{}, fmt.Errorf("%w: instagram: a short-lived token cannot be refreshed", ErrExchange)
	}
	return o
}

// instagramGrant posts the authorization_code grant as a form with the
// client credentials in it, and reads Instagram's answer in either shape.
func (o *OAuth2) instagramGrant(ctx context.Context, hc *http.Client, code, redirectURI string) (TokenSet, error) {
	secret, err := o.clientSecret(ctx)
	if err != nil {
		return TokenSet{}, fmt.Errorf("%w: client secret: %v", ErrExchange, err)
	}
	form := url.Values{
		paramClientID: {o.ClientID}, paramClientSecret: {secret},
		paramGrantType: {grantAuthorizationCode}, paramRedirectURI: {redirectURI}, paramCode: {code},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenSet{}, fmt.Errorf("%w: token request: %v", ErrExchange, err)
	}
	req.Header.Set(headerContentType, contentTypeForm)
	req.Header.Set(headerAccept, contentTypeJSON)
	o.addHeaders(req)
	body, err := fetchJSON(hc, req)
	if err != nil {
		return TokenSet{}, err
	}
	inner, err := instagramTokenObject(body)
	if err != nil {
		return TokenSet{}, fmt.Errorf("%w: %v", ErrExchange, err)
	}
	var tok tokenResponse
	if err := json.Unmarshal(inner, &tok); err != nil {
		return TokenSet{}, fmt.Errorf("%w: %v", ErrExchange, err)
	}
	if tok.AccessToken == "" {
		return TokenSet{}, fmt.Errorf("%w: token endpoint: %s", ErrExchange, firstOf(tok.Error, string(body)))
	}
	tok.raw = inner
	ts := tok.tokenSet(o.TokenLifetime)
	ts.Scope = instagramPermissions(inner)
	return ts, nil
}

// instagramTokenObject is the token object of an Instagram answer: the first
// element of its data array when it has one, else the answer itself.
func instagramTokenObject(body json.RawMessage) (json.RawMessage, error) {
	var wrapped struct {
		Data []json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &wrapped); err != nil {
		return nil, err
	}
	if len(wrapped.Data) > 0 {
		return wrapped.Data[0], nil
	}
	return body, nil
}

// instagramPermissions is the granted scope of a token object, space
// separated like every TokenSet.Scope: Instagram sends "permissions" as a
// comma-joined string, or as an array. Anything else is "" (unknown).
func instagramPermissions(obj json.RawMessage) string {
	var p struct {
		Permissions json.RawMessage `json:"permissions"`
	}
	if json.Unmarshal(obj, &p) != nil || len(p.Permissions) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(p.Permissions, &s) == nil {
		return strings.ReplaceAll(s, commaScopes, scopeSeparator)
	}
	var list []string
	if json.Unmarshal(p.Permissions, &list) == nil {
		return strings.Join(list, scopeSeparator)
	}
	return ""
}

// InstagramProfile reads the Graph API /me answer from u: the app-scoped id
// as subject (better-auth-instagram's), the name or else the username, and
// the profile picture.
func InstagramProfile(u string) func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
	return profileReader(http.MethodGet, u, nil, func(body json.RawMessage) (Profile, error) {
		var g struct {
			ID                string `json:"id"`
			Username          string `json:"username"`
			Name              string `json:"name"`
			ProfilePictureURL string `json:"profile_picture_url"`
			Error             struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(body, &g); err != nil {
			return Profile{}, err
		}
		if g.Error.Message != "" {
			return Profile{}, fmt.Errorf("instagram: %s", g.Error.Message)
		}
		return Profile{Subject: g.ID, Name: firstOf(g.Name, g.Username), Image: g.ProfilePictureURL}, nil
	})
}

// ZohoRegion is a Zoho data centre's accounts server, which is also its
// OpenID Connect issuer: a Zoho app is registered in one data centre and
// signs in that centre's users. Each value was read from the centre's
// discovery document on 2026-10-08 (S256, client_secret_basic and _post,
// /oauth/v2/userinfo on every one).
type ZohoRegion string

// The Zoho data centres, better-auth-zoho's location option (with China,
// which it leaves out).
const (
	//ds:def id=zohoregions-p3z4kw8n owner=@khanakia stability=stable
	ZohoUS        ZohoRegion = "https://accounts.zoho.com"
	ZohoEU        ZohoRegion = "https://accounts.zoho.eu"
	ZohoIndia     ZohoRegion = "https://accounts.zoho.in"
	ZohoAustralia ZohoRegion = "https://accounts.zoho.com.au"
	ZohoJapan     ZohoRegion = "https://accounts.zoho.jp"
	ZohoUK        ZohoRegion = "https://accounts.zoho.uk"
	ZohoCanada    ZohoRegion = "https://accounts.zohocloud.ca"
	ZohoSaudi     ZohoRegion = "https://accounts.zoho.sa"
	ZohoChina     ZohoRegion = "https://accounts.zoho.com.cn"
)

// ZohoRegionValues lists every ZohoRegion, for a configuration screen and
// for the test that keeps the set closed.
var ZohoRegionValues = []ZohoRegion{ZohoUS, ZohoEU, ZohoIndia, ZohoAustralia, ZohoJapan, ZohoUK, ZohoCanada, ZohoSaudi, ZohoChina}

// Zoho is Sign in with Zoho through OpenID Connect at region's accounts
// server, as better-auth-zoho configures it (discovery, scopes openid,
// email and profile). Use the data centre the app was registered in.
//
//ds:def id=zoho-p3w7nq4k owner=@khanakia stability=stable
func Zoho(region ZohoRegion, clientID, clientSecret string) *OIDCProvider {
	p := withDisplayName(OIDC("zoho", string(region), clientID, clientSecret), "Zoho")
	p.Scopes = []string{"openid", "email", "profile"}
	return p
}

// Snapchat endpoints: Login Kit's server-side OAuth2 flow
// (developers.snap.com/snap-kit/login-kit/Tutorials/web, read 2026-10-08)
// and the Snap Kit /v1/me GraphQL read better-auth-snapchat uses.
const (
	//ds:def id=snapchatauthurl-p3s8wk2n owner=@khanakia stability=stable
	SnapchatAuthURL = "https://accounts.snapchat.com/accounts/oauth2/auth"
	//ds:def id=snapchattokenurl-p3s3nx7q owner=@khanakia stability=stable
	SnapchatTokenURL = "https://accounts.snapchat.com/accounts/oauth2/token"
	//ds:def id=snapchatrevokeurl-p3s6qw4k owner=@khanakia stability=stable
	SnapchatRevokeURL = "https://accounts.snapchat.com/accounts/oauth2/revoke"
	//ds:def id=snapchatmeurl-p3s9kx5t owner=@khanakia stability=stable
	SnapchatMeURL = "https://kit.snapchat.com/v1/me"
	// SnapchatScopePrefix is how Snapchat names a scope: the full URL.
	//ds:def id=snapchatscopeprefix-p3s2wn8x owner=@khanakia stability=stable
	SnapchatScopePrefix = "https://auth.snapchat.com/oauth2/api/"
	// snapchatMeQuery is the GraphQL query of the profile read.
	snapchatMeQuery = "{me{externalId displayName bitmoji{avatar}}}"
	// snapchatQueryParam names the GraphQL query parameter of /v1/me.
	snapchatQueryParam = "query"
)

// Snapchat is Login with Snapchat (Login Kit), as better-auth-snapchat
// configures it: the scopes user.external_id, user.display_name and
// user.bitmoji.avatar as Snapchat's full scope URLs (SnapchatScopePrefix),
// the token endpoint with HTTP Basic as Snapchat documents it, PKCE S256
// on, revocation of the refresh token at unlink, and the profile from Snap
// Kit's /v1/me: the externalId as subject, the display name and the Bitmoji
// avatar. Snapchat sends no email, so a sign-up creates a user with no
// address; better-auth-snapchat invents "<id>@snapchat.com", which this
// preset does not, for the reason Instagram gives.
//
//ds:def id=snapchat-p3c4kn9w owner=@khanakia stability=stable
func Snapchat(clientID, clientSecret string) *OAuth2 {
	return &OAuth2{
		ID: "snapchat", DisplayName: "Snapchat", ClientID: clientID, ClientSecret: clientSecret, TokenAuth: ClientSecretBasic,
		AuthURL: SnapchatAuthURL, TokenURL: SnapchatTokenURL, RevokeURL: SnapchatRevokeURL,
		Scopes:       []string{SnapchatScopePrefix + "user.external_id", SnapchatScopePrefix + "user.display_name", SnapchatScopePrefix + "user.bitmoji.avatar"},
		FetchProfile: SnapchatProfile(SnapchatMeURL),
	}
}

// SnapchatProfile reads Snap Kit's /v1/me at u with the GraphQL query for
// externalId, displayName and the Bitmoji avatar. A GraphQL error, or an
// answer with no externalId (the user.external_id scope not granted), is a
// failed read.
func SnapchatProfile(u string) func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
	q := url.Values{snapchatQueryParam: {snapchatMeQuery}}
	return profileReader(http.MethodGet, u+"?"+q.Encode(), nil, func(body json.RawMessage) (Profile, error) {
		var s struct {
			Data struct {
				Me struct {
					ExternalID  string `json:"externalId"`
					DisplayName string `json:"displayName"`
					Bitmoji     struct {
						Avatar string `json:"avatar"`
					} `json:"bitmoji"`
				} `json:"me"`
			} `json:"data"`
			Errors []struct {
				Message string `json:"message"`
			} `json:"errors"`
		}
		if err := json.Unmarshal(body, &s); err != nil {
			return Profile{}, err
		}
		if len(s.Errors) > 0 {
			return Profile{}, fmt.Errorf("snapchat: %s", s.Errors[0].Message)
		}
		me := s.Data.Me
		if me.ExternalID == "" {
			return Profile{}, fmt.Errorf("snapchat: no externalId; is the user.external_id scope granted?")
		}
		return Profile{Subject: me.ExternalID, Name: me.DisplayName, Image: me.Bitmoji.Avatar}, nil
	})
}
