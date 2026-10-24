package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// This file holds the provider presets beyond Google, GitHub and Apple: one
// constructor per provider, each an *OAuth2 or an *OIDCProvider filled with
// the provider's endpoints, default scopes, token-endpoint authentication and
// a profile reader for its API's shape. The shapes follow what each provider
// documents; the parsers are pinned by fixture tests, not by calls to the live
// provider. Every URL is an exported constant, so a test or a sandbox
// deployment can point a preset elsewhere.
//
// A preset's email is marked verified only when the provider says so in the
// answer. Where the provider has no such flag (Facebook, Spotify, Figma,
// Discord without `verified`), EmailVerified is false and the account does
// not link to an existing user by email; TrustedProviders names the ones an
// app chooses to trust.

// OpenID Connect issuers. Each preset is OIDC with the issuer's own default
// scopes; every one of them publishes a discovery document with a userinfo
// endpoint.
const (
	//ds:def id=slackissuer-k2wq8tnm owner=@khanakia stability=stable
	SlackIssuer = "https://slack.com"
	//ds:def id=linkedinissuer-x7mq3bkz owner=@khanakia stability=stable
	LinkedInIssuer = "https://www.linkedin.com/oauth"
	//ds:def id=gitlabissuer-p4nt9wqr owner=@khanakia stability=stable
	GitLabIssuer = "https://gitlab.com"
	//ds:def id=twitchissuer-v8kx2mqn owner=@khanakia stability=stable
	TwitchIssuer = "https://id.twitch.tv/oauth2"
	//ds:def id=lineissuer-h3zr7xkt owner=@khanakia stability=stable
	LINEIssuer = "https://access.line.me"
	//ds:def id=huggingfaceissuer-b6wn4pqm owner=@khanakia stability=stable
	HuggingFaceIssuer = "https://huggingface.co"
	//ds:def id=robloxissuer-t9mk5xqw owner=@khanakia stability=stable
	RobloxIssuer = "https://apis.roblox.com/oauth"
	//ds:def id=salesforceissuer-n2qt8wkr owner=@khanakia stability=stable
	SalesforceIssuer = "https://login.salesforce.com"
	// SalesforceSandboxIssuer is the issuer of Salesforce sandbox orgs.
	//ds:def id=salesforcesandboxissuer-m5xk3nqz owner=@khanakia stability=stable
	SalesforceSandboxIssuer = "https://test.salesforce.com"
	// PaybinIssuer and RailwayIssuer were read from their discovery
	// documents on 2026-10-03: both publish a userinfo endpoint, S256 and
	// client_secret_post; Railway also announces the RFC 9207 iss parameter.
	//ds:def id=paybinissuer-k8wq3xtn owner=@khanakia stability=stable
	PaybinIssuer = "https://idp.paybin.io"
	//ds:def id=railwayissuer-m4nt7xkq owner=@khanakia stability=stable
	RailwayIssuer = "https://backboard.railway.com"
)

// Paybin is Sign in with Paybin through OpenID Connect.
//
//ds:def id=paybin-x6tk9wqn owner=@khanakia stability=stable
func Paybin(clientID, clientSecret string) *OIDCProvider {
	return withDisplayName(OIDC("paybin", PaybinIssuer, clientID, clientSecret), "Paybin")
}

// Railway is Railway sign-in through OpenID Connect; the userinfo endpoint
// is its /oauth/me.
//
//ds:def id=railway-q2wn8xkt owner=@khanakia stability=stable
func Railway(clientID, clientSecret string) *OIDCProvider {
	return withDisplayName(OIDC("railway", RailwayIssuer, clientID, clientSecret), "Railway")
}

// Slack is Sign in with Slack through OpenID Connect.
//
//ds:def id=slack-r4tn7wkq owner=@khanakia stability=stable
func Slack(clientID, clientSecret string) *OIDCProvider {
	return withDisplayName(OIDC("slack", SlackIssuer, clientID, clientSecret), "Slack")
}

// LinkedIn is Sign in with LinkedIn through OpenID Connect; the product
// "Sign In with LinkedIn using OpenID Connect" must be enabled on the app.
//
//ds:def id=linkedin-w9qk2xtm owner=@khanakia stability=stable
func LinkedIn(clientID, clientSecret string) *OIDCProvider {
	return withDisplayName(OIDC("linkedin", LinkedInIssuer, clientID, clientSecret), "LinkedIn")
}

// GitLab is GitLab sign-in through OpenID Connect; issuer is GitLabIssuer or
// a self-hosted instance.
//
//ds:def id=gitlab-z3mn8kqw owner=@khanakia stability=stable
func GitLab(issuer, clientID, clientSecret string) *OIDCProvider {
	return withDisplayName(OIDC("gitlab", issuer, clientID, clientSecret), "GitLab")
}

// twitchClaims asks Twitch's userinfo endpoint for the claims it only sends
// when requested (OpenID Connect Core section 5.5).
const twitchClaims = `{"userinfo":{"email":null,"email_verified":null,"picture":null,"preferred_username":null}}`

// twitchEmailScope is the scope Twitch needs before it releases the email.
const twitchEmailScope = "user:read:email"

// Twitch is Twitch sign-in through OpenID Connect, with the claims request
// Twitch needs before its userinfo endpoint sends the email, picture and
// username.
//
//ds:def id=twitch-c8xq4wnk owner=@khanakia stability=stable
func Twitch(clientID, clientSecret string) *OIDCProvider {
	p := withDisplayName(OIDC("twitch", TwitchIssuer, clientID, clientSecret), "Twitch")
	p.Scopes = []string{"openid", twitchEmailScope}
	p.AuthParams = url.Values{paramClaims: {twitchClaims}}
	return p
}

// paramClaims is the OpenID Connect claims request parameter.
const paramClaims = "claims"

// LINE is LINE Login through OpenID Connect; the email scope needs LINE's
// approval for the channel.
//
//ds:def id=line-f7wk3nqt owner=@khanakia stability=stable
func LINE(clientID, clientSecret string) *OIDCProvider {
	return withDisplayName(OIDC("line", LINEIssuer, clientID, clientSecret), "LINE")
}

// HuggingFace is Hugging Face sign-in through OpenID Connect.
//
//ds:def id=huggingface-q2nt9xkw owner=@khanakia stability=stable
func HuggingFace(clientID, clientSecret string) *OIDCProvider {
	return withDisplayName(OIDC("huggingface", HuggingFaceIssuer, clientID, clientSecret), "Hugging Face")
}

// Roblox is Roblox sign-in through OpenID Connect. Roblox has no email
// scope, so the profile carries the subject, name and picture only.
//
//ds:def id=roblox-m6kq8wtn owner=@khanakia stability=stable
func Roblox(clientID, clientSecret string) *OIDCProvider {
	p := withDisplayName(OIDC("roblox", RobloxIssuer, clientID, clientSecret), "Roblox")
	p.Scopes = []string{"openid", "profile"}
	return p
}

// Salesforce is Salesforce sign-in through OpenID Connect; issuer is
// SalesforceIssuer, SalesforceSandboxIssuer or a My Domain.
//
//ds:def id=salesforce-k4xw7nqm owner=@khanakia stability=stable
func Salesforce(issuer, clientID, clientSecret string) *OIDCProvider {
	return withDisplayName(OIDC("salesforce", issuer, clientID, clientSecret), "Salesforce")
}

// Auth0 is an Auth0 tenant through OpenID Connect; domain is the tenant
// domain such as "acme.us.auth0.com", with or without the scheme.
//
//ds:def id=auth0-t8mq2wkn owner=@khanakia stability=stable
func Auth0(domain, clientID, clientSecret string) *OIDCProvider {
	return withDisplayName(OIDC("auth0", withHTTPS(domain), clientID, clientSecret), "Auth0")
}

// Okta is an Okta org or authorization server through OpenID Connect; issuer
// is "https://<org>.okta.com" or "https://<org>.okta.com/oauth2/<server>".
//
//ds:def id=okta-n3kw9xqt owner=@khanakia stability=stable
func Okta(issuer, clientID, clientSecret string) *OIDCProvider {
	return withDisplayName(OIDC("okta", issuer, clientID, clientSecret), "Okta")
}

// Keycloak is a Keycloak realm through OpenID Connect; issuer is
// "https://<host>/realms/<realm>".
//
//ds:def id=keycloak-w2xn6kqm owner=@khanakia stability=stable
func Keycloak(issuer, clientID, clientSecret string) *OIDCProvider {
	return withDisplayName(OIDC("keycloak", issuer, clientID, clientSecret), "Keycloak")
}

// Zitadel is a Zitadel instance through OpenID Connect; issuer is the
// instance's URL.
//
//ds:def id=zitadel-q7tk4wnx owner=@khanakia stability=stable
func Zitadel(issuer, clientID, clientSecret string) *OIDCProvider {
	return withDisplayName(OIDC("zitadel", issuer, clientID, clientSecret), "Zitadel")
}

// cognitoIssuerFormat builds a Cognito user pool's issuer from its region
// and pool id.
const cognitoIssuerFormat = "https://cognito-idp.%s.amazonaws.com/%s"

// Cognito is an Amazon Cognito user pool through OpenID Connect: the pool's
// discovery document publishes its hosted UI as the authorization endpoint.
//
//ds:def id=cognito-b9wq3xkt owner=@khanakia stability=stable
func Cognito(region, userPoolID, clientID, clientSecret string) *OIDCProvider {
	return withDisplayName(OIDC("cognito", fmt.Sprintf(cognitoIssuerFormat, region, userPoolID), clientID, clientSecret), "Amazon Cognito")
}

// withHTTPS adds the scheme a bare domain lacks.
func withHTTPS(domain string) string {
	if strings.Contains(domain, "://") {
		return strings.TrimSuffix(domain, "/")
	}
	return httpsPrefix + strings.TrimSuffix(domain, "/")
}

// Microsoft Entra ID endpoints. The tenant is a tenant id or domain, or one
// of the multi-tenant aliases common, organizations and consumers.
const (
	//ds:def id=microsoftauthurlformat-x4kn8wqt owner=@khanakia stability=stable
	MicrosoftAuthURLFormat = "https://login.microsoftonline.com/%s/oauth2/v2.0/authorize"
	//ds:def id=microsofttokenurlformat-m7wq2xkn owner=@khanakia stability=stable
	MicrosoftTokenURLFormat = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"
	//ds:def id=microsoftjwksurlformat-t2kq9wnx owner=@khanakia stability=stable
	MicrosoftJWKSURLFormat = "https://login.microsoftonline.com/%s/discovery/v2.0/keys"
	//ds:def id=microsoftissuerformat-k8xn3wqm owner=@khanakia stability=stable
	MicrosoftIssuerFormat = "https://login.microsoftonline.com/%s/v2.0"
	//ds:def id=microsoftuserinfourl-w3qt7xkn owner=@khanakia stability=stable
	MicrosoftUserInfoURL = "https://graph.microsoft.com/oidc/userinfo"
	// microsoftSubjectClaim is Entra's stable identifier: oid survives the
	// app being re-registered where sub does not.
	microsoftSubjectClaim = "oid"
)

// microsoftMultiTenant are the tenant aliases whose discovery document names
// a templated issuer, so ID tokens cannot be verified against one issuer
// and the preset leaves the id-token route off.
var microsoftMultiTenant = []string{"common", "organizations", "consumers"}

// Microsoft is Microsoft Entra ID (work, school and personal accounts). The
// endpoints are static rather than discovered because the multi-tenant
// aliases publish a templated issuer the discovery check would refuse. The
// subject is the oid claim. Graph's userinfo has no email_verified, so the
// email is unverified: name the provider in TrustedProviders to link by it.
// With a single tenant the preset also accepts ID tokens (MSAL on mobile).
//
//ds:def id=microsoft-r5wk8xqn owner=@khanakia stability=stable
func Microsoft(tenant, clientID, clientSecret string) *OAuth2 {
	o := &OAuth2{
		ID: "microsoft", DisplayName: "Microsoft", ClientID: clientID, ClientSecret: clientSecret,
		AuthURL: fmt.Sprintf(MicrosoftAuthURLFormat, tenant), TokenURL: fmt.Sprintf(MicrosoftTokenURLFormat, tenant),
		Scopes:       openIDScopes(),
		FetchProfile: UserInfoProfile(MicrosoftUserInfoURL, microsoftSubjectClaim),
	}
	if !containsFold(microsoftMultiTenant, tenant) {
		o.IDToken = IDTokenConfig{JWKSURL: fmt.Sprintf(MicrosoftJWKSURLFormat, tenant), Issuers: []string{fmt.Sprintf(MicrosoftIssuerFormat, tenant)}}
	}
	return o
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// Discord endpoints.
const (
	//ds:def id=discordauthurl-n8kq4wxt owner=@khanakia stability=stable
	DiscordAuthURL = "https://discord.com/oauth2/authorize"
	//ds:def id=discordtokenurl-q3wn7xkm owner=@khanakia stability=stable
	DiscordTokenURL = "https://discord.com/api/oauth2/token"
	//ds:def id=discorduserurl-x6tk2wqn owner=@khanakia stability=stable
	DiscordUserURL = "https://discord.com/api/users/@me"
	// discordAvatarFormat builds the CDN URL of a user's avatar.
	discordAvatarFormat = "https://cdn.discordapp.com/avatars/%s/%s.png"
)

// Discord is Discord sign-in: scopes identify and email, profile from
// /users/@me; the email is verified when Discord says so.
//
//ds:def id=discord-k9xq3wnt owner=@khanakia stability=stable
func Discord(clientID, clientSecret string) *OAuth2 {
	return &OAuth2{
		ID: "discord", DisplayName: "Discord", ClientID: clientID, ClientSecret: clientSecret,
		AuthURL: DiscordAuthURL, TokenURL: DiscordTokenURL, Scopes: []string{"identify", "email"},
		FetchProfile: DiscordProfile(DiscordUserURL),
	}
}

// DiscordProfile reads Discord's /users/@me answer from u.
func DiscordProfile(u string) func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
	return profileReader(http.MethodGet, u, nil, func(body json.RawMessage) (Profile, error) {
		var d struct {
			ID         string  `json:"id"`
			Username   string  `json:"username"`
			GlobalName string  `json:"global_name"`
			Email      string  `json:"email"`
			Verified   boolish `json:"verified"`
			Avatar     string  `json:"avatar"`
		}
		if err := json.Unmarshal(body, &d); err != nil {
			return Profile{}, err
		}
		p := Profile{Subject: d.ID, Email: d.Email, EmailVerified: bool(d.Verified), Name: firstOf(d.GlobalName, d.Username)}
		if d.Avatar != "" && d.ID != "" {
			p.Image = fmt.Sprintf(discordAvatarFormat, d.ID, d.Avatar)
		}
		return p, nil
	})
}

// Facebook endpoints (Graph API v24.0).
const (
	//ds:def id=facebookauthurl-w7kn3xqt owner=@khanakia stability=stable
	FacebookAuthURL = "https://www.facebook.com/v24.0/dialog/oauth"
	//ds:def id=facebooktokenurl-t4xq8wkn owner=@khanakia stability=stable
	FacebookTokenURL = "https://graph.facebook.com/v24.0/oauth/access_token"
	//ds:def id=facebookprofileurl-m2wk9xqn owner=@khanakia stability=stable
	FacebookProfileURL = "https://graph.facebook.com/v24.0/me?fields=id,name,email,picture.type(large)"
)

// Facebook is Facebook Login: scopes email and public_profile, profile from
// /me. The Graph API has no verified flag for the email, so it is
// unverified; TrustedProviders("facebook") trusts it.
//
//ds:def id=facebook-q8tn4wkx owner=@khanakia stability=stable
func Facebook(clientID, clientSecret string) *OAuth2 {
	return &OAuth2{
		ID: "facebook", DisplayName: "Facebook", ClientID: clientID, ClientSecret: clientSecret,
		AuthURL: FacebookAuthURL, TokenURL: FacebookTokenURL, Scopes: []string{"email", "public_profile"},
		FetchProfile: FacebookProfile(FacebookProfileURL),
	}
}

// FacebookProfile reads Facebook's /me answer from u.
func FacebookProfile(u string) func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
	return profileReader(http.MethodGet, u, nil, func(body json.RawMessage) (Profile, error) {
		var f struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Email   string `json:"email"`
			Picture struct {
				Data struct {
					URL string `json:"url"`
				} `json:"data"`
			} `json:"picture"`
		}
		if err := json.Unmarshal(body, &f); err != nil {
			return Profile{}, err
		}
		return Profile{Subject: f.ID, Email: f.Email, Name: f.Name, Image: f.Picture.Data.URL}, nil
	})
}

// Spotify endpoints.
const (
	//ds:def id=spotifyauthurl-k3wq7xnt owner=@khanakia stability=stable
	SpotifyAuthURL = "https://accounts.spotify.com/authorize"
	//ds:def id=spotifytokenurl-x9kn2wqt owner=@khanakia stability=stable
	SpotifyTokenURL = "https://accounts.spotify.com/api/token"
	//ds:def id=spotifyprofileurl-n6tq4wkx owner=@khanakia stability=stable
	SpotifyProfileURL = "https://api.spotify.com/v1/me"
)

// Spotify is Spotify sign-in: scope user-read-email, profile from /v1/me;
// Spotify has no verified flag, so the email is unverified.
//
//ds:def id=spotify-w4xk8nqm owner=@khanakia stability=stable
func Spotify(clientID, clientSecret string) *OAuth2 {
	return &OAuth2{
		ID: "spotify", DisplayName: "Spotify", ClientID: clientID, ClientSecret: clientSecret,
		AuthURL: SpotifyAuthURL, TokenURL: SpotifyTokenURL, Scopes: []string{"user-read-email"},
		FetchProfile: SpotifyProfile(SpotifyProfileURL),
	}
}

// SpotifyProfile reads Spotify's /v1/me answer from u.
func SpotifyProfile(u string) func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
	return profileReader(http.MethodGet, u, nil, func(body json.RawMessage) (Profile, error) {
		var s struct {
			ID          string `json:"id"`
			Email       string `json:"email"`
			DisplayName string `json:"display_name"`
			Images      []struct {
				URL string `json:"url"`
			} `json:"images"`
		}
		if err := json.Unmarshal(body, &s); err != nil {
			return Profile{}, err
		}
		p := Profile{Subject: s.ID, Email: s.Email, Name: s.DisplayName}
		if len(s.Images) > 0 {
			p.Image = s.Images[0].URL
		}
		return p, nil
	})
}

// Dropbox endpoints.
const (
	//ds:def id=dropboxauthurl-t7kq3wxn owner=@khanakia stability=stable
	DropboxAuthURL = "https://www.dropbox.com/oauth2/authorize"
	//ds:def id=dropboxtokenurl-m9xn8wqk owner=@khanakia stability=stable
	DropboxTokenURL = "https://api.dropboxapi.com/oauth2/token"
	//ds:def id=dropboxprofileurl-q2wt4xkn owner=@khanakia stability=stable
	DropboxProfileURL = "https://api.dropboxapi.com/2/users/get_current_account"
)

// Dropbox is Dropbox sign-in: scope account_info.read, profile from
// get_current_account (a POST), email verified when Dropbox says so.
//
//ds:def id=dropbox-x3nk7wqt owner=@khanakia stability=stable
func Dropbox(clientID, clientSecret string) *OAuth2 {
	return &OAuth2{
		ID: "dropbox", DisplayName: "Dropbox", ClientID: clientID, ClientSecret: clientSecret,
		AuthURL: DropboxAuthURL, TokenURL: DropboxTokenURL, Scopes: []string{"account_info.read"},
		FetchProfile: DropboxProfile(DropboxProfileURL),
	}
}

// DropboxProfile posts to Dropbox's get_current_account at u.
func DropboxProfile(u string) func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
	return profileReader(http.MethodPost, u, nil, func(body json.RawMessage) (Profile, error) {
		var d struct {
			AccountID     string  `json:"account_id"`
			Email         string  `json:"email"`
			EmailVerified boolish `json:"email_verified"`
			Name          struct {
				DisplayName string `json:"display_name"`
			} `json:"name"`
			ProfilePhotoURL string `json:"profile_photo_url"`
		}
		if err := json.Unmarshal(body, &d); err != nil {
			return Profile{}, err
		}
		return Profile{Subject: d.AccountID, Email: d.Email, EmailVerified: bool(d.EmailVerified), Name: d.Name.DisplayName, Image: d.ProfilePhotoURL}, nil
	})
}

// X (Twitter) endpoints.
const (
	//ds:def id=xauthurl-k6wn2xqt owner=@khanakia stability=stable
	XAuthURL = "https://x.com/i/oauth2/authorize"
	//ds:def id=xtokenurl-n4kq9wxt owner=@khanakia stability=stable
	XTokenURL = "https://api.x.com/2/oauth2/token"
	//ds:def id=xprofileurl-w8tk3xqn owner=@khanakia stability=stable
	XProfileURL = "https://api.x.com/2/users/me?user.fields=profile_image_url,confirmed_email"
)

// X is Sign in with X (Twitter): PKCE with a Basic-authenticated token
// request, scopes users.read, tweet.read, offline.access and users.email,
// profile from /2/users/me. The email is the account's confirmed address,
// so it is verified when present.
//
//ds:def id=x-q5wk8xnt owner=@khanakia stability=stable
func X(clientID, clientSecret string) *OAuth2 {
	return &OAuth2{
		ID: "x", DisplayName: "X", ClientID: clientID, ClientSecret: clientSecret, TokenAuth: ClientSecretBasic,
		AuthURL: XAuthURL, TokenURL: XTokenURL, Scopes: []string{"users.read", "tweet.read", "offline.access", "users.email"},
		FetchProfile: XProfile(XProfileURL),
	}
}

// XProfile reads X's /2/users/me answer from u.
func XProfile(u string) func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
	return profileReader(http.MethodGet, u, nil, func(body json.RawMessage) (Profile, error) {
		var x struct {
			Data struct {
				ID              string `json:"id"`
				Name            string `json:"name"`
				Username        string `json:"username"`
				ProfileImageURL string `json:"profile_image_url"`
				ConfirmedEmail  string `json:"confirmed_email"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &x); err != nil {
			return Profile{}, err
		}
		return Profile{Subject: x.Data.ID, Email: x.Data.ConfirmedEmail, EmailVerified: x.Data.ConfirmedEmail != "", Name: firstOf(x.Data.Name, x.Data.Username), Image: x.Data.ProfileImageURL}, nil
	})
}

// Reddit endpoints.
const (
	//ds:def id=redditauthurl-t3xk7wqn owner=@khanakia stability=stable
	RedditAuthURL = "https://www.reddit.com/api/v1/authorize"
	//ds:def id=reddittokenurl-m8wq4xkt owner=@khanakia stability=stable
	RedditTokenURL = "https://www.reddit.com/api/v1/access_token"
	//ds:def id=redditprofileurl-x2nk9wqt owner=@khanakia stability=stable
	RedditProfileURL = "https://oauth.reddit.com/api/v1/me"
	// headerUserAgent is the header Reddit requires to be set to something
	// that names the app.
	headerUserAgent = "User-Agent"
)

// Reddit is Reddit sign-in: scope identity with a Basic-authenticated token
// request, profile from /api/v1/me. Reddit's API refuses the default Go
// user agent, so userAgent names the app ("web:com.acme.app:v1.0 (by
// /u/acme)" is Reddit's recommended form); it is sent on the profile call.
// Reddit returns no email address.
//
//ds:def id=reddit-w6tq2xkn owner=@khanakia stability=stable
func Reddit(clientID, clientSecret, userAgent string) *OAuth2 {
	return &OAuth2{
		ID: "reddit", DisplayName: "Reddit", ClientID: clientID, ClientSecret: clientSecret, TokenAuth: ClientSecretBasic,
		AuthURL: RedditAuthURL, TokenURL: RedditTokenURL, Scopes: []string{"identity"},
		FetchProfile: RedditProfile(RedditProfileURL, userAgent),
	}
}

// RedditProfile reads Reddit's /api/v1/me answer from u, sending userAgent.
func RedditProfile(u, userAgent string) func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
	return profileReader(http.MethodGet, u, http.Header{headerUserAgent: {userAgent}}, func(body json.RawMessage) (Profile, error) {
		var r struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			IconImg string `json:"icon_img"`
		}
		if err := json.Unmarshal(body, &r); err != nil {
			return Profile{}, err
		}
		// Reddit's icon URL is HTML-escaped in the JSON (&amp;).
		return Profile{Subject: r.ID, Name: r.Name, Image: strings.ReplaceAll(r.IconImg, "&amp;", "&")}, nil
	})
}

// Atlassian endpoints.
const (
	//ds:def id=atlassianauthurl-k4nq8wxt owner=@khanakia stability=stable
	AtlassianAuthURL = "https://auth.atlassian.com/authorize?audience=api.atlassian.com&prompt=consent"
	//ds:def id=atlassiantokenurl-q9xk3wnt owner=@khanakia stability=stable
	AtlassianTokenURL = "https://auth.atlassian.com/oauth/token"
	//ds:def id=atlassianprofileurl-w2tk7xqn owner=@khanakia stability=stable
	AtlassianProfileURL = "https://api.atlassian.com/me"
)

// Atlassian is Atlassian account sign-in (Jira, Confluence): scopes read:me,
// read:account and offline_access, profile from /me, email verified when
// Atlassian says so.
//
//ds:def id=atlassian-n7wq4xkt owner=@khanakia stability=stable
func Atlassian(clientID, clientSecret string) *OAuth2 {
	return &OAuth2{
		ID: "atlassian", DisplayName: "Atlassian", ClientID: clientID, ClientSecret: clientSecret,
		AuthURL: AtlassianAuthURL, TokenURL: AtlassianTokenURL, Scopes: []string{"read:me", "read:account", "offline_access"},
		FetchProfile: AtlassianProfile(AtlassianProfileURL),
	}
}

// AtlassianProfile reads Atlassian's /me answer from u.
func AtlassianProfile(u string) func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
	return profileReader(http.MethodGet, u, nil, func(body json.RawMessage) (Profile, error) {
		var a struct {
			AccountID     string  `json:"account_id"`
			Email         string  `json:"email"`
			EmailVerified boolish `json:"email_verified"`
			Name          string  `json:"name"`
			Picture       string  `json:"picture"`
		}
		if err := json.Unmarshal(body, &a); err != nil {
			return Profile{}, err
		}
		return Profile{Subject: a.AccountID, Email: a.Email, EmailVerified: bool(a.EmailVerified), Name: a.Name, Image: a.Picture}, nil
	})
}

// Zoom endpoints.
const (
	//ds:def id=zoomauthurl-x8kq2wnt owner=@khanakia stability=stable
	ZoomAuthURL = "https://zoom.us/oauth/authorize"
	//ds:def id=zoomtokenurl-t5wn9xkq owner=@khanakia stability=stable
	ZoomTokenURL = "https://zoom.us/oauth/token"
	//ds:def id=zoomprofileurl-m3xk6wqt owner=@khanakia stability=stable
	ZoomProfileURL = "https://api.zoom.us/v2/users/me"
	// zoomVerified is the value of Zoom's numeric verified flag for a
	// verified account.
	zoomVerified = 1
)

// Zoom is Zoom sign-in: a Basic-authenticated token request and the profile
// from /v2/users/me; scopes are set on the app in the Zoom marketplace.
//
//ds:def id=zoom-q4tn7xkw owner=@khanakia stability=stable
func Zoom(clientID, clientSecret string) *OAuth2 {
	return &OAuth2{
		ID: "zoom", DisplayName: "Zoom", ClientID: clientID, ClientSecret: clientSecret, TokenAuth: ClientSecretBasic,
		AuthURL: ZoomAuthURL, TokenURL: ZoomTokenURL,
		FetchProfile: ZoomProfile(ZoomProfileURL),
	}
}

// ZoomProfile reads Zoom's /v2/users/me answer from u.
func ZoomProfile(u string) func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
	return profileReader(http.MethodGet, u, nil, func(body json.RawMessage) (Profile, error) {
		var z struct {
			ID          string `json:"id"`
			Email       string `json:"email"`
			DisplayName string `json:"display_name"`
			FirstName   string `json:"first_name"`
			LastName    string `json:"last_name"`
			PicURL      string `json:"pic_url"`
			Verified    int    `json:"verified"`
		}
		if err := json.Unmarshal(body, &z); err != nil {
			return Profile{}, err
		}
		return Profile{Subject: z.ID, Email: z.Email, EmailVerified: z.Verified == zoomVerified, Name: firstOf(z.DisplayName, strings.TrimSpace(z.FirstName+" "+z.LastName)), Image: z.PicURL}, nil
	})
}

// Figma endpoints.
const (
	//ds:def id=figmaauthurl-w9kn4xqt owner=@khanakia stability=stable
	FigmaAuthURL = "https://www.figma.com/oauth"
	//ds:def id=figmatokenurl-k2xq8wnt owner=@khanakia stability=stable
	FigmaTokenURL = "https://api.figma.com/v1/oauth/token"
	//ds:def id=figmaprofileurl-n6wt3xkq owner=@khanakia stability=stable
	FigmaProfileURL = "https://api.figma.com/v1/me"
)

// Figma is Figma sign-in: scope current_user:read with a Basic-authenticated
// token request, profile from /v1/me; Figma has no verified flag, so the
// email is unverified.
//
//ds:def id=figma-t7xk2wqn owner=@khanakia stability=stable
func Figma(clientID, clientSecret string) *OAuth2 {
	return &OAuth2{
		ID: "figma", DisplayName: "Figma", ClientID: clientID, ClientSecret: clientSecret, TokenAuth: ClientSecretBasic,
		AuthURL: FigmaAuthURL, TokenURL: FigmaTokenURL, Scopes: []string{"current_user:read"},
		FetchProfile: FigmaProfile(FigmaProfileURL),
	}
}

// FigmaProfile reads Figma's /v1/me answer from u.
func FigmaProfile(u string) func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
	return profileReader(http.MethodGet, u, nil, func(body json.RawMessage) (Profile, error) {
		var f struct {
			ID     string `json:"id"`
			Email  string `json:"email"`
			Handle string `json:"handle"`
			ImgURL string `json:"img_url"`
		}
		if err := json.Unmarshal(body, &f); err != nil {
			return Profile{}, err
		}
		return Profile{Subject: f.ID, Email: f.Email, Name: f.Handle, Image: f.ImgURL}, nil
	})
}

// Kakao endpoints.
const (
	//ds:def id=kakaoauthurl-x4wq7knt owner=@khanakia stability=stable
	KakaoAuthURL = "https://kauth.kakao.com/oauth/authorize"
	//ds:def id=kakaotokenurl-m8kn3xqw owner=@khanakia stability=stable
	KakaoTokenURL = "https://kauth.kakao.com/oauth/token"
	//ds:def id=kakaoprofileurl-q2tx9wkn owner=@khanakia stability=stable
	KakaoProfileURL = "https://kapi.kakao.com/v2/user/me"
)

// Kakao is Kakao Login: scopes account_email, profile_image and
// profile_nickname, profile from /v2/user/me, email verified when Kakao
// says so.
//
//ds:def id=kakao-k7nq4xwt owner=@khanakia stability=stable
func Kakao(clientID, clientSecret string) *OAuth2 {
	return &OAuth2{
		ID: "kakao", DisplayName: "Kakao", ClientID: clientID, ClientSecret: clientSecret,
		AuthURL: KakaoAuthURL, TokenURL: KakaoTokenURL, Scopes: []string{"account_email", "profile_image", "profile_nickname"},
		FetchProfile: KakaoProfile(KakaoProfileURL),
	}
}

// KakaoProfile reads Kakao's /v2/user/me answer from u.
func KakaoProfile(u string) func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
	return profileReader(http.MethodGet, u, nil, func(body json.RawMessage) (Profile, error) {
		var k struct {
			ID      json.Number `json:"id"`
			Account struct {
				Email         string  `json:"email"`
				EmailVerified boolish `json:"is_email_verified"`
				Profile       struct {
					Nickname string `json:"nickname"`
					ImageURL string `json:"profile_image_url"`
				} `json:"profile"`
			} `json:"kakao_account"`
		}
		if err := json.Unmarshal(body, &k); err != nil {
			return Profile{}, err
		}
		return Profile{Subject: k.ID.String(), Email: k.Account.Email, EmailVerified: bool(k.Account.EmailVerified), Name: k.Account.Profile.Nickname, Image: k.Account.Profile.ImageURL}, nil
	})
}

// Naver endpoints.
const (
	//ds:def id=naverauthurl-w3kq8xnt owner=@khanakia stability=stable
	NaverAuthURL = "https://nid.naver.com/oauth2.0/authorize"
	//ds:def id=navertokenurl-t9xn2wkq owner=@khanakia stability=stable
	NaverTokenURL = "https://nid.naver.com/oauth2.0/token"
	//ds:def id=naverprofileurl-n5wk7xqt owner=@khanakia stability=stable
	NaverProfileURL = "https://openapi.naver.com/v1/nid/me"
)

// Naver is Naver Login: the profile fields are chosen in the Naver console
// rather than by scope, and come from /v1/nid/me. Naver has no verified
// flag, so the email is unverified.
//
//ds:def id=naver-q6tn3xkw owner=@khanakia stability=stable
func Naver(clientID, clientSecret string) *OAuth2 {
	return &OAuth2{
		ID: "naver", DisplayName: "Naver", ClientID: clientID, ClientSecret: clientSecret,
		AuthURL: NaverAuthURL, TokenURL: NaverTokenURL,
		FetchProfile: NaverProfile(NaverProfileURL),
	}
}

// NaverProfile reads Naver's /v1/nid/me answer from u.
func NaverProfile(u string) func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
	return profileReader(http.MethodGet, u, nil, func(body json.RawMessage) (Profile, error) {
		var n struct {
			Response struct {
				ID           string `json:"id"`
				Email        string `json:"email"`
				Name         string `json:"name"`
				Nickname     string `json:"nickname"`
				ProfileImage string `json:"profile_image"`
			} `json:"response"`
		}
		if err := json.Unmarshal(body, &n); err != nil {
			return Profile{}, err
		}
		r := n.Response
		return Profile{Subject: r.ID, Email: r.Email, Name: firstOf(r.Name, r.Nickname), Image: r.ProfileImage}, nil
	})
}

// Kick endpoints.
const (
	//ds:def id=kickauthurl-k8wn4xqt owner=@khanakia stability=stable
	KickAuthURL = "https://id.kick.com/oauth/authorize"
	//ds:def id=kicktokenurl-x3kq7wnt owner=@khanakia stability=stable
	KickTokenURL = "https://id.kick.com/oauth/token"
	//ds:def id=kickprofileurl-m7tx2wkq owner=@khanakia stability=stable
	KickProfileURL = "https://api.kick.com/public/v1/users"
)

// Kick is Kick sign-in: scope user:read, profile from /public/v1/users;
// Kick has no verified flag, so the email is unverified.
//
//ds:def id=kick-t2nq9xkw owner=@khanakia stability=stable
func Kick(clientID, clientSecret string) *OAuth2 {
	return &OAuth2{
		ID: "kick", DisplayName: "Kick", ClientID: clientID, ClientSecret: clientSecret,
		AuthURL: KickAuthURL, TokenURL: KickTokenURL, Scopes: []string{"user:read"},
		FetchProfile: KickProfile(KickProfileURL),
	}
}

// KickProfile reads Kick's /public/v1/users answer from u.
func KickProfile(u string) func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
	return profileReader(http.MethodGet, u, nil, func(body json.RawMessage) (Profile, error) {
		var k struct {
			Data []struct {
				UserID         json.Number `json:"user_id"`
				Email          string      `json:"email"`
				Name           string      `json:"name"`
				ProfilePicture string      `json:"profile_picture"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &k); err != nil {
			return Profile{}, err
		}
		if len(k.Data) == 0 {
			return Profile{}, nil
		}
		d := k.Data[0]
		return Profile{Subject: d.UserID.String(), Email: d.Email, Name: d.Name, Image: d.ProfilePicture}, nil
	})
}

// Linear endpoints.
const (
	//ds:def id=linearauthurl-w5kq3xnt owner=@khanakia stability=stable
	LinearAuthURL = "https://linear.app/oauth/authorize"
	//ds:def id=lineartokenurl-n8xk7wqt owner=@khanakia stability=stable
	LinearTokenURL = "https://api.linear.app/oauth/token"
	//ds:def id=lineargraphqlurl-q4wn2xkt owner=@khanakia stability=stable
	LinearGraphQLURL = "https://api.linear.app/graphql"
	// linearViewerQuery is the GraphQL query that reads the signed-in user.
	linearViewerQuery = `{"query":"{ viewer { id name email avatarUrl } }"}`
)

// Linear is Linear sign-in: scope read, profile through the GraphQL viewer
// query. Linear accounts are email-verified by Linear, but its API has no
// flag, so the email is unverified here; TrustedProviders("linear") trusts
// it.
//
//ds:def id=linear-x9tk4wqn owner=@khanakia stability=stable
func Linear(clientID, clientSecret string) *OAuth2 {
	return &OAuth2{
		ID: "linear", DisplayName: "Linear", ClientID: clientID, ClientSecret: clientSecret,
		AuthURL: LinearAuthURL, TokenURL: LinearTokenURL, Scopes: []string{"read"},
		FetchProfile: LinearProfile(LinearGraphQLURL),
	}
}

// LinearProfile posts the viewer query to Linear's GraphQL endpoint at u.
func LinearProfile(u string) func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
	return profileReader(http.MethodPost, u, http.Header{headerContentType: {contentTypeJSON}}, func(body json.RawMessage) (Profile, error) {
		var l struct {
			Data struct {
				Viewer struct {
					ID        string `json:"id"`
					Name      string `json:"name"`
					Email     string `json:"email"`
					AvatarURL string `json:"avatarUrl"`
				} `json:"viewer"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &l); err != nil {
			return Profile{}, err
		}
		v := l.Data.Viewer
		return Profile{Subject: v.ID, Email: v.Email, Name: v.Name, Image: v.AvatarURL}, nil
	}, linearViewerQuery)
}

// Cloudflare endpoints.
const (
	//ds:def id=cloudflareauthurl-k3nq8wxt owner=@khanakia stability=stable
	CloudflareAuthURL = "https://dash.cloudflare.com/oauth2/auth"
	//ds:def id=cloudflaretokenurl-t7wk2xqn owner=@khanakia stability=stable
	CloudflareTokenURL = "https://dash.cloudflare.com/oauth2/token"
	//ds:def id=cloudflareprofileurl-m2xq9wkt owner=@khanakia stability=stable
	CloudflareProfileURL = "https://api.cloudflare.com/client/v4/user"
)

// Cloudflare is Cloudflare sign-in: scope user-details.read with a
// Basic-authenticated token request, profile from /client/v4/user. The
// answer has no verified flag, so the email is unverified.
//
//ds:def id=cloudflare-w8tn3xkq owner=@khanakia stability=stable
func Cloudflare(clientID, clientSecret string) *OAuth2 {
	return &OAuth2{
		ID: "cloudflare", DisplayName: "Cloudflare", ClientID: clientID, ClientSecret: clientSecret, TokenAuth: ClientSecretBasic,
		AuthURL: CloudflareAuthURL, TokenURL: CloudflareTokenURL, Scopes: []string{"user-details.read"},
		FetchProfile: CloudflareProfile(CloudflareProfileURL),
	}
}

// CloudflareProfile reads Cloudflare's /client/v4/user answer from u.
func CloudflareProfile(u string) func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
	return profileReader(http.MethodGet, u, nil, func(body json.RawMessage) (Profile, error) {
		var c struct {
			Result struct {
				ID        string `json:"id"`
				Email     string `json:"email"`
				FirstName string `json:"first_name"`
				LastName  string `json:"last_name"`
			} `json:"result"`
		}
		if err := json.Unmarshal(body, &c); err != nil {
			return Profile{}, err
		}
		r := c.Result
		return Profile{Subject: r.ID, Email: r.Email, Name: strings.TrimSpace(r.FirstName + " " + r.LastName)}, nil
	})
}

// PayPal endpoints, live and sandbox.
const (
	//ds:def id=paypalauthurl-q7kn4wxt owner=@khanakia stability=stable
	PayPalAuthURL = "https://www.paypal.com/signin/authorize"
	//ds:def id=paypaltokenurl-x2wq8knt owner=@khanakia stability=stable
	PayPalTokenURL = "https://api-m.paypal.com/v1/oauth2/token"
	//ds:def id=paypalprofileurl-n9tk3xwq owner=@khanakia stability=stable
	PayPalProfileURL = "https://api-m.paypal.com/v1/identity/openidconnect/userinfo?schema=openid"
	//ds:def id=paypalsandboxauthurl-k4xq7wnt owner=@khanakia stability=stable
	PayPalSandboxAuthURL = "https://www.sandbox.paypal.com/signin/authorize"
	//ds:def id=paypalsandboxtokenurl-w6nk2xqt owner=@khanakia stability=stable
	PayPalSandboxTokenURL = "https://api-m.sandbox.paypal.com/v1/oauth2/token"
	//ds:def id=paypalsandboxprofileurl-t3wq9xkn owner=@khanakia stability=stable
	PayPalSandboxProfileURL = "https://api-m.sandbox.paypal.com/v1/identity/openidconnect/userinfo?schema=openid"
	// payPalSubjectClaim is PayPal's user identifier claim in its OpenID
	// userinfo answer.
	payPalSubjectClaim = "user_id"
)

// PayPal is Log in with PayPal: scopes openid, profile and email with a
// Basic-authenticated token request, profile from the OpenID userinfo
// endpoint (subject user_id). sandbox switches the three endpoints to the
// sandbox environment.
//
//ds:def id=paypal-m5kq2xwn owner=@khanakia stability=stable
func PayPal(clientID, clientSecret string, sandbox bool) *OAuth2 {
	o := &OAuth2{
		ID: "paypal", DisplayName: "PayPal", ClientID: clientID, ClientSecret: clientSecret, TokenAuth: ClientSecretBasic,
		AuthURL: PayPalAuthURL, TokenURL: PayPalTokenURL, Scopes: openIDScopes(),
		FetchProfile: UserInfoProfile(PayPalProfileURL, payPalSubjectClaim),
	}
	if sandbox {
		o.AuthURL, o.TokenURL, o.FetchProfile = PayPalSandboxAuthURL, PayPalSandboxTokenURL, UserInfoProfile(PayPalSandboxProfileURL, payPalSubjectClaim)
	}
	return o
}

// Polar endpoints.
const (
	//ds:def id=polarauthurl-x8wk3nqt owner=@khanakia stability=stable
	PolarAuthURL = "https://polar.sh/oauth2/authorize"
	//ds:def id=polartokenurl-k2tq7wxn owner=@khanakia stability=stable
	PolarTokenURL = "https://api.polar.sh/v1/oauth2/token"
	//ds:def id=polarprofileurl-n6xk9wqt owner=@khanakia stability=stable
	PolarProfileURL = "https://api.polar.sh/v1/oauth2/userinfo"
)

// Polar is Polar sign-in: scopes openid, profile and email, profile from
// the OpenID-shaped userinfo endpoint.
//
//ds:def id=polar-w4nq8xkt owner=@khanakia stability=stable
func Polar(clientID, clientSecret string) *OAuth2 {
	return &OAuth2{
		ID: "polar", DisplayName: "Polar", ClientID: clientID, ClientSecret: clientSecret,
		AuthURL: PolarAuthURL, TokenURL: PolarTokenURL, Scopes: openIDScopes(),
		FetchProfile: UserInfoProfile(PolarProfileURL, ""),
	}
}

// Vercel endpoints.
const (
	//ds:def id=vercelauthurl-t9kq4wxn owner=@khanakia stability=stable
	VercelAuthURL = "https://vercel.com/oauth/authorize"
	//ds:def id=verceltokenurl-q3xn8wkt owner=@khanakia stability=stable
	VercelTokenURL = "https://api.vercel.com/login/oauth/token"
	//ds:def id=vercelprofileurl-m7wq2xkn owner=@khanakia stability=stable
	VercelProfileURL = "https://api.vercel.com/login/oauth/userinfo"
)

// Vercel is Sign in with Vercel: scopes openid, profile and email, profile
// from the OpenID-shaped userinfo endpoint.
//
//ds:def id=vercel-k6tn3xwq owner=@khanakia stability=stable
func Vercel(clientID, clientSecret string) *OAuth2 {
	return &OAuth2{
		ID: "vercel", DisplayName: "Vercel", ClientID: clientID, ClientSecret: clientSecret,
		AuthURL: VercelAuthURL, TokenURL: VercelTokenURL, Scopes: openIDScopes(),
		FetchProfile: UserInfoProfile(VercelProfileURL, ""),
	}
}

// Patreon endpoints.
const (
	//ds:def id=patreonauthurl-w2kq9xnt owner=@khanakia stability=stable
	PatreonAuthURL = "https://www.patreon.com/oauth2/authorize"
	//ds:def id=patreontokenurl-x7nk4wqt owner=@khanakia stability=stable
	PatreonTokenURL = "https://www.patreon.com/api/oauth2/token"
	//ds:def id=patreonprofileurl-n3wq8xkt owner=@khanakia stability=stable
	PatreonProfileURL = "https://www.patreon.com/api/oauth2/v2/identity?fields%5Buser%5D=email,full_name,image_url,is_email_verified"
)

// Patreon is Patreon sign-in: scopes identity and identity[email], profile
// from the v2 identity endpoint, email verified when Patreon says so.
//
//ds:def id=patreon-q8xk2wnt owner=@khanakia stability=stable
func Patreon(clientID, clientSecret string) *OAuth2 {
	return &OAuth2{
		ID: "patreon", DisplayName: "Patreon", ClientID: clientID, ClientSecret: clientSecret,
		AuthURL: PatreonAuthURL, TokenURL: PatreonTokenURL, Scopes: []string{"identity", "identity[email]"},
		FetchProfile: PatreonProfile(PatreonProfileURL),
	}
}

// PatreonProfile reads Patreon's identity answer from u.
func PatreonProfile(u string) func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
	return profileReader(http.MethodGet, u, nil, func(body json.RawMessage) (Profile, error) {
		var p struct {
			Data struct {
				ID         string `json:"id"`
				Attributes struct {
					Email           string  `json:"email"`
					FullName        string  `json:"full_name"`
					ImageURL        string  `json:"image_url"`
					IsEmailVerified boolish `json:"is_email_verified"`
				} `json:"attributes"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &p); err != nil {
			return Profile{}, err
		}
		a := p.Data.Attributes
		return Profile{Subject: p.Data.ID, Email: a.Email, EmailVerified: bool(a.IsEmailVerified), Name: a.FullName, Image: a.ImageURL}, nil
	})
}

// Gumroad endpoints.
const (
	//ds:def id=gumroadauthurl-k9wn3xqt owner=@khanakia stability=stable
	GumroadAuthURL = "https://gumroad.com/oauth/authorize"
	//ds:def id=gumroadtokenurl-t4kq8wxn owner=@khanakia stability=stable
	GumroadTokenURL = "https://api.gumroad.com/oauth/token"
	//ds:def id=gumroadprofileurl-m8xq2wkt owner=@khanakia stability=stable
	GumroadProfileURL = "https://api.gumroad.com/v2/user"
)

// Gumroad is Gumroad sign-in: scope view_profile, profile from /v2/user;
// Gumroad has no verified flag, so the email is unverified.
//
//ds:def id=gumroad-x3tn7wkq owner=@khanakia stability=stable
func Gumroad(clientID, clientSecret string) *OAuth2 {
	return &OAuth2{
		ID: "gumroad", DisplayName: "Gumroad", ClientID: clientID, ClientSecret: clientSecret,
		AuthURL: GumroadAuthURL, TokenURL: GumroadTokenURL, Scopes: []string{"view_profile"},
		FetchProfile: GumroadProfile(GumroadProfileURL),
	}
}

// GumroadProfile reads Gumroad's /v2/user answer from u.
func GumroadProfile(u string) func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
	return profileReader(http.MethodGet, u, nil, func(body json.RawMessage) (Profile, error) {
		var g struct {
			User struct {
				UserID string `json:"user_id"`
				Email  string `json:"email"`
				Name   string `json:"name"`
			} `json:"user"`
		}
		if err := json.Unmarshal(body, &g); err != nil {
			return Profile{}, err
		}
		return Profile{Subject: g.User.UserID, Email: g.User.Email, Name: g.User.Name}, nil
	})
}

// HubSpot endpoints.
const (
	//ds:def id=hubspotauthurl-w7xk4nqt owner=@khanakia stability=stable
	HubSpotAuthURL = "https://app.hubspot.com/oauth/authorize"
	//ds:def id=hubspottokenurl-n2kq9wxt owner=@khanakia stability=stable
	HubSpotTokenURL = "https://api.hubapi.com/oauth/v1/token"
	// HubSpotTokenInfoURL is the endpoint that describes an access token,
	// the token itself appended; it is the only place HubSpot tells who the
	// token belongs to.
	//ds:def id=hubspottokeninfourl-q6wn3xkt owner=@khanakia stability=stable
	HubSpotTokenInfoURL = "https://api.hubapi.com/oauth/v1/access-tokens/"
)

// HubSpot is HubSpot sign-in: scope oauth, identity from the access-token
// introspection endpoint (user id and email; HubSpot has no name or
// picture there). The email is unverified: HubSpot does not say.
//
//ds:def id=hubspot-t5wq8xkn owner=@khanakia stability=stable
func HubSpot(clientID, clientSecret string) *OAuth2 {
	return &OAuth2{
		ID: "hubspot", DisplayName: "HubSpot", ClientID: clientID, ClientSecret: clientSecret,
		AuthURL: HubSpotAuthURL, TokenURL: HubSpotTokenURL, Scopes: []string{"oauth"},
		FetchProfile: HubSpotProfile(HubSpotTokenInfoURL),
	}
}

// HubSpotProfile reads HubSpot's access-token description at base + token.
func HubSpotProfile(base string) func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
	return func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
		read := profileReader(http.MethodGet, base+url.PathEscape(accessToken), nil, func(body json.RawMessage) (Profile, error) {
			var h struct {
				UserID json.Number `json:"user_id"`
				User   string      `json:"user"`
			}
			if err := json.Unmarshal(body, &h); err != nil {
				return Profile{}, err
			}
			return Profile{Subject: h.UserID.String(), Email: h.User}, nil
		})
		return read(ctx, hc, accessToken)
	}
}

// Yandex endpoints.
const (
	//ds:def id=yandexauthurl-k4nq7wxt owner=@khanakia stability=stable
	YandexAuthURL = "https://oauth.yandex.ru/authorize"
	//ds:def id=yandextokenurl-x9wk3nqt owner=@khanakia stability=stable
	YandexTokenURL = "https://oauth.yandex.ru/token"
	//ds:def id=yandexprofileurl-m3tq8wkn owner=@khanakia stability=stable
	YandexProfileURL = "https://login.yandex.ru/info?format=json"
	// yandexAvatarFormat builds the avatar URL from default_avatar_id.
	yandexAvatarFormat = "https://avatars.yandex.net/get-yapic/%s/islands-200"
	// yandexAuthScheme is the Authorization scheme Yandex's info endpoint
	// takes instead of Bearer.
	yandexAuthScheme = "OAuth "
)

// Yandex is Yandex ID sign-in: scopes login:info, login:email and
// login:avatar, profile from login.yandex.ru/info with the OAuth
// authorization scheme. Yandex has no verified flag, so the email is
// unverified.
//
//ds:def id=yandex-w8kq2xnt owner=@khanakia stability=stable
func Yandex(clientID, clientSecret string) *OAuth2 {
	return &OAuth2{
		ID: "yandex", DisplayName: "Yandex", ClientID: clientID, ClientSecret: clientSecret,
		AuthURL: YandexAuthURL, TokenURL: YandexTokenURL, Scopes: []string{"login:info", "login:email", "login:avatar"},
		FetchProfile: YandexProfile(YandexProfileURL),
	}
}

// YandexProfile reads Yandex's info answer from u.
func YandexProfile(u string) func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
	return func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
		hdr := http.Header{headerAuthorization: {yandexAuthScheme + accessToken}}
		read := profileReaderWithAuth(http.MethodGet, u, hdr, false, func(body json.RawMessage) (Profile, error) {
			var y struct {
				ID              string   `json:"id"`
				DefaultEmail    string   `json:"default_email"`
				Emails          []string `json:"emails"`
				RealName        string   `json:"real_name"`
				DisplayName     string   `json:"display_name"`
				DefaultAvatarID string   `json:"default_avatar_id"`
				IsAvatarEmpty   bool     `json:"is_avatar_empty"`
			}
			if err := json.Unmarshal(body, &y); err != nil {
				return Profile{}, err
			}
			email := y.DefaultEmail
			if email == "" && len(y.Emails) > 0 {
				email = y.Emails[0]
			}
			p := Profile{Subject: y.ID, Email: email, Name: firstOf(y.RealName, y.DisplayName)}
			if y.DefaultAvatarID != "" && !y.IsAvatarEmpty {
				p.Image = fmt.Sprintf(yandexAvatarFormat, y.DefaultAvatarID)
			}
			return p, nil
		}, "")
		return read(ctx, hc, accessToken)
	}
}

// firstOf returns the first non-empty string.
func firstOf(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// profileReader builds a FetchProfile that calls u with the bearer access
// token and the given headers (method GET or POST, with body for a POST),
// then parses the answer with parse. The raw answer becomes Profile.Claims.
// A parse error is wrapped in ErrExchange, like every provider failure.
func profileReader(method, u string, hdr http.Header, parse func(json.RawMessage) (Profile, error), body ...string) func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
	return profileReaderWithAuth(method, u, hdr, true, parse, body...)
}

// profileReaderWithAuth is profileReader with the bearer header optional,
// for a provider whose authorization scheme is not Bearer (Yandex).
func profileReaderWithAuth(method, u string, hdr http.Header, bearer bool, parse func(json.RawMessage) (Profile, error), body ...string) func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
	return func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
		var rd io.Reader
		if len(body) > 0 && body[0] != "" {
			rd = strings.NewReader(body[0])
		}
		req, err := http.NewRequestWithContext(ctx, method, u, rd)
		if err != nil {
			return Profile{}, fmt.Errorf("%w: request %v", ErrExchange, err)
		}
		if bearer {
			req.Header.Set(headerAuthorization, bearerPrefix+accessToken)
		}
		req.Header.Set(headerAccept, contentTypeJSON)
		for k, vs := range hdr {
			req.Header[k] = vs
		}
		raw, err := fetchJSON(hc, req)
		if err != nil {
			return Profile{}, err
		}
		p, err := parse(raw)
		if err != nil {
			return Profile{}, fmt.Errorf("%w: %v", ErrExchange, err)
		}
		p.Claims = claimsOf(raw)
		return p, nil
	}
}

// Presets lists every provider constructor's route segment, for
// documentation and for a test that keeps the README's table complete.
//
//ds:def id=presets-j4wk8xqn owner=@khanakia stability=stable
var Presets = []string{
	"google", "github", "apple", "microsoft", "discord", "facebook", "slack", "linkedin", "gitlab", "twitch", "line",
	"huggingface", "roblox", "salesforce", "auth0", "okta", "keycloak", "zitadel", "cognito", "spotify", "dropbox",
	"x", "reddit", "atlassian", "zoom", "figma", "kakao", "naver", "kick", "linear", "cloudflare", "paypal", "polar",
	"vercel", "patreon", "gumroad", "hubspot", "yandex", "paybin", "railway", "tiktok", "notion", "vk", "wechat",
	"dub", "instagram", "snapchat", "zoho",
}
