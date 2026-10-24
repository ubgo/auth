package oauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ubgo/auth"
)

// recordingAPI serves one JSON answer and records the request it received.
type recordingAPI struct {
	answer string
	method string
	header http.Header
	path   string
	body   string
}

func (r *recordingAPI) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		r.method, r.header, r.path, r.body = req.Method, req.Header.Clone(), req.URL.RequestURI(), string(b)
		w.Header().Set(headerContentType, contentTypeJSON)
		_, _ = w.Write([]byte(r.answer))
	}
}

type profileFn = func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error)

func TestPresets_ProfileReaders(t *testing.T) {
	cases := []struct {
		name   string
		reader func(u string) profileFn
		answer string
		want   Profile
		method string
		check  func(t *testing.T, r *recordingAPI)
	}{
		{name: "discord", reader: DiscordProfile, method: http.MethodGet,
			answer: `{"id":"1","username":"ann","global_name":"Ann","email":"a@b.co","verified":true,"avatar":"abc"}`,
			want:   Profile{Subject: "1", Email: "a@b.co", EmailVerified: true, Name: "Ann", Image: "https://cdn.discordapp.com/avatars/1/abc.png"}},
		{name: "discord no avatar", reader: DiscordProfile, method: http.MethodGet,
			answer: `{"id":"1","username":"ann","email":"a@b.co","verified":false,"avatar":null}`,
			want:   Profile{Subject: "1", Email: "a@b.co", Name: "ann"}},
		{name: "facebook", reader: FacebookProfile, method: http.MethodGet,
			answer: `{"id":"7","name":"Ann","email":"a@b.co","picture":{"data":{"url":"https://img/a"}}}`,
			want:   Profile{Subject: "7", Email: "a@b.co", Name: "Ann", Image: "https://img/a"}},
		{name: "spotify", reader: SpotifyProfile, method: http.MethodGet,
			answer: `{"id":"s1","email":"a@b.co","display_name":"Ann","images":[{"url":"https://img/a"},{"url":"https://img/b"}]}`,
			want:   Profile{Subject: "s1", Email: "a@b.co", Name: "Ann", Image: "https://img/a"}},
		{name: "spotify no image", reader: SpotifyProfile, method: http.MethodGet,
			answer: `{"id":"s1","images":[]}`, want: Profile{Subject: "s1"}},
		{name: "dropbox", reader: DropboxProfile, method: http.MethodPost,
			answer: `{"account_id":"dbid:1","email":"a@b.co","email_verified":true,"name":{"display_name":"Ann"},"profile_photo_url":"https://img/a"}`,
			want:   Profile{Subject: "dbid:1", Email: "a@b.co", EmailVerified: true, Name: "Ann", Image: "https://img/a"}},
		{name: "x", reader: XProfile, method: http.MethodGet,
			answer: `{"data":{"id":"x1","name":"Ann","username":"ann","profile_image_url":"https://img/a","confirmed_email":"a@b.co"}}`,
			want:   Profile{Subject: "x1", Email: "a@b.co", EmailVerified: true, Name: "Ann", Image: "https://img/a"}},
		{name: "x no email", reader: XProfile, method: http.MethodGet,
			answer: `{"data":{"id":"x1","username":"ann"}}`, want: Profile{Subject: "x1", Name: "ann"}},
		{name: "reddit", reader: func(u string) profileFn { return RedditProfile(u, "test-agent") }, method: http.MethodGet,
			answer: `{"id":"r1","name":"ann","icon_img":"https://img/a?x=1&amp;y=2"}`,
			want:   Profile{Subject: "r1", Name: "ann", Image: "https://img/a?x=1&y=2"},
			check: func(t *testing.T, r *recordingAPI) {
				if r.header.Get(headerUserAgent) != "test-agent" {
					t.Fatalf("user agent = %q", r.header.Get(headerUserAgent))
				}
			}},
		{name: "atlassian", reader: AtlassianProfile, method: http.MethodGet,
			answer: `{"account_id":"at1","email":"a@b.co","email_verified":true,"name":"Ann","picture":"https://img/a"}`,
			want:   Profile{Subject: "at1", Email: "a@b.co", EmailVerified: true, Name: "Ann", Image: "https://img/a"}},
		{name: "zoom", reader: ZoomProfile, method: http.MethodGet,
			answer: `{"id":"z1","email":"a@b.co","first_name":"Ann","last_name":"Lee","pic_url":"https://img/a","verified":1}`,
			want:   Profile{Subject: "z1", Email: "a@b.co", EmailVerified: true, Name: "Ann Lee", Image: "https://img/a"}},
		{name: "zoom unverified display name", reader: ZoomProfile, method: http.MethodGet,
			answer: `{"id":"z1","email":"a@b.co","display_name":"Ann L","verified":0}`,
			want:   Profile{Subject: "z1", Email: "a@b.co", Name: "Ann L"}},
		{name: "figma", reader: FigmaProfile, method: http.MethodGet,
			answer: `{"id":"f1","email":"a@b.co","handle":"ann","img_url":"https://img/a"}`,
			want:   Profile{Subject: "f1", Email: "a@b.co", Name: "ann", Image: "https://img/a"}},
		{name: "kakao", reader: KakaoProfile, method: http.MethodGet,
			answer: `{"id":12345,"kakao_account":{"email":"a@b.co","is_email_verified":true,"profile":{"nickname":"Ann","profile_image_url":"https://img/a"}}}`,
			want:   Profile{Subject: "12345", Email: "a@b.co", EmailVerified: true, Name: "Ann", Image: "https://img/a"}},
		{name: "naver", reader: NaverProfile, method: http.MethodGet,
			answer: `{"resultcode":"00","response":{"id":"n1","email":"a@b.co","nickname":"annie","profile_image":"https://img/a"}}`,
			want:   Profile{Subject: "n1", Email: "a@b.co", Name: "annie", Image: "https://img/a"}},
		{name: "kick", reader: KickProfile, method: http.MethodGet,
			answer: `{"data":[{"user_id":42,"email":"a@b.co","name":"ann","profile_picture":"https://img/a"}]}`,
			want:   Profile{Subject: "42", Email: "a@b.co", Name: "ann", Image: "https://img/a"}},
		{name: "kick empty", reader: KickProfile, method: http.MethodGet, answer: `{"data":[]}`, want: Profile{}},
		{name: "linear", reader: LinearProfile, method: http.MethodPost,
			answer: `{"data":{"viewer":{"id":"l1","name":"Ann","email":"a@b.co","avatarUrl":"https://img/a"}}}`,
			want:   Profile{Subject: "l1", Email: "a@b.co", Name: "Ann", Image: "https://img/a"},
			check: func(t *testing.T, r *recordingAPI) {
				if r.body != linearViewerQuery || r.header.Get(headerContentType) != contentTypeJSON {
					t.Fatalf("linear request body %q type %q", r.body, r.header.Get(headerContentType))
				}
			}},
		{name: "cloudflare", reader: CloudflareProfile, method: http.MethodGet,
			answer: `{"result":{"id":"c1","email":"a@b.co","first_name":"Ann","last_name":"Lee"},"success":true}`,
			want:   Profile{Subject: "c1", Email: "a@b.co", Name: "Ann Lee"}},
		{name: "patreon", reader: PatreonProfile, method: http.MethodGet,
			answer: `{"data":{"id":"p1","attributes":{"email":"a@b.co","full_name":"Ann","image_url":"https://img/a","is_email_verified":true}}}`,
			want:   Profile{Subject: "p1", Email: "a@b.co", EmailVerified: true, Name: "Ann", Image: "https://img/a"}},
		{name: "gumroad", reader: GumroadProfile, method: http.MethodGet,
			answer: `{"success":true,"user":{"user_id":"g1","email":"a@b.co","name":"Ann"}}`,
			want:   Profile{Subject: "g1", Email: "a@b.co", Name: "Ann"}},
		{name: "hubspot", reader: func(u string) profileFn { return HubSpotProfile(u + "/") }, method: http.MethodGet,
			answer: `{"user_id":99,"user":"a@b.co","hub_id":1}`,
			want:   Profile{Subject: "99", Email: "a@b.co"},
			check: func(t *testing.T, r *recordingAPI) {
				if !strings.HasSuffix(r.path, "/at") {
					t.Fatalf("hubspot path = %q, want the token appended", r.path)
				}
			}},
		{name: "yandex", reader: YandexProfile, method: http.MethodGet,
			answer: `{"id":"y1","default_email":"a@b.co","real_name":"Ann","default_avatar_id":"av1","is_avatar_empty":false}`,
			want:   Profile{Subject: "y1", Email: "a@b.co", Name: "Ann", Image: "https://avatars.yandex.net/get-yapic/av1/islands-200"},
			check: func(t *testing.T, r *recordingAPI) {
				if r.header.Get(headerAuthorization) != "OAuth at" {
					t.Fatalf("yandex authorization = %q", r.header.Get(headerAuthorization))
				}
			}},
		{name: "yandex fallbacks", reader: YandexProfile, method: http.MethodGet,
			answer: `{"id":"y1","emails":["b@b.co"],"display_name":"annie","default_avatar_id":"0/0-0","is_avatar_empty":true}`,
			want:   Profile{Subject: "y1", Email: "b@b.co", Name: "annie"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			api := &recordingAPI{answer: c.answer}
			srv := providerServer(t, map[string]http.HandlerFunc{"/": api.handler()})
			got, err := c.reader(srv.URL+"/me")(context.Background(), srv.Client(), "at")
			if err != nil {
				t.Fatal(err)
			}
			if got.Claims == nil {
				t.Fatal("no raw claims")
			}
			got.Claims = nil
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("profile = %+v, want %+v", got, c.want)
			}
			if api.method != c.method {
				t.Fatalf("method = %s, want %s", api.method, c.method)
			}
			if c.name != "yandex" && c.name != "yandex fallbacks" && api.header.Get(headerAuthorization) != bearerPrefix+"at" {
				t.Fatalf("authorization = %q", api.header.Get(headerAuthorization))
			}
			if c.check != nil {
				c.check(t, api)
			}
			// A body that is not the provider's shape is ErrExchange, and so is
			// a provider that is down or answering an error.
			down := providerServer(t, map[string]http.HandlerFunc{"/": answer(http.StatusServiceUnavailable, "")})
			if _, err := c.reader(down.URL+"/me")(context.Background(), down.Client(), "at"); !errors.Is(err, ErrExchange) {
				t.Fatalf("503: %v", err)
			}
			api.answer = `[1]`
			if _, err := c.reader(srv.URL+"/me")(context.Background(), srv.Client(), "at"); !errors.Is(err, ErrExchange) {
				t.Fatalf("array answer: %v", err)
			}
			if _, err := c.reader("http://[::1")(context.Background(), srv.Client(), "at"); !errors.Is(err, ErrExchange) {
				t.Fatalf("bad URL: %v", err)
			}
		})
	}
}

func TestPresets_Constructors(t *testing.T) {
	oauth2s := map[string]*OAuth2{
		"microsoft":  Microsoft("tenant-1", "id", "s"),
		"discord":    Discord("id", "s"),
		"facebook":   Facebook("id", "s"),
		"spotify":    Spotify("id", "s"),
		"dropbox":    Dropbox("id", "s"),
		"x":          X("id", "s"),
		"reddit":     Reddit("id", "s", "ua"),
		"atlassian":  Atlassian("id", "s"),
		"zoom":       Zoom("id", "s"),
		"figma":      Figma("id", "s"),
		"kakao":      Kakao("id", "s"),
		"naver":      Naver("id", "s"),
		"kick":       Kick("id", "s"),
		"linear":     Linear("id", "s"),
		"cloudflare": Cloudflare("id", "s"),
		"paypal":     PayPal("id", "s", false),
		"polar":      Polar("id", "s"),
		"vercel":     Vercel("id", "s"),
		"patreon":    Patreon("id", "s"),
		"gumroad":    Gumroad("id", "s"),
		"hubspot":    HubSpot("id", "s"),
		"yandex":     Yandex("id", "s"),
		"tiktok":     TikTok("id", "s"),
		"notion":     Notion("id", "s"),
		"vk":         VK("id", "s"),
		"wechat":     WeChat("id", "s", ""),
		"dub":        Dub("id", "s"),
		"instagram":  Instagram("id", "s"),
		"snapchat":   Snapchat("id", "s"),
		"google":     Google("id", "s"),
		"github":     GitHub("id", "s"),
		"apple":      Apple("id", func(context.Context) (string, error) { return "s", nil }),
	}
	oidcs := map[string]*OIDCProvider{
		"slack":       Slack("id", "s"),
		"linkedin":    LinkedIn("id", "s"),
		"gitlab":      GitLab(GitLabIssuer, "id", "s"),
		"twitch":      Twitch("id", "s"),
		"line":        LINE("id", "s"),
		"huggingface": HuggingFace("id", "s"),
		"roblox":      Roblox("id", "s"),
		"salesforce":  Salesforce(SalesforceSandboxIssuer, "id", "s"),
		"auth0":       Auth0("acme.us.auth0.com/", "id", "s"),
		"okta":        Okta("https://acme.okta.com", "id", "s"),
		"keycloak":    Keycloak("https://kc.example/realms/r", "id", "s"),
		"zitadel":     Zitadel("https://z.example", "id", "s"),
		"cognito":     Cognito("eu-west-1", "eu-west-1_abc", "id", "s"),
		"paybin":      Paybin("id", "s"),
		"railway":     Railway("id", "s"),
		"zoho":        Zoho(ZohoEU, "id", "s"),
	}
	// Every preset is listed, every listed preset exists, and each one
	// passes auth.New's validation with its route segment as its name.
	var names []string
	for name, o := range oauth2s {
		if o.ID != name {
			t.Errorf("%s: id %q", name, o.ID)
		}
		names = append(names, name)
		if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(New(WithProviders(o)))); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, o := range oidcs {
		if o.ID != name || !strings.HasPrefix(o.Issuer, httpsPrefix) || strings.HasSuffix(o.Issuer, "/") {
			t.Errorf("%s: id %q issuer %q", name, o.ID, o.Issuer)
		}
		names = append(names, name)
		if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(New(WithProviders(o)))); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Every preset has a display name for its button, which is not its id.
	for name, o := range oauth2s {
		if o.DisplayName == "" || o.Label() != o.DisplayName || o.DisplayName == o.ID {
			t.Errorf("%s: display name %q", name, o.DisplayName)
		}
	}
	for name, o := range oidcs {
		if o.DisplayName == "" || o.Label() != o.DisplayName || o.DisplayName == o.ID {
			t.Errorf("%s: display name %q", name, o.DisplayName)
		}
	}
	slices.Sort(names)
	listed := slices.Clone(Presets)
	slices.Sort(listed)
	if !slices.Equal(names, listed) {
		t.Fatalf("Presets = %v, constructors = %v", listed, names)
	}

	// Token-endpoint authentication per provider.
	for _, name := range []string{"x", "reddit", "zoom", "figma", "cloudflare", "paypal"} {
		if oauth2s[name].TokenAuth != ClientSecretBasic {
			t.Errorf("%s should authenticate with Basic", name)
		}
	}
	for _, name := range []string{"discord", "facebook", "spotify", "microsoft", "google"} {
		if oauth2s[name].TokenAuth != "" {
			t.Errorf("%s should post the secret", name)
		}
	}
	// Microsoft: oid as subject, ID tokens for a single tenant only.
	if oauth2s["microsoft"].IDToken.JWKSURL != "https://login.microsoftonline.com/tenant-1/discovery/v2.0/keys" || oauth2s["microsoft"].IDToken.Issuers[0] != "https://login.microsoftonline.com/tenant-1/v2.0" {
		t.Fatalf("microsoft id tokens = %+v", oauth2s["microsoft"].IDToken)
	}
	for _, alias := range []string{"common", "Organizations", "consumers"} {
		if Microsoft(alias, "id", "s").IDToken.Enabled() {
			t.Fatalf("%s tenant accepts ID tokens", alias)
		}
	}
	// Twitch asks for the userinfo claims and the email scope; Roblox has no
	// email scope; the Auth0 domain gets its scheme; Cognito's issuer.
	if u, _ := url.Parse("https://x/?" + url.Values{paramClaims: oidcs["twitch"].AuthParams[paramClaims]}.Encode()); u.Query().Get(paramClaims) != twitchClaims || !slices.Contains(oidcs["twitch"].Scopes, twitchEmailScope) {
		t.Fatalf("twitch = %+v", oidcs["twitch"])
	}
	if slices.Contains(oidcs["roblox"].Scopes, "email") {
		t.Fatal("roblox requests an email scope it does not have")
	}
	if oidcs["auth0"].Issuer != "https://acme.us.auth0.com" || Auth0("https://acme.eu.auth0.com", "id", "s").Issuer != "https://acme.eu.auth0.com" {
		t.Fatalf("auth0 issuer = %q", oidcs["auth0"].Issuer)
	}
	if oidcs["cognito"].Issuer != "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_abc" {
		t.Fatalf("cognito issuer = %q", oidcs["cognito"].Issuer)
	}
	// PayPal sandbox switches the three endpoints.
	sb := PayPal("id", "s", true)
	if sb.AuthURL != PayPalSandboxAuthURL || sb.TokenURL != PayPalSandboxTokenURL || sb.FetchProfile == nil {
		t.Fatalf("paypal sandbox = %+v", sb)
	}
	// The OpenID-shaped profiles read user_id (PayPal) or sub (Polar,
	// Vercel) as the subject, and Twitch's preferred_username stands in for
	// a missing name.
	srv := providerServer(t, map[string]http.HandlerFunc{
		"/paypal": answer(http.StatusOK, `{"user_id":"https://www.paypal.com/webapps/auth/identity/user/abc","email":"a@b.co","email_verified":true,"name":"Ann"}`),
		"/polar":  answer(http.StatusOK, `{"sub":"p1","email":"a@b.co","email_verified":"true","preferred_username":"ann"}`),
	})
	pp, err := UserInfoProfile(srv.URL+"/paypal", payPalSubjectClaim)(context.Background(), srv.Client(), "at")
	if err != nil || pp.Subject != "https://www.paypal.com/webapps/auth/identity/user/abc" || !pp.EmailVerified {
		t.Fatalf("paypal = %+v %v", pp, err)
	}
	pl, err := UserInfoProfile(srv.URL+"/polar", "")(context.Background(), srv.Client(), "at")
	if err != nil || pl.Subject != "p1" || pl.Name != "ann" || !pl.EmailVerified {
		t.Fatalf("polar = %+v %v", pl, err)
	}
	if firstOf("", "", "") != "" || withHTTPS("x.example/") != "https://x.example" {
		t.Fatal("helpers")
	}
}
