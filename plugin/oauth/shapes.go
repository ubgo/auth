package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/ubgo/auth"
)

// This file holds the provider shapes that are not RFC 6749 on the wire
// (round 6, 2026-10-06): the callback values a token request may carry, the
// presets for TikTok, Notion, VK ID and WeChat, and the Microsoft Graph
// photo. Each preset follows the provider's own documentation, read on
// 2026-10-06 (TikTok's from the Internet Archive's copies of
// developers.tiktok.com, which answered 503 directly), and better-auth
// v1.7.7's source; the parsers and requests are pinned by fixture tests.

// ErrPublicClientPKCE is a configuration error: NoPKCE on a provider with
// TokenAuth PublicClient. With no secret and no PKCE, anyone holding the
// code could redeem it.
var ErrPublicClientPKCE = errors.New("oauth: NoPKCE needs a client secret; a public client has nothing else tying the code to it")

// ErrCallbackParam is a configuration error: a CallbackParams entry that is
// not one of CallbackParamValues.
var ErrCallbackParam = errors.New("oauth: unknown callback parameter")

// CallbackParam names a callback query parameter a provider's token request
// carries as well (OAuth2.CallbackParams). A closed set: the plugin forwards
// only values it decoded and checked itself.
type CallbackParam string

const (
	// CallbackParamState forwards the callback's state, which VK ID's token
	// request requires. The state is spent by then; sending it back to the
	// provider that issued it reveals nothing.
	CallbackParamState CallbackParam = "state"
	// CallbackParamDeviceID forwards VK ID's device_id.
	CallbackParamDeviceID CallbackParam = "device_id"
)

// CallbackParamValues is every CallbackParam, for validation.
var CallbackParamValues = []CallbackParam{CallbackParamState, CallbackParamDeviceID}

// CallbackValues are the callback's values a token request may need beyond
// the code: what VK ID's exchange requires. The callback puts them in the
// exchange's context; a Provider of the app's own reads them with
// CallbackValuesOf (better-auth hands deviceId to validateAuthorizationCode).
type CallbackValues struct {
	State    string
	DeviceID string
}

// value returns the value named by p.
func (v CallbackValues) value(p CallbackParam) string {
	switch p {
	case CallbackParamState:
		return v.State
	case CallbackParamDeviceID:
		return v.DeviceID
	}
	return ""
}

// callbackValuesKey carries CallbackValues in a context.
type callbackValuesKey struct{}

// WithCallbackValues returns ctx carrying v, for the exchange the callback
// runs; a test or a flow outside this plugin (authgate) sets it the same way.
func WithCallbackValues(ctx context.Context, v CallbackValues) context.Context {
	return context.WithValue(ctx, callbackValuesKey{}, v)
}

// CallbackValuesOf returns the callback values in ctx, zero outside a
// callback's exchange.
func CallbackValuesOf(ctx context.Context) CallbackValues {
	v, _ := ctx.Value(callbackValuesKey{}).(CallbackValues)
	return v
}

// TikTok endpoints (Login Kit for Web; developers.tiktok.com/doc/login-kit-web,
// oauth-user-access-token-management, tiktok-api-v2-get-user-info).
const (
	//ds:def id=tiktokauthurl-r6kq2wxn owner=@khanakia stability=stable
	TikTokAuthURL = "https://www.tiktok.com/v2/auth/authorize/"
	//ds:def id=tiktoktokenurl-m3xw8kqt owner=@khanakia stability=stable
	TikTokTokenURL = "https://open.tiktokapis.com/v2/oauth/token/"
	//ds:def id=tiktokrevokeurl-h7nq4xwk owner=@khanakia stability=stable
	TikTokRevokeURL = "https://open.tiktokapis.com/v2/oauth/revoke/"
	// TikTokUserInfoURL asks for the user.info.basic fields only: open_id
	// (the subject), union_id, the large avatar and the display name.
	// TikTok has no email.
	//ds:def id=tiktokuserinfourl-t2wk9xqm owner=@khanakia stability=stable
	TikTokUserInfoURL = "https://open.tiktokapis.com/v2/user/info/?fields=open_id,union_id,avatar_large_url,display_name"
	// tiktokClientKeyParam is TikTok's name for client_id (better-auth's
	// clientKey).
	tiktokClientKeyParam = "client_key"
	// commaScopes joins scopes the way TikTok and WeChat read them.
	commaScopes = ","
)

// TikTok is Login Kit for Web. clientKey is the app's client key, TikTok's
// name for the client id (better-auth's clientKey), sent as client_key on
// the authorization URL and in the token, refresh and revocation forms.
// Scope user.info.basic, comma-joined; the subject is open_id; TikTok has no
// email, so the user is created with no identity. PKCE is off (NoPKCE): the
// web flow documents none, and better-auth sends no challenge either.
// Unlink revokes the token at TikTok's revoke endpoint.
//
//ds:def id=tiktok-w8nq3xkt owner=@khanakia stability=stable
func TikTok(clientKey, clientSecret string) *OAuth2 {
	return &OAuth2{
		ID: "tiktok", DisplayName: "TikTok", ClientID: clientKey, ClientSecret: clientSecret,
		ClientIDParam: tiktokClientKeyParam, ScopeSeparator: commaScopes, NoPKCE: true,
		AuthURL: TikTokAuthURL, TokenURL: TikTokTokenURL, RevokeURL: TikTokRevokeURL,
		Scopes: []string{"user.info.basic"}, FetchProfile: TikTokProfile(TikTokUserInfoURL),
	}
}

// TikTokProfile reads TikTok's /v2/user/info/ answer from u: data.user with
// open_id, display_name and avatar_large_url. An answer whose error.code is
// not "ok" is a failed read.
func TikTokProfile(u string) func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
	return profileReader(http.MethodGet, u, nil, func(body json.RawMessage) (Profile, error) {
		var t struct {
			Data struct {
				User struct {
					OpenID         string `json:"open_id"`
					DisplayName    string `json:"display_name"`
					Username       string `json:"username"`
					AvatarLargeURL string `json:"avatar_large_url"`
				} `json:"user"`
			} `json:"data"`
			Error struct {
				Status  string `json:"code"` // TikTok's status word ("ok"), not a secret
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(body, &t); err != nil {
			return Profile{}, err
		}
		if t.Error.Status != "" && t.Error.Status != tiktokOK {
			return Profile{}, fmt.Errorf("tiktok: %s: %s", t.Error.Status, t.Error.Message)
		}
		u := t.Data.User
		return Profile{Subject: u.OpenID, Name: firstOf(u.DisplayName, u.Username), Image: u.AvatarLargeURL}, nil
	})
}

// tiktokOK is the error.code of a successful TikTok API answer.
const tiktokOK = "ok"

// Notion endpoints (developers.notion.com/docs/authorization).
const (
	//ds:def id=notionauthurl-k5wq8xnt owner=@khanakia stability=stable
	NotionAuthURL = "https://api.notion.com/v1/oauth/authorize"
	//ds:def id=notiontokenurl-x3nk7wqm owner=@khanakia stability=stable
	NotionTokenURL = "https://api.notion.com/v1/oauth/token"
	//ds:def id=notionmeurl-q8tw2kxn owner=@khanakia stability=stable
	NotionMeURL = "https://api.notion.com/v1/users/me"
	// NotionVersion is the Notion-Version header the profile call sends,
	// the version better-auth v1.7.7 pins.
	//ds:def id=notionversion-n4xq9wkt owner=@khanakia stability=stable
	NotionVersion = "2022-06-28"
	// notionVersionHeader names the API version header Notion requires.
	notionVersionHeader = "Notion-Version"
	// notionOwnerParam and notionOwnerUser ask for a user-owned token, the
	// only kind that names the person who signed in.
	notionOwnerParam = "owner"
	notionOwnerUser  = "user"
)

// Notion is Sign in with Notion for a public integration: owner=user on the
// authorization URL and no scopes; the token request is HTTP Basic with a
// JSON body, as Notion documents it; the profile is the token's owner read
// from /v1/users/me (bot.owner.user), its email unverified. PKCE is off
// (NoPKCE): Notion documents none, and better-auth sends none.
//
//ds:def id=notion-p7kw3xqn owner=@khanakia stability=stable
func Notion(clientID, clientSecret string) *OAuth2 {
	o := &OAuth2{
		ID: "notion", DisplayName: "Notion", ClientID: clientID, ClientSecret: clientSecret, TokenAuth: ClientSecretBasic,
		NoPKCE: true, AuthURL: NotionAuthURL, TokenURL: NotionTokenURL,
		AuthParams:   url.Values{notionOwnerParam: {notionOwnerUser}},
		FetchProfile: NotionProfile(NotionMeURL),
	}
	o.exchange = func(ctx context.Context, hc *http.Client, code, redirectURI string) (TokenSet, error) {
		return o.jsonGrant(ctx, hc, map[string]string{paramGrantType: grantAuthorizationCode, paramCode: code, paramRedirectURI: redirectURI})
	}
	o.renew = func(ctx context.Context, hc *http.Client, rt auth.Token) (TokenSet, error) {
		return o.jsonGrant(ctx, hc, map[string]string{paramGrantType: grantRefreshToken, paramRefreshToken: rt.Reveal()})
	}
	return o
}

// jsonGrant posts a grant to TokenURL as a JSON body with the client
// credentials as HTTP Basic, Notion's documented form.
func (o *OAuth2) jsonGrant(ctx context.Context, hc *http.Client, body map[string]string) (TokenSet, error) {
	// Marshalling a map[string]string cannot fail.
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.TokenURL, strings.NewReader(string(raw)))
	if err != nil {
		return TokenSet{}, fmt.Errorf("%w: token request: %v", ErrExchange, err)
	}
	secret, err := o.clientSecret(ctx)
	if err != nil {
		return TokenSet{}, fmt.Errorf("%w: client secret: %v", ErrExchange, err)
	}
	req.SetBasicAuth(url.QueryEscape(o.ClientID), url.QueryEscape(secret))
	req.Header.Set(headerContentType, contentTypeJSON)
	req.Header.Set(headerAccept, contentTypeJSON)
	o.addHeaders(req)
	return o.decodeTokens(hc, req)
}

// decodeTokens sends a token request and converts the answer; an answer
// without an access token is a failed grant.
func (o *OAuth2) decodeTokens(hc *http.Client, req *http.Request) (TokenSet, error) {
	body, err := fetchJSON(hc, req)
	if err != nil {
		return TokenSet{}, err
	}
	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return TokenSet{}, fmt.Errorf("%w: %v", ErrExchange, err)
	}
	if tok.AccessToken == "" {
		return TokenSet{}, fmt.Errorf("%w: token endpoint: %s", ErrExchange, firstOf(tok.Error, string(body)))
	}
	tok.raw = body
	return tok.tokenSet(o.TokenLifetime), nil
}

// NotionProfile reads Notion's /v1/users/me answer from u: a bot whose
// owner.user is the person who authorized it.
func NotionProfile(u string) func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
	return profileReader(http.MethodGet, u, http.Header{notionVersionHeader: {NotionVersion}}, func(body json.RawMessage) (Profile, error) {
		var n struct {
			Bot struct {
				Owner struct {
					User struct {
						ID        string `json:"id"`
						Name      string `json:"name"`
						AvatarURL string `json:"avatar_url"`
						Person    struct {
							Email string `json:"email"`
						} `json:"person"`
					} `json:"user"`
				} `json:"owner"`
			} `json:"bot"`
		}
		if err := json.Unmarshal(body, &n); err != nil {
			return Profile{}, err
		}
		usr := n.Bot.Owner.User
		return Profile{Subject: usr.ID, Email: usr.Person.Email, Name: usr.Name, Image: usr.AvatarURL}, nil
	})
}

// VK ID endpoints (id.vk.ru/about/business/go/docs, "API description").
const (
	//ds:def id=vkauthurl-c6nw2xkq owner=@khanakia stability=stable
	VKAuthURL = "https://id.vk.ru/authorize"
	//ds:def id=vktokenurl-f8kq3wxn owner=@khanakia stability=stable
	VKTokenURL = "https://id.vk.ru/oauth2/auth"
	//ds:def id=vkuserinfourl-j2xw7kqt owner=@khanakia stability=stable
	VKUserInfoURL = "https://id.vk.ru/oauth2/user_info"
)

// VK is Sign in with VK ID: PKCE S256, scopes email and phone, and a token
// request that carries the device_id and the state the callback returned
// (CallbackParams), as VK ID requires. The profile is read by posting the
// access token and client id to /oauth2/user_info; the email is unverified.
// VK ID's refresh grant also requires the device_id: it is kept, sealed,
// with the stored tokens (RefreshCallbackParams, under StoreTokens) and sent
// with every refresh.
//
//ds:def id=vk-t5qw8xkn owner=@khanakia stability=stable
func VK(clientID, clientSecret string) *OAuth2 {
	return &OAuth2{
		ID: "vk", DisplayName: "VK ID", ClientID: clientID, ClientSecret: clientSecret,
		AuthURL: VKAuthURL, TokenURL: VKTokenURL, Scopes: []string{"email", "phone"},
		CallbackParams:        []CallbackParam{CallbackParamDeviceID, CallbackParamState},
		RefreshCallbackParams: []CallbackParam{CallbackParamDeviceID},
		FetchProfile:          VKProfile(VKUserInfoURL, clientID),
	}
}

// VKProfile reads VK ID's user_info answer from u, posting the access token
// and clientID as a form, which is how VK ID takes them.
func VKProfile(u, clientID string) func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
	return func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
		form := url.Values{paramClientID: {clientID}, paramAccessToken: {accessToken}}
		read := profileReaderWithAuth(http.MethodPost, u, http.Header{headerContentType: {contentTypeForm}}, false, func(body json.RawMessage) (Profile, error) {
			var v struct {
				User struct {
					UserID    json.RawMessage `json:"user_id"`
					FirstName string          `json:"first_name"`
					LastName  string          `json:"last_name"`
					Email     string          `json:"email"`
					Avatar    string          `json:"avatar"`
				} `json:"user"`
			}
			if err := json.Unmarshal(body, &v); err != nil {
				return Profile{}, err
			}
			usr := v.User
			return Profile{Subject: stringClaim(usr.UserID), Email: usr.Email, Name: strings.TrimSpace(usr.FirstName + " " + usr.LastName), Image: usr.Avatar}, nil
		}, form.Encode())
		return read(ctx, hc, accessToken)
	}
}

// WeChat endpoints (developers.weixin.qq.com, Website App WeChat Login).
const (
	//ds:def id=wechatauthurl-v3kq8xwn owner=@khanakia stability=stable
	WeChatAuthURL = "https://open.weixin.qq.com/connect/qrconnect"
	//ds:def id=wechattokenurl-b7xw2kqn owner=@khanakia stability=stable
	WeChatTokenURL = "https://api.weixin.qq.com/sns/oauth2/access_token"
	//ds:def id=wechatrefreshurl-g4nq9xkt owner=@khanakia stability=stable
	WeChatRefreshURL = "https://api.weixin.qq.com/sns/oauth2/refresh_token"
	//ds:def id=wechatuserinfourl-z8kw3xqm owner=@khanakia stability=stable
	WeChatUserInfoURL = "https://api.weixin.qq.com/sns/userinfo"
	// wechatAppIDParam and wechatSecretParam are WeChat's names for
	// client_id and client_secret.
	wechatAppIDParam  = "appid"
	wechatSecretParam = "secret"
	// wechatFragment is the fragment WeChat's QR login URL must end with.
	wechatFragment = "wechat_redirect"
	// wechatLangParam selects the QR page's language: cn or en.
	wechatLangParam = "lang"
	// wechatOpenIDParam names the openid the userinfo call takes.
	wechatOpenIDParam = "openid"
	// wechatUserInfoLang is the language of the userinfo answer.
	wechatUserInfoLang = "zh_CN"
	// paramAccessToken carries an access token in a form or query, for the
	// providers whose profile call takes it there (VK ID, WeChat).
	paramAccessToken = "access_token"
)

// WeChat languages for the QR login page (better-auth's lang option).
const (
	WeChatLangCN = "cn"
	WeChatLangEN = "en"
)

// WeChat is WeChat Login for a website app (QR code): appid instead of
// client_id, scope snsapi_login, #wechat_redirect on the authorization URL,
// lang on the QR page (WeChatLangCN, better-auth's default, or
// WeChatLangEN). The token and refresh endpoints are GETs that take appid
// and secret in the query, as WeChat documents them; the secret therefore
// travels in a URL, which this provider cannot avoid. The subject is the
// unionid when WeChat sends one, else the openid; WeChat has no email. PKCE
// is off (NoPKCE): WeChat has none.
//
//ds:def id=wechat-q2xn8kwt owner=@khanakia stability=stable
func WeChat(appID, appSecret, lang string) *OAuth2 {
	o := &OAuth2{
		ID: "wechat", DisplayName: "WeChat", ClientID: appID, ClientSecret: appSecret,
		ClientIDParam: wechatAppIDParam, ClientSecretParam: wechatSecretParam, ScopeSeparator: commaScopes,
		NoPKCE: true, AuthURLFragment: wechatFragment,
		AuthURL: WeChatAuthURL, TokenURL: WeChatTokenURL, Scopes: []string{"snsapi_login"},
		AuthParams:             url.Values{wechatLangParam: {firstOf(lang, WeChatLangCN)}},
		FetchProfileFromTokens: WeChatProfile(WeChatUserInfoURL),
	}
	o.exchange = func(ctx context.Context, hc *http.Client, code, _ string) (TokenSet, error) {
		return o.wechatGrant(ctx, hc, o.TokenURL, url.Values{paramGrantType: {grantAuthorizationCode}, paramCode: {code}, wechatSecretParam: {o.ClientSecret}})
	}
	o.renew = func(ctx context.Context, hc *http.Client, rt auth.Token) (TokenSet, error) {
		return o.wechatGrant(ctx, hc, WeChatRefreshURL, url.Values{paramGrantType: {grantRefreshToken}, paramRefreshToken: {rt.Reveal()}})
	}
	return o
}

// wechatGrant runs a WeChat grant: a GET to u with appid and q. A WeChat
// error comes back as 200 with errcode, which decodeTokens refuses for its
// missing access token.
func (o *OAuth2) wechatGrant(ctx context.Context, hc *http.Client, u string, q url.Values) (TokenSet, error) {
	q.Set(wechatAppIDParam, o.ClientID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u+"?"+q.Encode(), nil)
	if err != nil {
		return TokenSet{}, fmt.Errorf("%w: token request: %v", ErrExchange, err)
	}
	req.Header.Set(headerAccept, contentTypeJSON)
	ts, err := o.decodeTokens(hc, req)
	if err != nil {
		return TokenSet{}, err
	}
	// WeChat separates granted scopes with a comma; TokenSet.Scope is
	// space-separated like every other provider's.
	ts.Scope = strings.ReplaceAll(ts.Scope, commaScopes, scopeSeparator)
	return ts, nil
}

// WeChatProfile reads WeChat's /sns/userinfo from u for the openid the token
// answer carried (TokenSet.Raw).
func WeChatProfile(u string) func(ctx context.Context, hc *http.Client, ts TokenSet) (Profile, error) {
	return func(ctx context.Context, hc *http.Client, ts TokenSet) (Profile, error) {
		var t struct {
			OpenID string `json:"openid"`
		}
		if err := json.Unmarshal(ts.Raw, &t); err != nil || t.OpenID == "" {
			return Profile{}, fmt.Errorf("%w: wechat: the token answer has no openid", ErrExchange)
		}
		q := url.Values{paramAccessToken: {ts.AccessToken.Reveal()}, wechatOpenIDParam: {t.OpenID}, wechatLangParam: {wechatUserInfoLang}}
		read := profileReaderWithAuth(http.MethodGet, u+"?"+q.Encode(), nil, false, func(body json.RawMessage) (Profile, error) {
			var w struct {
				OpenID     string `json:"openid"`
				UnionID    string `json:"unionid"`
				Nickname   string `json:"nickname"`
				HeadImgURL string `json:"headimgurl"`
				ErrCode    int    `json:"errcode"`
				ErrMsg     string `json:"errmsg"`
			}
			if err := json.Unmarshal(body, &w); err != nil {
				return Profile{}, err
			}
			if w.ErrCode != 0 {
				return Profile{}, fmt.Errorf("wechat: %d: %s", w.ErrCode, w.ErrMsg)
			}
			return Profile{Subject: firstOf(w.UnionID, w.OpenID), Name: w.Nickname, Image: w.HeadImgURL}, nil
		}, "")
		return read(ctx, hc, "")
	}
}

// MicrosoftPhotoSize is a size Microsoft Graph serves a profile photo at
// (better-auth's profilePhotoSize). A closed set: Graph answers 404 for any
// other.
type MicrosoftPhotoSize int

// The sizes Graph serves, in pixels per side.
const (
	MicrosoftPhoto48  MicrosoftPhotoSize = 48
	MicrosoftPhoto64  MicrosoftPhotoSize = 64
	MicrosoftPhoto96  MicrosoftPhotoSize = 96
	MicrosoftPhoto120 MicrosoftPhotoSize = 120
	MicrosoftPhoto240 MicrosoftPhotoSize = 240
	MicrosoftPhoto360 MicrosoftPhotoSize = 360
	MicrosoftPhoto432 MicrosoftPhotoSize = 432
	MicrosoftPhoto504 MicrosoftPhotoSize = 504
	MicrosoftPhoto648 MicrosoftPhotoSize = 648
)

// MicrosoftPhotoSizes is every MicrosoftPhotoSize.
var MicrosoftPhotoSizes = []MicrosoftPhotoSize{MicrosoftPhoto48, MicrosoftPhoto64, MicrosoftPhoto96, MicrosoftPhoto120, MicrosoftPhoto240, MicrosoftPhoto360, MicrosoftPhoto432, MicrosoftPhoto504, MicrosoftPhoto648}

// MicrosoftPhotoURLFormat is the Graph photo of the signed-in person at a
// size (%d twice).
//
//ds:def id=microsoftphotourlformat-w6kq3xnt owner=@khanakia stability=stable
const MicrosoftPhotoURLFormat = "https://graph.microsoft.com/v1.0/me/photos/%dx%d/$value"

// MaxPhotoDataURL is the longest data URL MicrosoftPhoto puts in
// Profile.Image: 4096 characters, the user image column on MySQL
// (VARCHAR(4096)), so the photo fits on every engine. A larger photo is left
// out and the profile keeps its image; a 48-pixel photo fits, a large one
// rarely does.
//
//ds:def id=maxphotodataurl-k9xw2nqt owner=@khanakia stability=stable
const MaxPhotoDataURL = 4096

// ErrPhotoSize is MicrosoftPhoto given a size Graph does not serve.
var ErrPhotoSize = errors.New("oauth: MicrosoftPhoto size must be one of MicrosoftPhotoSizes")

// dataURLPrefix and dataURLBase64 build a data URL (RFC 2397).
const (
	dataURLPrefix = "data:"
	dataURLBase64 = ";base64,"
	// defaultPhotoType is the photo's media type when Graph does not say;
	// Graph serves JPEG.
	defaultPhotoType = "image/jpeg"
)

// MicrosoftPhoto wraps a Microsoft FetchProfile so the profile's image is
// the person's Graph photo at size, as a data URL (better-auth's
// profilePhotoSize; leaving it unwrapped is disableProfilePhoto, our
// default). A photo that is missing (404), unreadable, or longer than
// MaxPhotoDataURL as a data URL leaves the image as the profile had it: a
// sign-in never fails over a photo. size must be one of MicrosoftPhotoSizes.
//
//	m := oauth.Microsoft(tenant, id, secret)
//	m.FetchProfile, err = oauth.MicrosoftPhoto(m.FetchProfile, oauth.MicrosoftPhoto48)
//
//ds:def id=microsoftphoto-r3nw8kqx owner=@khanakia stability=stable
func MicrosoftPhoto(fetch func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error), size MicrosoftPhotoSize) (func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error), error) {
	if !slices.Contains(MicrosoftPhotoSizes, size) || fetch == nil {
		return nil, ErrPhotoSize
	}
	photoURL := fmt.Sprintf(MicrosoftPhotoURLFormat, size, size)
	return func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
		p, err := fetch(ctx, hc, accessToken)
		if err != nil {
			return Profile{}, err
		}
		if img := photoDataURL(ctx, hc, photoURL, accessToken); img != "" {
			p.Image = img
		}
		return p, nil
	}, nil
}

// photoDataURL fetches an image with the bearer token and returns it as a
// data URL, or "" when it is missing, not an image, or would exceed
// MaxPhotoDataURL.
func photoDataURL(ctx context.Context, hc *http.Client, u, accessToken string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return ""
	}
	req.Header.Set(headerAuthorization, bearerPrefix+accessToken)
	res, err := hc.Do(req)
	if err != nil {
		return ""
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return ""
	}
	ctype := defaultPhotoType
	if mt, _, err := mime.ParseMediaType(res.Header.Get(headerContentType)); err == nil && mt != "" {
		ctype = mt
	}
	if !strings.HasPrefix(ctype, "image/") {
		return ""
	}
	prefix := dataURLPrefix + ctype + dataURLBase64
	// Read one byte past what fits, so an oversized photo is detected
	// without reading all of it.
	limit := int64(base64.StdEncoding.DecodedLen(MaxPhotoDataURL-len(prefix))) + 1
	raw, err := io.ReadAll(io.LimitReader(res.Body, limit))
	if err != nil || len(raw) == 0 {
		return ""
	}
	out := prefix + base64.StdEncoding.EncodeToString(raw)
	if len(out) > MaxPhotoDataURL {
		return ""
	}
	return out
}
