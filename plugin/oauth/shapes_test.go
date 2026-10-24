package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/ubgo/auth"
)

// seenRequest is one request a fixture provider received.
type seenRequest struct {
	method, query, body, auth, ctype, version string
}

// fixtureProvider serves a JSON answer per path and records every request.
type fixtureProvider struct {
	mu   sync.Mutex
	seen map[string][]seenRequest
}

func newFixtureProvider(t *testing.T, answers map[string]string) (*fixtureProvider, string, *http.Client) {
	t.Helper()
	f := &fixtureProvider{seen: map[string][]seenRequest{}}
	routes := map[string]http.HandlerFunc{}
	for path, body := range answers {
		routes[path] = func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			f.mu.Lock()
			f.seen[path] = append(f.seen[path], seenRequest{r.Method, r.URL.RawQuery, string(b), r.Header.Get(headerAuthorization), r.Header.Get(headerContentType), r.Header.Get(notionVersionHeader)})
			f.mu.Unlock()
			w.Header().Set(headerContentType, contentTypeJSON)
			_, _ = w.Write([]byte(body))
		}
	}
	srv := providerServer(t, routes)
	return f, srv.URL, srv.Client()
}

func (f *fixtureProvider) last(t *testing.T, path string) seenRequest {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.seen[path]
	if len(s) == 0 {
		t.Fatalf("%s was never called", path)
	}
	return s[len(s)-1]
}

func basic(id, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(id+":"+secret))
}

func mustQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	v, err := url.ParseQuery(raw)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func authURLQuery(t *testing.T, u string) (url.Values, string) {
	t.Helper()
	p, err := url.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	return p.Query(), p.Fragment
}

func TestNoPKCE_LeavesTheChallengeAndVerifierOut(t *testing.T) {
	f, base, hc := newFixtureProvider(t, map[string]string{"/token": `{"access_token":"at"}`, "/me": `{"sub":"s1"}`})
	o := &OAuth2{ID: "p", ClientID: "c", ClientSecret: "s", AuthURL: base + "/a", TokenURL: base + "/token", FetchProfile: UserInfoProfile(base+"/me", ""), NoPKCE: true}
	q, _ := authURLQuery(t, o.AuthCodeURL("st", "challenge", "https://app/cb"))
	if q.Has(paramChallenge) || q.Has(paramChallengeAlg) || q.Get(paramState) != "st" {
		t.Fatalf("NoPKCE URL = %v", q)
	}
	if _, err := o.Exchange(context.Background(), hc, "code", "verifier", "https://app/cb"); err != nil {
		t.Fatal(err)
	}
	if form := mustQuery(t, f.last(t, "/token").body); form.Has(paramVerifier) || form.Get(paramClientSecret) != "s" {
		t.Fatalf("NoPKCE token form = %v", form)
	}
	// Default: both are sent (the inverse).
	o.NoPKCE = false
	q, _ = authURLQuery(t, o.AuthCodeURL("st", "challenge", "https://app/cb"))
	if q.Get(paramChallenge) != "challenge" || q.Get(paramChallengeAlg) != challengeMethodS256 {
		t.Fatalf("PKCE URL = %v", q)
	}
	if _, err := o.Exchange(context.Background(), hc, "code", "verifier", "https://app/cb"); err != nil {
		t.Fatal(err)
	}
	if form := mustQuery(t, f.last(t, "/token").body); form.Get(paramVerifier) != "verifier" {
		t.Fatalf("PKCE token form = %v", form)
	}
}

func TestValidate_NoPKCEAndCallbackParams(t *testing.T) {
	profile := func(context.Context, *http.Client, string) (Profile, error) { return Profile{}, nil }
	pub := &OAuth2{ID: "p", ClientID: "c", AuthURL: "https://p/a", TokenURL: "https://p/t", FetchProfile: profile, TokenAuth: PublicClient, NoPKCE: true}
	if err := ValidateProvider(pub); !errors.Is(err, ErrPublicClientPKCE) {
		t.Fatalf("public client without PKCE: %v", err)
	}
	pub.NoPKCE = false
	if err := ValidateProvider(pub); err != nil {
		t.Fatalf("public client with PKCE: %v", err)
	}
	bad := &OAuth2{ID: "p", ClientID: "c", AuthURL: "https://p/a", TokenURL: "https://p/t", FetchProfile: profile, CallbackParams: []CallbackParam{"code"}}
	if err := ValidateProvider(bad); !errors.Is(err, ErrCallbackParam) {
		t.Fatalf("unknown callback param: %v", err)
	}
	bad.CallbackParams = CallbackParamValues
	if err := ValidateProvider(bad); err != nil {
		t.Fatalf("known callback params: %v", err)
	}
}

func TestCallbackValues_RoundTripAndZero(t *testing.T) {
	if v := CallbackValuesOf(context.Background()); v != (CallbackValues{}) {
		t.Fatalf("zero = %+v", v)
	}
	ctx := WithCallbackValues(context.Background(), CallbackValues{State: "s", DeviceID: "d"})
	v := CallbackValuesOf(ctx)
	if v.value(CallbackParamState) != "s" || v.value(CallbackParamDeviceID) != "d" || v.value("other") != "" {
		t.Fatalf("values = %+v", v)
	}
}

func TestTikTok_ClientKeyCommaScopesAndNoPKCE(t *testing.T) {
	f, base, hc := newFixtureProvider(t, map[string]string{
		"/token":  `{"access_token":"act.1","refresh_token":"rft.1","expires_in":86400,"refresh_expires_in":31536000,"open_id":"o1","scope":"user.info.basic","token_type":"Bearer"}`,
		"/info":   `{"data":{"user":{"open_id":"o1","union_id":"u1","display_name":"Ann","avatar_large_url":"https://p16/a.jpg"}},"error":{"code":"ok","message":""}}`,
		"/revoke": `{}`,
	})
	o := TikTok("key-1", "secret-1")
	o.AuthURL, o.TokenURL, o.RevokeURL, o.FetchProfile = base+"/a", base+"/token", base+"/revoke", TikTokProfile(base+"/info")
	o.OptionalScopes = []string{"video.list"}
	q, frag := authURLQuery(t, o.AuthCodeURLWithParams("st", "ch", "https://app/cb", RequestParams{Scopes: []string{"video.list"}}))
	if q.Get(tiktokClientKeyParam) != "key-1" || q.Has(paramClientID) || q.Get(paramScope) != "user.info.basic,video.list" || q.Has(paramChallenge) || frag != "" {
		t.Fatalf("tiktok URL = %v #%s", q, frag)
	}
	p, err := o.Exchange(context.Background(), hc, "code-1", "verifier", "https://app/cb")
	if err != nil || p.Subject != "o1" || p.Name != "Ann" || p.Image != "https://p16/a.jpg" || p.Email != "" || p.Tokens.RefreshExpiresAt.IsZero() {
		t.Fatalf("tiktok profile = %+v %v", p, err)
	}
	form := mustQuery(t, f.last(t, "/token").body)
	want := url.Values{"client_key": {"key-1"}, "client_secret": {"secret-1"}, "code": {"code-1"}, "grant_type": {"authorization_code"}, "redirect_uri": {"https://app/cb"}}
	if form.Encode() != want.Encode() {
		t.Fatalf("tiktok token form = %v", form)
	}
	if _, err := o.Refresh(context.Background(), hc, "rft.1"); err != nil {
		t.Fatal(err)
	}
	form = mustQuery(t, f.last(t, "/token").body)
	want = url.Values{"client_key": {"key-1"}, "client_secret": {"secret-1"}, "grant_type": {"refresh_token"}, "refresh_token": {"rft.1"}}
	if form.Encode() != want.Encode() {
		t.Fatalf("tiktok refresh form = %v", form)
	}
	if err := o.Revoke(context.Background(), hc, TokenSet{AccessToken: "act.1"}); err != nil {
		t.Fatal(err)
	}
	if form := mustQuery(t, f.last(t, "/revoke").body); form.Get("client_key") != "key-1" || form.Get("token") != "act.1" || form.Has(paramClientID) {
		t.Fatalf("tiktok revoke form = %v", form)
	}
}

func TestTikTokProfile_AnErrorCodeFails(t *testing.T) {
	_, base, hc := newFixtureProvider(t, map[string]string{"/info": `{"data":{},"error":{"code":"access_token_invalid","message":"expired"}}`})
	if _, err := TikTokProfile(base+"/info")(context.Background(), hc, "at"); !errors.Is(err, ErrExchange) {
		t.Fatalf("error code: %v", err)
	}
	_, base, hc = newFixtureProvider(t, map[string]string{"/info": `{"data":{"user":{"open_id":"o","username":"ann"}}}`})
	if p, err := TikTokProfile(base+"/info")(context.Background(), hc, "at"); err != nil || p.Name != "ann" {
		t.Fatalf("no error object, username as name: %+v %v", p, err)
	}
}

func TestNotion_JSONBasicGrantAndOwnerProfile(t *testing.T) {
	f, base, hc := newFixtureProvider(t, map[string]string{
		"/token": `{"access_token":"ntn_1","refresh_token":"nrt_1","token_type":"bearer","bot_id":"b1","owner":{"type":"user"}}`,
		"/me":    `{"object":"user","id":"bot-1","type":"bot","bot":{"owner":{"type":"user","user":{"object":"user","id":"u-1","name":"Ann","avatar_url":"https://s3/a.png","type":"person","person":{"email":"ann@b.co"}}}}}`,
	})
	o := Notion("cid", "sec:ret")
	o.AuthURL, o.TokenURL, o.FetchProfile = base+"/a", base+"/token", NotionProfile(base+"/me")
	q, _ := authURLQuery(t, o.AuthCodeURL("st", "ch", "https://app/cb"))
	if q.Get(notionOwnerParam) != notionOwnerUser || q.Get(paramClientID) != "cid" || q.Has(paramChallenge) {
		t.Fatalf("notion URL = %v", q)
	}
	p, err := o.Exchange(context.Background(), hc, "code-1", "verifier", "https://app/cb")
	if err != nil || p.Subject != "u-1" || p.Email != "ann@b.co" || p.EmailVerified || p.Name != "Ann" || p.Image != "https://s3/a.png" {
		t.Fatalf("notion profile = %+v %v", p, err)
	}
	tok := f.last(t, "/token")
	var body map[string]string
	if err := json.Unmarshal([]byte(tok.body), &body); err != nil {
		t.Fatalf("notion token body is not JSON: %q", tok.body)
	}
	if tok.ctype != contentTypeJSON || tok.auth != basic("cid", url.QueryEscape("sec:ret")) || len(body) != 3 || body[paramGrantType] != grantAuthorizationCode || body[paramCode] != "code-1" || body[paramRedirectURI] != "https://app/cb" {
		t.Fatalf("notion token request = %+v", tok)
	}
	if v := f.last(t, "/me").version; v != NotionVersion {
		t.Fatalf("Notion-Version = %q", v)
	}
	if _, err := o.Refresh(context.Background(), hc, "nrt_1"); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(f.last(t, "/token").body), &body); err != nil || body[paramGrantType] != grantRefreshToken || body[paramRefreshToken] != "nrt_1" {
		t.Fatalf("notion refresh body = %v %v", body, err)
	}
}

func TestNotion_GrantFailures(t *testing.T) {
	_, base, hc := newFixtureProvider(t, map[string]string{"/token": `{"error":"invalid_grant"}`, "/bad": `not json`})
	o := Notion("c", "s")
	o.TokenURL = base + "/token"
	if _, err := o.Exchange(context.Background(), hc, "c", "", "r"); !errors.Is(err, ErrExchange) {
		t.Fatalf("refused grant: %v", err)
	}
	o.TokenURL = base + "/bad"
	if _, err := o.Refresh(context.Background(), hc, "rt"); !errors.Is(err, ErrExchange) {
		t.Fatalf("bad JSON: %v", err)
	}
	o.TokenURL = "://bad"
	if _, err := o.Refresh(context.Background(), hc, "rt"); !errors.Is(err, ErrExchange) {
		t.Fatalf("bad URL: %v", err)
	}
	o.TokenURL = unreachableURL(t)
	if _, err := o.Refresh(context.Background(), hc, "rt"); !errors.Is(err, ErrExchange) {
		t.Fatalf("unreachable: %v", err)
	}
	o.ClientSecretFunc = func(context.Context) (string, error) { return "", errors.New("no key") }
	if _, err := o.Refresh(context.Background(), hc, "rt"); !errors.Is(err, ErrExchange) {
		t.Fatalf("secret func: %v", err)
	}
}

func TestVK_DeviceIDStateAndPostedUserInfo(t *testing.T) {
	f, base, hc := newFixtureProvider(t, map[string]string{
		"/token": `{"access_token":"vk-at","refresh_token":"vk-rt","id_token":"x","expires_in":3600,"user_id":1234567890,"state":"st","scope":"email phone"}`,
		"/info":  `{"user":{"user_id":"1234567890","first_name":"Ivan","last_name":"I","email":"ivan@vk.example","avatar":"https://sun9/a.jpg","verified":false}}`,
	})
	o := VK("app-1", "sec-1")
	o.AuthURL, o.TokenURL, o.FetchProfile = base+"/a", base+"/token", VKProfile(base+"/info", "app-1")
	q, _ := authURLQuery(t, o.AuthCodeURL("st", "ch", "https://app/cb"))
	if q.Get(paramChallenge) != "ch" || q.Get(paramScope) != "email phone" || q.Get(paramClientID) != "app-1" {
		t.Fatalf("vk URL = %v", q)
	}
	ctx := WithCallbackValues(context.Background(), CallbackValues{State: "st", DeviceID: "dev-9"})
	p, err := o.Exchange(ctx, hc, "code-1", "verifier", "https://app/cb")
	if err != nil || p.Subject != "1234567890" || p.Email != "ivan@vk.example" || p.EmailVerified || p.Name != "Ivan I" || p.Image != "https://sun9/a.jpg" {
		t.Fatalf("vk profile = %+v %v", p, err)
	}
	form := mustQuery(t, f.last(t, "/token").body)
	if form.Get("device_id") != "dev-9" || form.Get("state") != "st" || form.Get(paramVerifier) != "verifier" || form.Get(paramClientID) != "app-1" || form.Get(paramClientSecret) != "sec-1" {
		t.Fatalf("vk token form = %v", form)
	}
	info := f.last(t, "/info")
	if info.method != http.MethodPost || info.ctype != contentTypeForm || info.auth != "" {
		t.Fatalf("vk user_info request = %+v", info)
	}
	if form := mustQuery(t, info.body); form.Get(paramClientID) != "app-1" || form.Get(paramAccessToken) != "vk-at" {
		t.Fatalf("vk user_info form = %v", form)
	}
	// Without callback values nothing extra is sent: an empty device_id
	// would be refused by VK, so it is left out rather than sent blank.
	if _, err := o.Exchange(context.Background(), hc, "code-2", "verifier", "https://app/cb"); err != nil {
		t.Fatal(err)
	}
	if form := mustQuery(t, f.last(t, "/token").body); form.Has("device_id") || form.Has("state") {
		t.Fatalf("vk token form without callback values = %v", form)
	}
}

func TestWeChat_AppIDFragmentGETGrantsAndOpenIDProfile(t *testing.T) {
	f, base, hc := newFixtureProvider(t, map[string]string{
		"/token":    `{"access_token":"wx-at","expires_in":7200,"refresh_token":"wx-rt","openid":"OPEN1","scope":"snsapi_login,snsapi_userinfo","unionid":"UNION1"}`,
		"/refresh":  `{"access_token":"wx-at2","expires_in":7200,"refresh_token":"wx-rt2","openid":"OPEN1","scope":"snsapi_login"}`,
		"/userinfo": `{"openid":"OPEN1","nickname":"Wei","headimgurl":"https://thirdwx/a","privilege":[],"unionid":"UNION1"}`,
	})
	o := WeChat("wxapp", "wxsecret", WeChatLangEN)
	o.AuthURL, o.TokenURL, o.FetchProfileFromTokens = base+"/a", base+"/token", WeChatProfile(base+"/userinfo")
	q, frag := authURLQuery(t, o.AuthCodeURL("st", "ch", "https://app/cb"))
	if q.Get(wechatAppIDParam) != "wxapp" || q.Has(paramClientID) || q.Get(paramScope) != "snsapi_login" || q.Get(wechatLangParam) != WeChatLangEN || q.Has(paramChallenge) || frag != wechatFragment {
		t.Fatalf("wechat URL = %v #%s", q, frag)
	}
	if q, _ := authURLQuery(t, WeChat("a", "s", "").AuthCodeURL("st", "ch", "r")); q.Get(wechatLangParam) != WeChatLangCN {
		t.Fatalf("default lang = %v", q)
	}
	p, err := o.Exchange(context.Background(), hc, "code-1", "verifier", "https://app/cb")
	if err != nil || p.Subject != "UNION1" || p.Name != "Wei" || p.Image != "https://thirdwx/a" || p.Tokens.Scope != "snsapi_login snsapi_userinfo" {
		t.Fatalf("wechat profile = %+v %v", p, err)
	}
	tok := f.last(t, "/token")
	if tok.method != http.MethodGet || tok.body != "" {
		t.Fatalf("wechat token request = %+v", tok)
	}
	want := url.Values{"appid": {"wxapp"}, "secret": {"wxsecret"}, "code": {"code-1"}, "grant_type": {"authorization_code"}}
	if mustQuery(t, tok.query).Encode() != want.Encode() {
		t.Fatalf("wechat token query = %v", tok.query)
	}
	ui := mustQuery(t, f.last(t, "/userinfo").query)
	if ui.Get(paramAccessToken) != "wx-at" || ui.Get(wechatOpenIDParam) != "OPEN1" || ui.Get(wechatLangParam) != wechatUserInfoLang {
		t.Fatalf("wechat userinfo query = %v", ui)
	}
	o2 := WeChat("wxapp", "wxsecret", "")
	o2.renew = func(ctx context.Context, hc *http.Client, rt auth.Token) (TokenSet, error) {
		return o2.wechatGrant(ctx, hc, base+"/refresh", url.Values{paramGrantType: {grantRefreshToken}, paramRefreshToken: {rt.Reveal()}})
	}
	ts, err := o2.Refresh(context.Background(), hc, "wx-rt")
	if err != nil || ts.AccessToken != "wx-at2" {
		t.Fatalf("wechat refresh = %+v %v", ts, err)
	}
	want = url.Values{"appid": {"wxapp"}, "grant_type": {"refresh_token"}, "refresh_token": {"wx-rt"}}
	if got := mustQuery(t, f.last(t, "/refresh").query); got.Encode() != want.Encode() {
		t.Fatalf("wechat refresh query = %v", got)
	}
}

func TestWeChat_RefreshUsesTheRefreshEndpoint(t *testing.T) {
	// The preset's own renew targets WeChatRefreshURL; pointing the client
	// at a local server through a rewriting transport proves the URL.
	_, base, hc := newFixtureProvider(t, map[string]string{"/sns/oauth2/refresh_token": `{"access_token":"wx-at3","expires_in":7200}`})
	hc.Transport = everyHostTo(base, hc.Transport)
	ts, err := WeChat("wxapp", "s", "").Refresh(context.Background(), hc, "rt")
	if err != nil || ts.AccessToken != "wx-at3" {
		t.Fatalf("wechat refresh endpoint = %+v %v", ts, err)
	}
}

func TestWeChat_Failures(t *testing.T) {
	_, base, hc := newFixtureProvider(t, map[string]string{
		"/token":    `{"errcode":40029,"errmsg":"invalid code"}`,
		"/noopenid": `{"access_token":"at"}`,
		"/userinfo": `{"errcode":40003,"errmsg":"invalid openid"}`,
		"/badinfo":  `[1]`,
	})
	o := WeChat("a", "s", "")
	o.TokenURL = base + "/token"
	if _, err := o.Exchange(context.Background(), hc, "c", "", "r"); !errors.Is(err, ErrExchange) {
		t.Fatalf("errcode: %v", err)
	}
	o.TokenURL = base + "/noopenid"
	if _, err := o.Exchange(context.Background(), hc, "c", "", "r"); !errors.Is(err, ErrExchange) {
		t.Fatalf("no openid: %v", err)
	}
	o.TokenURL = "://bad"
	if _, err := o.Exchange(context.Background(), hc, "c", "", "r"); !errors.Is(err, ErrExchange) {
		t.Fatalf("bad URL: %v", err)
	}
	ts := TokenSet{AccessToken: "at", Raw: json.RawMessage(`{"openid":"O"}`)}
	if _, err := WeChatProfile(base+"/userinfo")(context.Background(), hc, ts); !errors.Is(err, ErrExchange) {
		t.Fatalf("userinfo errcode: %v", err)
	}
	if _, err := WeChatProfile(base+"/badinfo")(context.Background(), hc, ts); !errors.Is(err, ErrExchange) {
		t.Fatalf("userinfo not an object: %v", err)
	}
}

func TestMicrosoftPhoto(t *testing.T) {
	jpeg := []byte{0xff, 0xd8, 0xff, 0xe0, 1, 2, 3}
	var status int
	var ctype string
	var body []byte
	var gotPath, gotAuth string
	srv := providerServer(t, map[string]http.HandlerFunc{"/": func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.EscapedPath(), r.Header.Get(headerAuthorization)
		if ctype != "" {
			w.Header().Set(headerContentType, ctype)
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}})
	hc := srv.Client()
	hc.Transport = everyHostTo(srv.URL, hc.Transport)
	base := func(context.Context, *http.Client, string) (Profile, error) {
		return Profile{Subject: "oid-1", Image: "kept"}, nil
	}
	fetch, err := MicrosoftPhoto(base, MicrosoftPhoto96)
	if err != nil {
		t.Fatal(err)
	}
	status, ctype, body = http.StatusOK, "image/jpeg", jpeg
	p, err := fetch(context.Background(), hc, "graph-at")
	if err != nil || p.Image != "data:image/jpeg;base64,"+base64.StdEncoding.EncodeToString(jpeg) {
		t.Fatalf("photo = %q %v", p.Image, err)
	}
	if gotPath != "/v1.0/me/photos/96x96/$value" || gotAuth != bearerPrefix+"graph-at" {
		t.Fatalf("photo request %s %s", gotPath, gotAuth)
	}
	// No media type: JPEG is assumed.
	ctype = ""
	if p, _ := fetch(context.Background(), hc, "at"); !strings.HasPrefix(p.Image, "data:image/jpeg;base64,") {
		t.Fatalf("no content type = %q", p.Image)
	}
	// Every way of not getting a usable photo keeps the profile's image.
	for name, c := range map[string]struct {
		status int
		ctype  string
		body   []byte
	}{
		"missing":   {http.StatusNotFound, "image/jpeg", nil},
		"not image": {http.StatusOK, "application/json", []byte(`{}`)},
		"empty":     {http.StatusOK, "image/png", nil},
		"too large": {http.StatusOK, "image/jpeg", make([]byte, MaxPhotoDataURL)},
	} {
		status, ctype, body = c.status, c.ctype, c.body
		if p, err := fetch(context.Background(), hc, "at"); err != nil || p.Image != "kept" {
			t.Fatalf("%s: image %q %v", name, p.Image, err)
		}
	}
	// The largest photo that fits is kept whole.
	status, ctype = http.StatusOK, "image/png"
	prefix := "data:image/png;base64,"
	body = make([]byte, base64.StdEncoding.DecodedLen(MaxPhotoDataURL-len(prefix)))
	if p, _ := fetch(context.Background(), hc, "at"); len(p.Image) > MaxPhotoDataURL || !strings.HasPrefix(p.Image, prefix) {
		t.Fatalf("largest fitting photo: %d chars", len(p.Image))
	}
	// The profile's own failure wins, and the photo is not fetched.
	failing, _ := MicrosoftPhoto(func(context.Context, *http.Client, string) (Profile, error) { return Profile{}, ErrExchange }, MicrosoftPhoto48)
	if _, err := failing(context.Background(), hc, "at"); !errors.Is(err, ErrExchange) {
		t.Fatalf("profile failure: %v", err)
	}
	// An unreachable Graph keeps the image too.
	gone, _ := MicrosoftPhoto(base, MicrosoftPhoto48)
	dead := &http.Client{Transport: everyHostTo(unreachableURL(t), http.DefaultTransport)}
	if p, err := gone(context.Background(), dead, "at"); err != nil || p.Image != "kept" {
		t.Fatalf("unreachable: %+v %v", p, err)
	}
	if _, err := MicrosoftPhoto(base, 50); !errors.Is(err, ErrPhotoSize) {
		t.Fatalf("bad size: %v", err)
	}
	if _, err := MicrosoftPhoto(nil, MicrosoftPhoto48); !errors.Is(err, ErrPhotoSize) {
		t.Fatalf("nil fetch: %v", err)
	}
	if photoDataURL(context.Background(), hc, "://bad", "at") != "" {
		t.Fatal("bad URL produced a photo")
	}
}

// everyHostRT sends every request to base, whatever its host, so a preset's
// fixed provider URL is served by a local fixture and never reaches the
// real provider.
type everyHostRT struct {
	base *url.URL
	next http.RoundTripper
}

func everyHostTo(base string, next http.RoundTripper) http.RoundTripper {
	u, err := url.Parse(base)
	if err != nil {
		panic(err)
	}
	return everyHostRT{base: u, next: next}
}

func (r everyHostRT) RoundTrip(req *http.Request) (*http.Response, error) {
	c := req.Clone(req.Context())
	c.URL.Scheme, c.URL.Host, c.Host = r.base.Scheme, r.base.Host, r.base.Host
	return r.next.RoundTrip(c)
}

func TestPresetProfiles_RefuseAnAnswerOfTheWrongShape(t *testing.T) {
	_, base, hc := newFixtureProvider(t, map[string]string{"/p": `[1]`})
	for name, read := range map[string]profileFn{
		"tiktok": TikTokProfile(base + "/p"),
		"notion": NotionProfile(base + "/p"),
		"vk":     VKProfile(base+"/p", "app"),
	} {
		if _, err := read(context.Background(), hc, "at"); !errors.Is(err, ErrExchange) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
