package authhttp_test

import (
	"context"
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

// Round 6 of the better-auth comparison: the hosted error page and the
// original message beside a translated one.

// r6Messages translates the test plugin's conflict and the core's signed-out
// error into German.
var r6Messages = auth.Messages{"de": {errConflict.Code: "Schon vergeben.", auth.ErrSignedOut.Code: "Abgemeldet."}}

func r6Auth(t *testing.T, opts ...auth.Option) *auth.Auth {
	t.Helper()
	a, err := auth.New(append([]auth.Option{auth.WithBaseURL(base), auth.WithPlugins(newPlugin())}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func german(r *http.Request) { r.Header.Set("Accept-Language", "de-DE,de;q=0.9") }

// The page shows a declared code with its message in the request's language,
// escapes the provider's description, and never echoes a value that is not
// shaped like a code.
func TestErrorPage_RendersTheCode(t *testing.T) {
	h := authhttp.Handler(r6Auth(t, auth.WithMessages(r6Messages)), authhttp.Prefix("/auth"), authhttp.ErrorPage(authhttp.ErrorPageOptions{}))
	rec := do(h, http.MethodGet, "/auth/error?error=auth.signed_out&error_description=%3Cscript%3Ealert(1)%3C/script%3E", "", german)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "Abgemeldet.") || !strings.Contains(body, "auth.signed_out") {
		t.Fatalf("%d %s", rec.Code, body)
	}
	if strings.Contains(body, "<script>") || !strings.Contains(body, "&lt;script&gt;") {
		t.Fatalf("description not escaped: %s", body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("headers %v", rec.Header())
	}
	rec = do(h, http.MethodGet, "/auth/error?error=%22%3E%3Cb%3Ex", "")
	if strings.Contains(rec.Body.String(), "<b>") || !strings.Contains(rec.Body.String(), "<code>unknown</code>") {
		t.Fatalf("a malformed code: %s", rec.Body.String())
	}
	// A well-shaped code nobody declares is shown without a message.
	rec = do(h, http.MethodGet, "/auth/error?error=access_denied", "")
	if !strings.Contains(rec.Body.String(), "<code>access_denied</code>") {
		t.Fatalf("an OAuth code: %s", rec.Body.String())
	}
	long := strings.Repeat("x", 400)
	rec = do(h, http.MethodGet, "/auth/error?error=x&error_description="+long, "")
	if strings.Contains(rec.Body.String(), long) {
		t.Fatal("the description was not capped")
	}
}

// Without the option there is no route; with Redirect the request goes on to
// the app's page with the parameters; a custom template and a nonce are used.
func TestErrorPage_Options(t *testing.T) {
	a := r6Auth(t)
	if rec := do(authhttp.Handler(a, authhttp.Prefix("/auth")), http.MethodGet, "/auth/error?error=x", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("route without ErrorPage: %d", rec.Code)
	}
	h := authhttp.Handler(a, authhttp.Prefix("/auth"), authhttp.ErrorPage(authhttp.ErrorPageOptions{Redirect: "/oops?from=auth"}))
	rec := do(h, http.MethodGet, "/auth/error?error=oauth.denied&error_description=no", "")
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/oops?from=auth&error=oauth.denied&error_description=no" {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get("Location"))
	}
	h = authhttp.Handler(a, authhttp.Prefix("/auth"), authhttp.ErrorPage(authhttp.ErrorPageOptions{Redirect: "/oops"}))
	if rec := do(h, http.MethodGet, "/auth/error?error=x", ""); rec.Header().Get("Location") != "/oops?error=x" {
		t.Fatalf("redirect without a description: %q", rec.Header().Get("Location"))
	}
	tmpl := template.Must(template.New("t").Parse(`[{{.Code}}|{{.Message}}|{{.Nonce}}]`))
	h = authhttp.Handler(a, authhttp.Prefix("/auth"), authhttp.ErrorPage(authhttp.ErrorPageOptions{Template: tmpl, Nonce: func(*http.Request) string { return "n0nce" }}))
	if rec := do(h, http.MethodGet, "/auth/error?error=auth.signed_out", ""); rec.Body.String() != "[auth.signed_out|"+auth.ErrSignedOut.Message+"|n0nce]" {
		t.Fatalf("custom template: %q", rec.Body.String())
	}
	h = authhttp.Handler(a, authhttp.Prefix("/auth"), authhttp.ErrorPage(authhttp.ErrorPageOptions{Nonce: func(*http.Request) string { return "n0nce" }}))
	if rec := do(h, http.MethodGet, "/auth/error", ""); !strings.Contains(rec.Body.String(), `<style nonce="n0nce">`) {
		t.Fatalf("nonce on the built-in page: %s", rec.Body.String())
	}
	defer func() {
		if recover() == nil {
			t.Fatal("an off-site Redirect was accepted")
		}
	}()
	authhttp.Handler(a, authhttp.ErrorPage(authhttp.ErrorPageOptions{Redirect: "https://evil.example"}))
}

// A translated error carries the declared English text as originalMessage,
// as better-auth's i18n plugin answers; an untranslated one does not.
func TestWriteError_OriginalMessage(t *testing.T) {
	h := authhttp.Handler(r6Auth(t, auth.WithMessages(r6Messages)), authhttp.Prefix("/auth"))
	var body struct {
		Error map[string]string `json:"error"`
	}
	rec := do(h, http.MethodPost, "/auth/hp/conflict", "{}", german, func(r *http.Request) { r.Header.Set("Origin", base) })
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error["message"] != "Schon vergeben." || body.Error["originalMessage"] != errConflict.Message {
		t.Fatalf("translated: %v", body.Error)
	}
	rec = do(h, http.MethodPost, "/auth/hp/conflict", "{}", func(r *http.Request) { r.Header.Set("Origin", base) })
	body.Error = nil
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if _, ok := body.Error["originalMessage"]; ok || body.Error["message"] != errConflict.Message {
		t.Fatalf("untranslated: %v", body.Error)
	}
}

// CookieDomainFromBaseURL sets each response's cookies for the host of that
// request's base URL: an allowed host gets its own domain, an unknown Host
// header gets the static base URL's, and an explicit CookieDomain wins.
func TestCookieDomainFromBaseURL(t *testing.T) {
	a := r6Auth(t, auth.WithAllowedHosts("*.preview.example.com"))
	issue := func(h http.Handler, host string) *http.Cookie {
		t.Helper()
		rec := do(h, http.MethodPost, "/auth/hp/issue", "{}", func(r *http.Request) {
			r.Host = host
			r.Header.Set("Origin", base)
		})
		for _, c := range rec.Result().Cookies() {
			if strings.HasSuffix(c.Name, "_session") {
				return c
			}
		}
		t.Fatalf("no session cookie for %s: %d %s", host, rec.Code, rec.Body.String())
		return nil
	}
	h := authhttp.Handler(a, authhttp.Prefix("/auth"), authhttp.CookieDomainFromBaseURL())
	if c := issue(h, "pr-42.preview.example.com"); c.Domain != "pr-42.preview.example.com" || c.Name != "__Secure-auth_session" {
		t.Fatalf("allowed host: %s domain %q", c.Name, c.Domain)
	}
	if c := issue(h, "evil.test"); c.Domain != "app.example.com" {
		t.Fatalf("a Host header no rule allows: domain %q", c.Domain)
	}
	h = authhttp.Handler(a, authhttp.Prefix("/auth"), authhttp.CookieDomainFromBaseURL(), authhttp.CookieDomain("example.com"))
	if c := issue(h, "pr-42.preview.example.com"); c.Domain != "example.com" {
		t.Fatalf("explicit domain: %q", c.Domain)
	}
}

// A plugin cookie is set beside the core's under the same prefixes, with the
// library's attributes whatever the plugin wanted, and read back under the
// name the plugin gave it.
func TestPluginCookie_SetAndRead(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	for _, tc := range []struct {
		opts []authhttp.Option
		name string
	}{
		{nil, "__Host-auth_two_factor"},
		{[]authhttp.Option{authhttp.CookiePrefix("myapp"), authhttp.SameSiteStrict()}, "__Host-myapp_two_factor"},
		{[]authhttp.Option{authhttp.CookieDomain("example.com")}, "__Secure-auth_two_factor"},
	} {
		rec := httptest.NewRecorder()
		authhttp.ApplyEffects(rec, httptest.NewRequest(http.MethodGet, "/", nil), []auth.Effect{{Kind: auth.EffectCookie, Name: "two_factor", Value: "v1", ExpiresAt: exp}}, tc.opts...)
		cs := rec.Result().Cookies()
		if len(cs) != 1 || cs[0].Name != tc.name || cs[0].Value != "v1" || !cs[0].HttpOnly || !cs[0].Secure || cs[0].Path != "/" || cs[0].SameSite == http.SameSiteNoneMode {
			t.Fatalf("%s: %+v", tc.name, cs)
		}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(&http.Cookie{Name: tc.name, Value: "v1"})
		v, ok := authhttp.RequestOf(r, tc.opts...).Cookie("two_factor")
		if !ok || v != "v1" {
			t.Fatalf("%s read back %q %v", tc.name, v, ok)
		}
		if _, ok := authhttp.RequestOf(r, tc.opts...).Cookie("other"); ok {
			t.Fatal("a cookie the client did not send")
		}
	}
	// A zero expiry deletes it.
	rec := httptest.NewRecorder()
	authhttp.ApplyEffects(rec, httptest.NewRequest(http.MethodGet, "/", nil), []auth.Effect{{Kind: auth.EffectCookie, Name: "two_factor"}})
	if cs := rec.Result().Cookies(); len(cs) != 1 || cs[0].MaxAge >= 0 {
		t.Fatalf("delete: %+v", cs)
	}
}

// mwPlugin adds two middlewares: one on every request that records the
// order and stamps the response, and one on /hp/echo* that answers early.
type mwPlugin struct {
	name  string
	order *[]string
}

func (p mwPlugin) Name() string                 { return p.name }
func (p mwPlugin) Operations() []auth.Operation { return nil }
func (p mwPlugin) HTTPMiddleware() []authhttp.PluginMiddleware {
	return []authhttp.PluginMiddleware{
		{Wrap: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				*p.order = append(*p.order, p.name)
				w.Header().Add("X-Seen-By", p.name)
				next.ServeHTTP(w, r)
			})
		}},
		{Paths: []string{"/hp/echo*", "/hp/query"}, Wrap: func(http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
		}},
	}
}

// spanRecorder is an auth.Tracer that keeps the names of the spans started.
type spanRecorder struct{ names []string }

func (s *spanRecorder) Start(ctx context.Context, i auth.SpanInfo) (context.Context, auth.Span) {
	s.names = append(s.names, i.Name)
	return ctx, noSpan{}
}

type noSpan struct{}

func (noSpan) End(error) {}

// Plugin middleware wraps Handler's routes in plugin order, runs only where
// its paths match, can answer early, and is traced.
func TestPluginMiddleware(t *testing.T) {
	var order []string
	tr := &spanRecorder{}
	a, err := auth.New(auth.WithBaseURL(base), auth.WithPlugins(newPlugin(), mwPlugin{"first", &order}, mwPlugin{"second", &order}), auth.WithTracer(tr))
	if err != nil {
		t.Fatal(err)
	}
	h := authhttp.Handler(a, authhttp.Prefix("/auth"))
	rec := do(h, http.MethodPost, "/auth/hp/conflict", "{}", func(r *http.Request) { r.Header.Set("Origin", base) })
	if rec.Code != http.StatusConflict || strings.Join(rec.Header().Values("X-Seen-By"), ",") != "first,second" || strings.Join(order, ",") != "first,second" {
		t.Fatalf("%d %v %v", rec.Code, rec.Header(), order)
	}
	if rec := do(h, http.MethodPost, "/auth/hp/echo", "{}"); rec.Code != http.StatusTeapot {
		t.Fatalf("prefix path: %d", rec.Code)
	}
	if rec := do(h, http.MethodGet, "/auth/hp/query", ""); rec.Code != http.StatusTeapot {
		t.Fatalf("exact path: %d", rec.Code)
	}
	if rec := do(h, http.MethodGet, "/auth/nowhere", ""); rec.Code != http.StatusNotFound || len(rec.Header().Values("X-Seen-By")) != 2 {
		t.Fatalf("unknown route: %d %v", rec.Code, rec.Header())
	}
	want := "auth.middleware first /hp/conflict"
	if len(tr.names) == 0 || tr.names[0] != want {
		t.Fatalf("spans %v, want %q first", tr.names, want)
	}
}
