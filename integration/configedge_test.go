package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authgate"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/authui"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/agentauth"
	"github.com/ubgo/auth/plugin/agentauth/agentclient"
	"github.com/ubgo/auth/plugin/anonymous"
	"github.com/ubgo/auth/plugin/apikey"
	"github.com/ubgo/auth/plugin/audit"
	"github.com/ubgo/auth/plugin/captcha"
	"github.com/ubgo/auth/plugin/deviceauth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/emailchallenge"
	"github.com/ubgo/auth/plugin/handoff"
	"github.com/ubgo/auth/plugin/invite"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/lastlogin"
	"github.com/ubgo/auth/plugin/magiclink"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/oauthprovider"
	"github.com/ubgo/auth/plugin/oauthproxy"
	"github.com/ubgo/auth/plugin/oauthproxy/oauthpopup"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/passkey"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/phone"
	"github.com/ubgo/auth/plugin/referral"
	"github.com/ubgo/auth/plugin/scim"
	"github.com/ubgo/auth/plugin/sessiondata"
	"github.com/ubgo/auth/plugin/sso"
	"github.com/ubgo/auth/plugin/twofactor"
	"github.com/ubgo/auth/plugin/username"
	"github.com/ubgo/sqlb"
)

// The config edge test: every exported option constructor, called with the
// edge values of each parameter kind (nil for a func, interface, pointer,
// map or slice; 0 and -1 for a number or duration; "" for a string; no
// argument and one zero argument for a variadic; for a config struct the
// zero struct and each struct with one field set), then applied to a
// minimal valid configuration. The rule, per call:
//
//   - nothing panics, from the constructor to the last request;
//   - auth.New (or the package's own constructor) either refuses with an
//     error that names the option, or succeeds and the instance serves a
//     sign-up, a sign-in and a session read, and the session it issues
//     lives longer than a minute (no zero-lifetime, zero-limit surprise).
//
// Why: the option tests pass sensible values, so a partial WithSession
// that set a zero lifetime and a nil option that panicked at the first
// request shipped. Discovery is by source (configedge_discover_test.go),
// so a new option is covered as soon as its registry line is added, which
// this test demands.

// edgeNotImported are packages whose options the registry cannot hold,
// because they live in modules this one does not import; each keeps its own
// options_nil_test.go for the nil rule.
var edgeNotImported = map[string]string{
	"github.com/ubgo/auth/contrib/redis":        "contrib/redis is its own module (go-redis); its options are nil-checked by its options_nil_test.go",
	"github.com/ubgo/auth/plugin/password/hibp": "plugin/password/hibp is its own module; its options are nil-checked by its options_nil_test.go",
}

// edgeUnnamedRefusals are the options whose edge values auth.New (or the
// plugin's Validate) refuses with an error that describes the setting in the
// plugin's own words instead of naming the option. Each such refusal is safe,
// which is the rule's point; the unnamed message is the debt. The list was
// pinned at 65 options on 2026-10-09 and emptied the same day (auth batch 2)
// by rewording every refusal to name its option. It stays as the place a
// future entry must be argued for: a NEW option cannot join it silently, and
// an entry whose refusal starts naming the option fails as stale, so the list
// only shrinks. Every entry needs a comment saying why its refusal cannot
// name the option.
var edgeUnnamedRefusals = map[string]bool{}

// edgeExempt are options whose edge value is legal by design and changes
// what the basic flow may do, so the flow's failure is the intended
// behaviour, by qualified name and, after a colon, the edge case label
// ("" for every case of the option). Each entry says why.
var edgeExempt = map[string]string{}

// edgePassword is the password every edge flow signs up with.
const edgePassword = "correct horse battery staple 9"

// edgeMinLifetime is the shortest session lifetime the basic flow accepts:
// a session that is gone in under a minute is the zero-lifetime surprise.
const edgeMinLifetime = time.Minute

// edgeUnnamed starts the verdict of a refusal that does not name its option.
const edgeUnnamed = "refused without naming the option"

// edgeBaseURL is the app URL every edge instance runs under.
const edgeBaseURL = "https://app.example.test"

// edgeDBCount numbers the in-memory databases, one per instance.
var edgeDBCount atomic.Int64

// edgeCase is one call of an option constructor.
type edgeCase struct {
	label string
	args  []reflect.Value
}

// edgeMail records the last mail, for the verification link.
type edgeMail struct {
	mu   sync.Mutex
	last email.Mail
}

func (m *edgeMail) Send(_ context.Context, mail email.Mail) error {
	m.mu.Lock()
	m.last = mail
	m.mu.Unlock()
	return nil
}

var edgeTokenInLink = regexp.MustCompile(`token=([A-Za-z0-9_%-]+)`)

// edgeKnown are plausible values for interface and pointer parameters that
// are not the parameter under test, by type.
func edgeKnown(db *sql.DB) map[reflect.Type]reflect.Value {
	return map[reflect.Type]reflect.Value{
		reflect.TypeFor[sqlb.Dialect](): reflect.ValueOf(sqlb.SQLiteDialect{}),
		reflect.TypeFor[*sql.DB]():      reflect.ValueOf(db),
		reflect.TypeFor[*slog.Logger](): reflect.ValueOf(slog.New(slog.NewTextHandler(io.Discard, nil))),
		reflect.TypeFor[*http.Client](): reflect.ValueOf(http.DefaultClient),
		// A closed set of names: any other text is a programming error
		// WeakenCookie panics on at once, by design.
		reflect.TypeFor[authhttp.CookieRole](): reflect.ValueOf(authhttp.CookieFlow),
	}
}

// plausible is a value of t that is not an edge: what a caller who meant
// it would pass for a parameter not under test.
func edgePlausible(t reflect.Type, known map[reflect.Type]reflect.Value, depth int) reflect.Value {
	if v, ok := known[t]; ok {
		return v
	}
	v := reflect.New(t).Elem()
	if depth > wireMaxDepth {
		return v
	}
	if t == reflect.TypeFor[time.Duration]() {
		v.SetInt(int64(time.Hour))
		return v
	}
	switch t.Kind() {
	case reflect.String:
		v.SetString(edgeBaseURL + "/edge")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(8)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(8)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(0.5)
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			b := make([]byte, 32)
			_, _ = rand.Read(b)
			v.SetBytes(b)
			return v
		}
		s := reflect.MakeSlice(t, 1, 1)
		s.Index(0).Set(edgePlausible(t.Elem(), known, depth+1))
		v.Set(s)
	case reflect.Map:
		v.Set(reflect.MakeMap(t))
	case reflect.Pointer:
		v.Set(edgePlausible(t.Elem(), known, depth+1).Addr())
	case reflect.Func:
		v.Set(reflect.MakeFunc(t, func([]reflect.Value) []reflect.Value {
			out := make([]reflect.Value, t.NumOut())
			for i := range out {
				out[i] = reflect.New(t.Out(i)).Elem()
			}
			return out
		}))
	}
	return v
}

// edgeValues are the edge values of a parameter of type t, labelled.
func edgeValues(t reflect.Type, known map[reflect.Type]reflect.Value) []edgeCase {
	zero := func(label string) edgeCase {
		return edgeCase{label: label, args: []reflect.Value{reflect.New(t).Elem()}}
	}
	one := func(label string, v reflect.Value) edgeCase { return edgeCase{label: label, args: []reflect.Value{v}} }
	switch t.Kind() {
	case reflect.Func, reflect.Interface, reflect.Pointer, reflect.Map, reflect.Chan:
		return []edgeCase{zero("nil")}
	case reflect.Slice:
		empty := reflect.MakeSlice(t, 0, 0)
		return []edgeCase{zero("nil"), one("empty", empty)}
	case reflect.String:
		return []edgeCase{zero(`""`)}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Float32, reflect.Float64:
		neg := reflect.New(t).Elem()
		if t.Kind() == reflect.Float32 || t.Kind() == reflect.Float64 {
			neg.SetFloat(-1)
		} else {
			neg.SetInt(-1)
		}
		return []edgeCase{zero("0"), one("-1", neg)}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return []edgeCase{zero("0")}
	case reflect.Struct:
		if t == reflect.TypeFor[time.Time]() {
			return []edgeCase{zero("zero time")}
		}
		out := []edgeCase{zero("zero struct")}
		for i := range t.NumField() {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			v := reflect.New(t).Elem()
			v.Field(i).Set(edgePlausible(f.Type, known, 1))
			out = append(out, one("only "+f.Name, v))
		}
		return out
	}
	return nil
}

// edgeCases are every call of fn the test makes: for each parameter, each
// of its edge values with every other parameter plausible.
func edgeCases(fn reflect.Value, known map[reflect.Type]reflect.Value) []edgeCase {
	ft := fn.Type()
	n := ft.NumIn()
	plausible := make([]reflect.Value, n)
	for i := range n {
		pt := ft.In(i)
		if ft.IsVariadic() && i == n-1 {
			pt = pt.Elem()
		}
		plausible[i] = edgePlausible(pt, known, 0)
	}
	var out []edgeCase
	for i := range n {
		pt := ft.In(i)
		variadic := ft.IsVariadic() && i == n-1
		if variadic {
			// No argument at all, then one argument at each edge.
			out = append(out, edgeCase{label: fmt.Sprintf("arg %d: none", i), args: append([]reflect.Value(nil), plausible[:i]...)})
			pt = pt.Elem()
		}
		for _, e := range edgeValues(pt, known) {
			args := append([]reflect.Value(nil), plausible...)
			args[i] = e.args[0]
			out = append(out, edgeCase{label: fmt.Sprintf("arg %d: %s", i, e.label), args: args})
		}
	}
	return out
}

// edgeEnv is one minimal valid configuration: a fresh in-memory database,
// the base plugins (email and password), and the recorders.
type edgeEnv struct {
	db   *sql.DB
	mail *edgeMail
	key  []byte
	sig  ed25519.PrivateKey
}

func newEdgeEnv(t *testing.T) *edgeEnv {
	t.Helper()
	db, err := sql.Open("sqlite", fmt.Sprintf("file:edge-%d?mode=memory&cache=shared&_pragma=busy_timeout(5000)", edgeDBCount.Add(1)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	key := make([]byte, auth.MinSecretSize)
	_, _ = rand.Read(key)
	_, sig, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &edgeEnv{db: db, mail: &edgeMail{}, key: key, sig: sig}
}

// edgeBuild is how options of one type reach a running instance: the
// plugins and core options that carry them. opts are the option values
// under test; a builder adds them after the base options, so they win.
type edgeBuild func(ee *edgeEnv, opts []reflect.Value) ([]auth.Plugin, []auth.Option)

// edgeAs converts reflect values to the option type T.
func edgeAs[T any](opts []reflect.Value) []T {
	out := make([]T, len(opts))
	for i, o := range opts {
		out[i] = o.Interface().(T)
	}
	return out
}

func edgeEmail(ee *edgeEnv, opts ...email.Option) *email.Plugin {
	return email.New(append([]email.Option{email.Login(), email.Recover(), email.WithMailer(ee.mail)}, opts...)...)
}

func edgePasswordPlugin(opts ...password.Option) *password.Plugin {
	return password.New(append([]password.Option{password.Argon2(fastArgon2)}, opts...)...)
}

// edgeBase is the base plugin list plus extra.
func edgeBase(ee *edgeEnv, extra ...auth.Plugin) []auth.Plugin {
	return append([]auth.Plugin{edgeEmail(ee), edgePasswordPlugin()}, extra...)
}

// edgeBuilders maps an option type's qualified name to its builder.
var edgeBuilders = map[string]edgeBuild{
	"auth.Option": func(ee *edgeEnv, opts []reflect.Value) ([]auth.Plugin, []auth.Option) {
		return edgeBase(ee), edgeAs[auth.Option](opts)
	},
	"email.Option": func(ee *edgeEnv, opts []reflect.Value) ([]auth.Plugin, []auth.Option) {
		return []auth.Plugin{edgeEmail(ee, edgeAs[email.Option](opts)...), edgePasswordPlugin()}, nil
	},
	"password.Option": func(ee *edgeEnv, opts []reflect.Value) ([]auth.Plugin, []auth.Option) {
		return []auth.Plugin{edgeEmail(ee), edgePasswordPlugin(edgeAs[password.Option](opts)...)}, nil
	},
	"admin.Option": func(ee *edgeEnv, opts []reflect.Value) ([]auth.Plugin, []auth.Option) {
		return edgeBase(ee, admin.New(edgeAs[admin.Option](opts)...)), nil
	},
	"agentauth.Option": func(ee *edgeEnv, opts []reflect.Value) ([]auth.Plugin, []auth.Option) {
		return edgeBase(ee, agentauth.New(edgeAs[agentauth.Option](opts)...)), nil
	},
	"anonymous.Option": func(ee *edgeEnv, opts []reflect.Value) ([]auth.Plugin, []auth.Option) {
		return edgeBase(ee, anonymous.New(edgeAs[anonymous.Option](opts)...)), nil
	},
	"apikey.Option": func(ee *edgeEnv, opts []reflect.Value) ([]auth.Plugin, []auth.Option) {
		return edgeBase(ee, apikey.New(append([]apikey.Option{apikey.Scopes("read")}, edgeAs[apikey.Option](opts)...)...)), nil
	},
	"audit.Option": func(ee *edgeEnv, opts []reflect.Value) ([]auth.Plugin, []auth.Option) {
		return edgeBase(ee, audit.New(edgeAs[audit.Option](opts)...)), nil
	},
	"captcha.Option": func(ee *edgeEnv, opts []reflect.Value) ([]auth.Plugin, []auth.Option) {
		return edgeBase(ee, captcha.New(edgeCaptchaPass, append([]captcha.Option{edgeCaptchaProtect}, edgeAs[captcha.Option](opts)...)...)), nil
	},
	"captcha.ProviderOption": func(ee *edgeEnv, opts []reflect.Value) ([]auth.Plugin, []auth.Option) {
		return edgeBase(ee, captcha.New(captcha.Turnstile("secret", edgeAs[captcha.ProviderOption](opts)...), edgeCaptchaProtect)), nil
	},
	"deviceauth.Option": func(ee *edgeEnv, opts []reflect.Value) ([]auth.Plugin, []auth.Option) {
		return edgeBase(ee, deviceauth.New(edgeAs[deviceauth.Option](opts)...)), nil
	},
	"emailchallenge.Option": func(ee *edgeEnv, opts []reflect.Value) ([]auth.Plugin, []auth.Option) {
		return edgeBase(ee, emailchallenge.New(edgeAs[emailchallenge.Option](opts)...)), nil
	},
	"handoff.Option": func(ee *edgeEnv, opts []reflect.Value) ([]auth.Plugin, []auth.Option) {
		return edgeBase(ee, handoff.New(edgeAs[handoff.Option](opts)...)), nil
	},
	"invite.Option": func(ee *edgeEnv, opts []reflect.Value) ([]auth.Plugin, []auth.Option) {
		return edgeBase(ee, invite.New(edgeAs[invite.Option](opts)...)), nil
	},
	"jwt.Option": func(ee *edgeEnv, opts []reflect.Value) ([]auth.Plugin, []auth.Option) {
		return edgeBase(ee, jwt.New(append([]jwt.Option{jwt.WithSigningKey(ee.sig)}, edgeAs[jwt.Option](opts)...)...)), nil
	},
	"lastlogin.Option": func(ee *edgeEnv, opts []reflect.Value) ([]auth.Plugin, []auth.Option) {
		return edgeBase(ee, lastlogin.New(edgeAs[lastlogin.Option](opts)...)), nil
	},
	"magiclink.Option": func(ee *edgeEnv, opts []reflect.Value) ([]auth.Plugin, []auth.Option) {
		return edgeBase(ee, magiclink.New(edgeAs[magiclink.Option](opts)...)), nil
	},
	"oauth.Option": func(ee *edgeEnv, opts []reflect.Value) ([]auth.Plugin, []auth.Option) {
		return edgeBase(ee, oauth.New(append([]oauth.Option{oauth.WithProviders(oauth.Google("client-id", "client-secret"))}, edgeAs[oauth.Option](opts)...)...)), nil
	},
	"oauthprovider.Option": func(ee *edgeEnv, opts []reflect.Value) ([]auth.Plugin, []auth.Option) {
		return edgeProvider(ee, edgeAs[oauthprovider.Option](opts)...), nil
	},
	"oauthprovider.CIMDOption": func(ee *edgeEnv, opts []reflect.Value) ([]auth.Plugin, []auth.Option) {
		return edgeProvider(ee, oauthprovider.ClientIDMetadataDocuments(edgeAs[oauthprovider.CIMDOption](opts)...)), nil
	},
	"oauthproxy.Option": func(ee *edgeEnv, opts []reflect.Value) ([]auth.Plugin, []auth.Option) {
		proxy := oauthproxy.New(append([]oauthproxy.Option{oauthproxy.ProductionURL(edgeBaseURL)}, edgeAs[oauthproxy.Option](opts)...)...)
		return edgeBase(ee, oauth.New(oauth.WithProviders(proxy.Wrap(oauth.Google("client-id", "client-secret")))), proxy), nil
	},
	"oauthpopup.Option": func(ee *edgeEnv, opts []reflect.Value) ([]auth.Plugin, []auth.Option) {
		return edgeBase(ee, oauth.New(oauth.WithProviders(oauth.Google("client-id", "client-secret"))), oauthpopup.New(edgeAs[oauthpopup.Option](opts)...)), nil
	},
	"organization.Option": func(ee *edgeEnv, opts []reflect.Value) ([]auth.Plugin, []auth.Option) {
		return edgeBase(ee, organization.New(edgeAs[organization.Option](opts)...)), nil
	},
	"passkey.Option": func(ee *edgeEnv, opts []reflect.Value) ([]auth.Plugin, []auth.Option) {
		return edgeBase(ee, passkey.New(edgeAs[passkey.Option](opts)...)), nil
	},
	"phone.Option": func(ee *edgeEnv, opts []reflect.Value) ([]auth.Plugin, []auth.Option) {
		return edgeBase(ee, phone.New(append([]phone.Option{phone.WithSMS(phone.SMSFunc(func(context.Context, string, string) error { return nil }))}, edgeAs[phone.Option](opts)...)...)), nil
	},
	"referral.Option": func(ee *edgeEnv, opts []reflect.Value) ([]auth.Plugin, []auth.Option) {
		return edgeBase(ee, referral.New(edgeAs[referral.Option](opts)...)), nil
	},
	"scim.Option": func(ee *edgeEnv, opts []reflect.Value) ([]auth.Plugin, []auth.Option) {
		return edgeBase(ee, scim.New(append([]scim.Option{edgeSCIMAuth}, edgeAs[scim.Option](opts)...)...)), nil
	},
	"scim.ManagedOption": func(ee *edgeEnv, opts []reflect.Value) ([]auth.Plugin, []auth.Option) {
		return edgeBase(ee, scim.New(edgeSCIMAuth, scim.ManagedConnections(edgeAs[scim.ManagedOption](opts)...))), nil
	},
	"sessiondata.Option": func(ee *edgeEnv, opts []reflect.Value) ([]auth.Plugin, []auth.Option) {
		return edgeBase(ee, sessiondata.New(edgeAs[sessiondata.Option](opts)...)), nil
	},
	"sso.Option": func(ee *edgeEnv, opts []reflect.Value) ([]auth.Plugin, []auth.Option) {
		return edgeBase(ee, sso.New(edgeAs[sso.Option](opts)...)), nil
	},
	"twofactor.Option": func(ee *edgeEnv, opts []reflect.Value) ([]auth.Plugin, []auth.Option) {
		return edgeBase(ee, twofactor.New(append([]twofactor.Option{twofactor.WithEncryptionKey(ee.key)}, edgeAs[twofactor.Option](opts)...)...)), nil
	},
	"username.Option": func(ee *edgeEnv, opts []reflect.Value) ([]auth.Plugin, []auth.Option) {
		return edgeBase(ee, username.New(edgeAs[username.Option](opts)...)), nil
	},
}

// edgeCaptchaProtect guards an operation the basic flow does not call, so
// the provider is built and validated but the flow never reaches it.
var edgeCaptchaProtect = captcha.Protect(password.EndpointForgot)

// edgeCaptchaPass accepts every captcha token.
var edgeCaptchaPass = captcha.VerifierFunc(func(context.Context, string, string) error { return nil })

// edgeSCIMAuth is the least a SCIM endpoint needs: a way to authenticate
// its caller. It is never called.
var edgeSCIMAuth = scim.VerifyBearerToken(func(context.Context, scim.BearerRequest) (scim.Principal, error) {
	return scim.Principal{}, nil
})

// edgeProvider is the OAuth provider with the jwt plugin it signs with.
func edgeProvider(ee *edgeEnv, opts ...oauthprovider.Option) []auth.Plugin {
	jw := jwt.New(jwt.WithSigningKey(ee.sig), jwt.Issuer(edgeBaseURL))
	base := []oauthprovider.Option{oauthprovider.Issuer(edgeBaseURL), oauthprovider.LoginPage("/login"), oauthprovider.ConsentPage("/consent")}
	return edgeBase(ee, jw, oauthprovider.New(jw, append(base, opts...)...))
}

// edgeOwnPath are the option types that do not configure auth.New, and how
// each is checked instead.
var edgeOwnPath = map[string]string{
	"authhttp.Option":    "applied to authhttp.Handler, which then serves a sign-up and a session read",
	"authui.Option":      "applied to authui.Handler, which then serves the sign-in page",
	"authgate.Option":    "applied to authgate.New with a minimal gate, which must refuse naming the option or serve its sign-in route",
	"agentclient.Option": "applied to agentclient.New, which must not panic; the client has no server side to serve",
	"authtest.Option":    "skipped: the test harness fails its test on a bad option (authtest/options_nil_test.go pins nil)",
	"oauthtest.Option":   "skipped: a fake provider for tests; oauthtest/options_nil_test.go pins nil",
	"auth.KindOption":    "takes no parameters, so it has no edge value",
}

// run applies one option value and returns the case's verdict, "" when
// the rule held.
func (ee *edgeEnv) run(name, result string, opt reflect.Value) (verdict string) {
	defer func() {
		if r := recover(); r != nil {
			verdict = fmt.Sprintf("panicked: %v", r)
			if edgeNoErrorPath[result] && edgeNames(name, fmt.Sprint(r)) {
				verdict = ""
			}
		}
	}()
	named := func(err error) bool { return edgeNames(name, err.Error()) }
	switch result {
	case "authhttp.Option", "authui.Option":
		a, err := ee.newAuth(edgeBase(ee), nil)
		if err != nil {
			return "base configuration failed: " + err.Error()
		}
		defer a.Close()
		var h http.Handler
		if result == "authhttp.Option" {
			h = authhttp.Handler(a, opt.Interface().(authhttp.Option))
		} else {
			h = authui.Handler(a, opt.Interface().(authui.Option))
		}
		return edgeServe(h, result)
	case "authgate.Option":
		g, err := authgate.New(authgate.WithProviders(oauth.Google("client-id", "client-secret")), authgate.WithSecret(ee.key), authgate.WithBaseURL(edgeBaseURL), authgate.AllowAnyone(), opt.Interface().(authgate.Option))
		if err != nil {
			if named(err) {
				return ""
			}
			return edgeUnnamed + " (authgate.New): " + err.Error()
		}
		rec := httptest.NewRecorder()
		g.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, edgeBaseURL+"/", nil))
		if rec.Code >= http.StatusInternalServerError {
			return fmt.Sprintf("gate answered %d", rec.Code)
		}
		return ""
	case "agentclient.Option":
		k, err := agentclient.NewKey()
		if err != nil {
			return err.Error()
		}
		agentclient.New(k, opt.Interface().(agentclient.Option))
		return ""
	}
	build, ok := edgeBuilders[result]
	if !ok {
		return "no builder for option type " + result + "; add one to edgeBuilders"
	}
	plugins, opts := build(ee, []reflect.Value{opt})
	a, err := ee.newAuth(plugins, opts)
	if err != nil {
		if named(err) {
			return ""
		}
		return "auth.New refused without naming the option: " + err.Error()
	}
	defer a.Close()
	return ee.basicFlow(a)
}

// edgeNoErrorPath are the option types of packages whose constructors
// return no error (authhttp.Handler, authui.Handler build an
// http.Handler): a programming error there panics at mount, before any
// request, which is their refusal. Such a panic passes when it names the
// option; one that does not, or one during a request, fails.
var edgeNoErrorPath = map[string]bool{"authhttp.Option": true, "authui.Option": true}

// edgeNames reports whether msg names the option, by its qualified or its
// bare name.
func edgeNames(name, msg string) bool {
	short := name[strings.Index(name, ".")+1:]
	m := strings.ToLower(msg)
	return strings.Contains(m, strings.ToLower(short)) || strings.Contains(m, strings.ToLower(name))
}

// newAuth builds and migrates an instance on the env's database.
func (ee *edgeEnv) newAuth(plugins []auth.Plugin, opts []auth.Option) (*auth.Auth, error) {
	all := append([]auth.Option{
		auth.WithDB(ee.db, sqlb.SQLiteDialect{}), auth.WithBaseURL(edgeBaseURL), auth.WithSecret(ee.key),
		auth.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		auth.WithPlugins(plugins...),
	}, opts...)
	a, err := auth.New(all...)
	if err != nil {
		return nil, err
	}
	if _, err := a.Migrate(context.Background()); err != nil {
		_ = a.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return a, nil
}

// basicFlow signs a user up, verifies the address if asked, signs in and
// reads the session back; "" when every step worked and the session lives
// past edgeMinLifetime.
func (ee *edgeEnv) basicFlow(a *auth.Auth) string {
	pw, ok := edgeFind[*password.Plugin](a)
	if !ok {
		return "no password plugin wired"
	}
	addr := fmt.Sprintf("edge%d@example.test", edgeDBCount.Add(1))
	up, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: addr, Password: edgePassword, Name: "Edge"})
	if err != nil {
		return "sign-up failed: " + err.Error()
	}
	tok := up.Token
	if tok == "" {
		a.WaitDeliveries()
		ee.mail.mu.Lock()
		m := edgeTokenInLink.FindStringSubmatch(ee.mail.last.Text)
		ee.mail.mu.Unlock()
		em, ok := edgeFind[*email.Plugin](a)
		if m == nil || !ok {
			return "sign-up asked for verification and mailed no link"
		}
		if _, err := em.Verify(anon(a), auth.Token(m[1])); err != nil {
			return "verify failed: " + err.Error()
		}
	}
	in, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: addr, Password: edgePassword})
	if err != nil {
		return "sign-in failed: " + err.Error()
	}
	if in.SecondFactorRequired {
		return ""
	}
	s, _, _, err := a.ResolveSession(context.Background(), in.Token)
	if err != nil {
		return "session read failed: " + err.Error()
	}
	if left := time.Until(s.ExpiresAt); left < edgeMinLifetime {
		return fmt.Sprintf("the session expires in %v: a zero-lifetime surprise", left)
	}
	return ""
}

// edgeFind returns the wired plugin of type P.
func edgeFind[P auth.Plugin](a *auth.Auth) (P, bool) {
	for _, p := range a.Plugins() {
		if x, ok := p.(P); ok {
			return x, true
		}
	}
	var zero P
	return zero, false
}

// edgeServe sends a sign-up and a session read through h; "" when neither
// panics nor answers 500.
func edgeServe(h http.Handler, kind string) string {
	reqs := []*http.Request{httptest.NewRequest(http.MethodGet, edgeBaseURL+"/", nil)}
	if kind == "authhttp.Option" {
		up := httptest.NewRequest(http.MethodPost, edgeBaseURL+"/password/sign-up", strings.NewReader(`{"identifier":"serve@example.test","password":"`+edgePassword+`","name":"Serve"}`))
		up.Header.Set("Content-Type", "application/json")
		up.Header.Set("Origin", edgeBaseURL)
		reqs = []*http.Request{up, httptest.NewRequest(http.MethodGet, edgeBaseURL+"/session", nil)}
	}
	for _, r := range reqs {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code >= http.StatusInternalServerError {
			return fmt.Sprintf("%s %s answered %d: %s", r.Method, r.URL.Path, rec.Code, rec.Body.String())
		}
	}
	return ""
}

// TestConfigEdge runs every option's edge cases; see the top of this file.
func TestConfigEdge(t *testing.T) {
	found := discoverOptions(t)
	if len(found) < 500 {
		t.Fatalf("discovered %d option constructors; the walk is broken (571 on 2026-10-09)", len(found))
	}
	seen := map[string]bool{}
	var missing []string
	for _, o := range found {
		seen[o.name] = true
		if _, skip := edgeNotImported[o.importPath]; skip {
			continue
		}
		if _, ok := edgeRegistry[o.name]; !ok {
			missing = append(missing, fmt.Sprintf("\t%q: %s,", o.name, o.name))
		}
	}
	if len(missing) > 0 {
		t.Errorf("options missing from edgeRegistry (configedge_registry_test.go); add:\n%s", strings.Join(missing, "\n"))
	}
	for name := range edgeRegistry {
		if !seen[name] {
			t.Errorf("edgeRegistry names %s, which the source no longer declares; remove it", name)
		}
	}
	results := map[string]string{}
	for _, o := range found {
		results[o.name] = o.result
	}
	names := make([]string, 0, len(edgeRegistry))
	for n := range edgeRegistry {
		names = append(names, n)
	}
	sort.Strings(names)
	var cases, options int
	unnamedSeen := map[string]bool{}
	for _, name := range names {
		result := results[name]
		if strings.HasPrefix(edgeOwnPath[result], "skipped") {
			continue
		}
		ee := newEdgeEnv(t)
		fn := reflect.ValueOf(edgeRegistry[name])
		cs := edgeCases(fn, edgeKnown(ee.db))
		if len(cs) > 0 {
			options++
		}
		for _, c := range cs {
			cases++
			if _, ok := edgeExempt[name+":"+c.label]; ok {
				continue
			}
			if _, ok := edgeExempt[name]; ok {
				continue
			}
			var opt reflect.Value
			built := true
			verdict := func() (v string) {
				defer func() {
					if r := recover(); r != nil {
						built = false
						v = fmt.Sprintf("the constructor panicked: %v", r)
						if edgeNoErrorPath[result] && edgeNames(name, fmt.Sprint(r)) {
							v = ""
						}
					}
				}()
				opt = fn.Call(c.args)[0]
				return ""
			}()
			if verdict == "" && built {
				verdict = newEdgeEnv(t).run(name, result, opt)
			}
			if strings.Contains(verdict, edgeUnnamed) && edgeUnnamedRefusals[name] {
				unnamedSeen[name] = true
				continue
			}
			if verdict != "" {
				t.Errorf("%s (%s): %s", name, c.label, verdict)
			}
		}
	}
	for n := range edgeUnnamedRefusals {
		if !unnamedSeen[n] {
			t.Errorf("edgeUnnamedRefusals names %s, whose refusals now name the option (or are gone); remove it", n)
		}
	}
	t.Logf("config edge: %d edge cases over %d options with an edge-valued parameter (%d registered)", cases, options, len(edgeRegistry))
}
