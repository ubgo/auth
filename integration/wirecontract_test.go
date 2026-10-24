package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/admin"
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
	"github.com/ubgo/auth/plugin/metadata"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/oauthprovider"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/passkey"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/phone"
	"github.com/ubgo/auth/plugin/pow"
	"github.com/ubgo/auth/plugin/referral"
	"github.com/ubgo/auth/plugin/terms"
	"github.com/ubgo/auth/plugin/twofactor"
	"github.com/ubgo/auth/plugin/username"
)

// The wire contract: every operation an Auth with every built-in plugin
// exposes is sent through the real authhttp handler, the way a typed client
// sends it, and three rules hold for every answer.
//
//  1. A request a typed client may legally send is never refused because the
//     transport could not decode it: no 400 auth.bad_request before the
//     input was decoded, no 404 or 405 for a route the operation list names.
//  2. No answer is a 500.
//  3. No JSON answer and no request a Go type encodes carries "[redacted]",
//     the text an auth.Token writes in JSON.
//
// Why: the unit and integration suites call the typed Go API with sensible
// values, so a defect that lives only on the wire (a token encoded as
// "[redacted]", ?limit= refused for a field without `,string`, a 500 from a
// default setting) passed a 99.5% coverage suite. This test sees the class,
// not the instance: it discovers the operations from a.Operations() and
// builds each input from its Go type, so an operation added tomorrow is
// probed with no edit here.
//
// Classifying a 400: the decode step and an operation's own refusal both
// answer auth.bad_request, so the status alone cannot tell them apart. An
// app-level Finally hook sees every call; the pipeline gives it c.Input nil
// when the call was refused before its input was decoded, so "bad_request
// with no input" is exactly a decode failure.

// wireRedacted is what an auth.Token writes in JSON.
const wireRedacted = "[redacted]"

// wirePassword is the main user's password: long enough for the default
// policy, and what every password field of a generic probe carries, so
// password.verify and password.change succeed for the main user.
const wirePassword = "correct horse battery staple 9"

// wirePasswordNext is the password password.change and password.reset set.
const wirePasswordNext = "another horse battery staple 7"

// wireSweepPasses is how many times the generic sweep walks the operation
// list: the second pass fills inputs with ids the first pass's answers
// carried (an API key created in pass one is read in pass two).
const wireSweepPasses = 2

// wireMinOperations is a floor on the operation count, so a wiring change
// that registers nothing makes the test fail instead of pass vacuously
// (185 HTTP operations on 2026-10-09).
const wireMinOperations = 150

// wireLastOps run after every other operation of a pass, because they end
// the main user's account or sessions, or remove the organization and team
// the other probes work on; the order inside the list is the order they
// run in.
var wireLastOps = []auth.EndpointID{
	// These remove what the flows built and the later probes read.
	"organization.remove-team",
	"organization.delete",
	"core.sign-out-all",
	"core.account-delete",
}

// wireGETUnflattened are query fields a probe does not put in the query
// string because their type has no one-value text form; each is a defect
// candidate, so the list is reported and pinned in wireQueryShapeAllowed.
// A query input should be flat strings, numbers and bools.
var wireQueryShapeAllowed = map[string]string{}

// wireOutcome is what the probes saw for one operation.
type wireOutcome struct {
	op auth.Operation
	// ok is true once any call answered 2xx or 3xx.
	ok bool
	// answers counts the answers by "<status> <code>", for the report.
	answers map[string]int
}

// wireWorld is one engine's fully wired library, its handler and what the
// probes learned.
type wireWorld struct {
	t       *testing.T
	e       *authtest.Env
	inner   http.Handler
	routes  map[string]auth.Operation
	ad      *admin.Plugin
	tfKey   []byte
	mu      sync.Mutex
	last    wireFinally
	results map[auth.EndpointID]*wireOutcome
	// pool holds values answers carried, by lower-cased JSON key, so a
	// later input field of the same name gets a real id.
	pool map[string]string
	// pinned keys keep the value the test set (the admin's target user),
	// whatever an answer carries.
	pinned map[string]bool
	seq    int
	mainID string
	// mainEmail is the probing user's address. Every "userId" field
	// targets a fresh user instead (sweep), so an admin probe never bans
	// its own caller.
	mainEmail string
	// tfUserID has a confirmed authenticator; tfSecret is its key.
	tfUserID string
	tfSecret string
	// powInstead swaps the captcha plugin for proof of work: both are rate
	// challengers and auth.New refuses two, so each is walked in a world of
	// its own.
	powInstead bool
}

// wireFinally is what the Finally hook saw for the last call.
type wireFinally struct {
	id      auth.EndpointID
	decoded bool
	err     error
}

// wirePlugins is every built-in plugin with the least configuration that
// passes its Validate, as integration/cmd/apiref wires them for the
// reference, but with the Env's recorders and fast hashing.
func (w *wireWorld) plugins(e *authtest.Env) []auth.Plugin {
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		w.t.Fatal(err)
	}
	// The template is named what textValue writes into an unpooled field,
	// so jwt.template is driven to a signed token.
	jw := jwt.New(jwt.WithSigningKey(signing), jwt.Issuer(authtest.BaseURL), jwt.WithTemplate("probe", jwt.Template{}))
	w.ad = admin.New()
	// passkey's security-key store gives twofactor its security-key routes.
	// The enrolment rule names nobody, so the walk's sessions carry no
	// setup-mfa task that would answer 403 for every other operation.
	pk := passkey.New(passkey.WithSignUp())
	noEnrolment := func(context.Context, *auth.Auth, string) (bool, error) { return false, nil }
	return []auth.Plugin{
		email.New(email.Login(), email.Recover(), email.Multiple(), email.SignInWithCode(), email.VerifyByCode(), email.WithMailer(e.Mail)),
		phone.New(phone.Login(), phone.Recover(), phone.Multiple(), phone.SignInWithCode(), phone.WithSMS(e.SMS)),
		username.New(username.Login()),
		password.New(password.Argon2(fastArgon2)),
		oauth.New(oauth.WithProviders(oauth.Google("client-id", "client-secret"), oauth.GitHub("client-id", "client-secret")), oauth.StoreTokens(), oauth.ExposeAccessTokens()),
		twofactor.New(twofactor.WithEncryptionKey(w.tfKey), twofactor.DeliveredCodes(), twofactor.TrustDevices(0), twofactor.ReadableTOTPURI(), twofactor.RecoveryCodeStorage(twofactor.StoreEncrypted),
			twofactor.WithSecurityKeys(pk.SecurityKeys()), twofactor.RequireEnrolment(noEnrolment)),
		pk,
		magiclink.New(),
		w.ad,
		audit.New(),
		apikey.New(apikey.Scopes("read")),
		jw,
		oauthprovider.New(jw, oauthprovider.Issuer(authtest.BaseURL), oauthprovider.LoginPage("/login"), oauthprovider.ConsentPage("/consent")),
		terms.New(terms.Current("2026-01")),
		anonymous.New(),
		handoff.New(),
		deviceauth.New(),
		lastlogin.New(),
		w.challenger(),
		// The domain verifier proves nothing, so the walk covers the domain
		// operations without a DNS lookup.
		organization.New(organization.Teams(organization.TeamsConfig{}), organization.DynamicRoles(organization.DynamicRolesConfig{}),
			organization.Domains(organization.DomainsConfig{Verifier: organization.DomainVerifierFunc(func(context.Context, organization.DomainChallenge) (bool, error) { return false, nil })})),
		emailchallenge.New(),
		invite.New(),
		referral.New(),
		metadata.New(metadata.WithAdmin(metadata.AuthorizerFunc(func(context.Context, metadata.AccessRequest) (bool, error) { return true, nil }))),
	}
}

// challenger is the rate challenger of the world: a captcha with a verifier
// that accepts every token, the token header set on every request
// (ServeHTTP) because the provider is not under test and a refused captcha
// would hide every sign-up behind it; or, in the proof-of-work world, the
// proof-of-work plugin.
func (w *wireWorld) challenger() auth.Plugin {
	if w.powInstead {
		return pow.New()
	}
	return captcha.New(captcha.VerifierFunc(func(context.Context, string, string) error { return nil }))
}

// newWireWorld wires every plugin on the engine's database.
func newWireWorld(t *testing.T, e *env, powInstead bool) *wireWorld {
	w := &wireWorld{powInstead: powInstead, t: t, results: map[auth.EndpointID]*wireOutcome{}, pool: map[string]string{}, pinned: map[string]bool{}, routes: map[string]auth.Operation{}}
	w.tfKey = make([]byte, 32)
	if _, err := rand.Read(w.tfKey); err != nil {
		t.Fatal(err)
	}
	secretKey := make([]byte, auth.MinSecretSize)
	if _, err := rand.Read(secretKey); err != nil {
		t.Fatal(err)
	}
	hook := auth.OperationHook{Finally: func(_ context.Context, c *auth.Call, err error) {
		w.mu.Lock()
		w.last = wireFinally{id: c.Op.ID, decoded: c.Input != nil, err: err}
		w.mu.Unlock()
	}}
	w.e = authtest.New(t, authtest.WithDB(e.db, e.d), authtest.WithPlugins(w.plugins), authtest.WithOptions(
		auth.WithTablePrefix(tablePrefix()), auth.WithSecret(secretKey),
		auth.WithAccountDeletion(auth.AccountDeletion{}), auth.WithMultiSession(0), auth.WithDeferredSessionRefresh(),
		auth.WithOperationHooks(hook),
		// Hundreds of calls from one address: the per-IP rules would turn
		// most of them into 429s, which prove nothing about the wire.
		auth.WithRateExempt(func(context.Context, *auth.Call) bool { return true }),
	))
	w.inner = authhttp.Handler(w.e.Auth, authhttp.Prefix("/auth"))
	for _, op := range w.e.Auth.Operations() {
		w.routes[authhttp.MethodOf(op.Info().Kind)+" /auth"+op.Route()] = op
		w.results[op.Info().ID] = &wireOutcome{op: op, answers: map[string]int{}}
	}
	if len(w.routes) < wireMinOperations {
		t.Fatalf("%d operations wired, want at least %d: the wiring is broken", len(w.routes), wireMinOperations)
	}
	return w
}

// ServeHTTP serves the request through the library's handler and judges
// the answer by the three rules. Every request of every flow passes here.
func (w *wireWorld) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	w.mu.Lock()
	w.last = wireFinally{}
	w.mu.Unlock()
	if r.Header.Get(captcha.TokenHeader) == "" {
		r.Header.Set(captcha.TokenHeader, "probe")
	}
	rec := httptest.NewRecorder()
	w.inner.ServeHTTP(rec, r)
	for k, v := range rec.Header() {
		rw.Header()[k] = v
	}
	rw.WriteHeader(rec.Code)
	_, _ = rw.Write(rec.Body.Bytes())
	w.judge(r, rec)
}

// wireErrorBody is the error answer's shape.
type wireErrorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// judge applies the three rules to one answer and records it.
func (w *wireWorld) judge(r *http.Request, rec *httptest.ResponseRecorder) {
	t := w.t
	t.Helper()
	key := r.Method + " " + r.URL.Path
	op, known := w.routes[key]
	w.mu.Lock()
	fin := w.last
	w.mu.Unlock()
	var eb wireErrorBody
	_ = json.Unmarshal(rec.Body.Bytes(), &eb)
	where := key
	if known {
		where = string(op.Info().ID) + " (" + key + ")"
	}
	body := strings.TrimSpace(rec.Body.String())
	if rec.Code >= http.StatusInternalServerError {
		t.Errorf("wire: %s answered %d to a well-formed request: %s (finally err: %v)", where, rec.Code, body, fin.err)
	}
	if !known {
		return
	}
	res := w.results[op.Info().ID]
	w.mu.Lock()
	res.answers[strconv.Itoa(rec.Code)+" "+eb.Error.Code]++
	w.mu.Unlock()
	switch {
	case rec.Code < http.StatusBadRequest:
		res.ok = true
		if strings.Contains(rec.Header().Get("Content-Type"), "json") {
			var v any
			if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
				t.Errorf("wire: %s answered %d with a body that is not JSON: %v", where, rec.Code, err)
				return
			}
			if p := findRedacted(v, ""); p != "" {
				t.Errorf("wire: %s answered %q at %s: an auth.Token reached the response; use auth.WireToken", where, wireRedacted, p)
			}
			w.harvest(v, "")
		}
	case rec.Code == http.StatusBadRequest && eb.Error.Code == auth.ErrBadRequest.Code && fin.id == op.Info().ID && !fin.decoded:
		t.Errorf("wire: %s refused its input before decoding it (a transport decode failure): %s", where, body)
	case rec.Code == http.StatusNotFound && eb.Error.Code == auth.ErrUnknownOperation.Code, rec.Code == http.StatusMethodNotAllowed:
		t.Errorf("wire: %s is in the operation list but the handler answered %d %s", where, rec.Code, eb.Error.Code)
	}
}

// findRedacted returns the JSON path of the first string equal to
// wireRedacted in v, or "".
func findRedacted(v any, path string) string {
	switch x := v.(type) {
	case string:
		if x == wireRedacted {
			if path == "" {
				return "(the body)"
			}
			return path
		}
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if p := findRedacted(x[k], joinJSON(path, k)); p != "" {
				return p
			}
		}
	case []any:
		for i, e := range x {
			if p := findRedacted(e, path+"["+strconv.Itoa(i)+"]"); p != "" {
				return p
			}
		}
	}
	return ""
}

func joinJSON(path, k string) string {
	if path == "" {
		return k
	}
	return path + "." + k
}

// harvest records the string and number leaves of an answer by key, and an
// "id" inside an object under key X also as "xid", so a later input field
// named organizationId receives the organization an earlier answer made.
func (w *wireWorld) harvest(v any, parent string) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			lk := strings.ToLower(k)
			var s string
			switch leaf := val.(type) {
			case string:
				s = leaf
			case float64:
				s = strconv.FormatFloat(leaf, 'f', -1, 64)
			default:
				w.harvest(val, lk)
				continue
			}
			if s == "" {
				continue
			}
			w.put(lk, s)
			if lk == "id" && parent != "" {
				w.put(strings.TrimSuffix(parent, "s")+"id", s)
			}
		}
	case []any:
		for _, e := range x {
			w.harvest(e, parent)
		}
	}
}

func (w *wireWorld) put(k, v string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.pinned[k] {
		w.pool[k] = v
	}
}

func (w *wireWorld) pin(k, v string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pool[k], w.pinned[k] = v, true
}

func (w *wireWorld) pooled(k string) (string, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	v, ok := w.pool[k]
	return v, ok
}

// next returns a number unique within the world, for fresh addresses.
func (w *wireWorld) next() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.seq++
	return w.seq
}

// wireMaxDepth bounds how deep the input builder follows nested types.
const wireMaxDepth = 6

// textValue is the plausible text a typed client would put in a field
// named name: a value earlier answers carried under that name, else a
// value shaped by the name.
func (w *wireWorld) textValue(name string) string {
	n := strings.ToLower(name)
	if v, ok := w.pooled(n); ok {
		return v
	}
	switch {
	case strings.Contains(n, "password") || n == "secret" || n == "current" || n == "new":
		return wirePassword
	case strings.Contains(n, "email") || n == "identifier" || n == "to" || n == "address":
		return fmt.Sprintf("probe%d@example.test", w.next())
	case strings.Contains(n, "phone") || n == "number":
		return fmt.Sprintf("+1415555%04d", w.next()%10000)
	case n == "username" || n == "handle":
		return fmt.Sprintf("probe%d", w.next())
	case n == "slug":
		return fmt.Sprintf("probe-%d", w.next())
	case n == "domain":
		return fmt.Sprintf("probe%d.example.com", w.next())
	case n == "enrollmentmode":
		return "manual_invitation"
	case strings.Contains(n, "redirect") || strings.Contains(n, "return") || strings.Contains(n, "callback") || n == "next":
		// A return address is a path on the app: an absolute URL is
		// refused unless the app trusts its origin.
		return "/done"
	case strings.Contains(n, "url") || strings.Contains(n, "uri"):
		return authtest.BaseURL + "/done"
	case n == "code" || strings.HasSuffix(n, "code"):
		return "000000"
	case n == "locale" || n == "lang":
		return "en"
	case n == "role":
		return "member"
	case n == "scope" || n == "scopes":
		return "read"
	case strings.Contains(n, "name") || n == "title":
		return "Probe"
	}
	return "probe"
}

// build returns a plausible value of type t for a field named name: what
// a typed client fills in. Interfaces stay nil, a type with its own JSON
// encoding that is not text stays zero, and recursion stops at
// wireMaxDepth.
func (w *wireWorld) build(t reflect.Type, name string, depth int, minimal bool) reflect.Value {
	v := reflect.New(t).Elem()
	if depth > wireMaxDepth {
		return v
	}
	if minimal {
		return w.buildMinimal(t, name, depth)
	}
	if t == reflect.TypeFor[time.Time]() {
		v.Set(reflect.ValueOf(w.e.Clock.Now().Add(time.Hour)))
		return v
	}
	switch t.Kind() {
	case reflect.String:
		v.SetString(w.textValue(name))
		return v
	case reflect.Bool:
		v.SetBool(true)
		return v
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(1)
		return v
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(1)
		return v
	case reflect.Float32, reflect.Float64:
		v.SetFloat(1)
		return v
	}
	// Raw JSON is a document the client writes itself; an object is what
	// every such field takes (metadata, patches).
	if t == reflect.TypeFor[json.RawMessage]() {
		v.SetBytes([]byte("{}"))
		return v
	}
	if t.Implements(wireJSONMarshaler) || reflect.PointerTo(t).Implements(wireJSONMarshaler) {
		return v
	}
	switch t.Kind() {
	case reflect.Pointer:
		v.Set(w.build(t.Elem(), name, depth+1, false).Addr())
	case reflect.Slice:
		s := reflect.MakeSlice(t, 1, 1)
		s.Index(0).Set(w.build(t.Elem(), strings.TrimSuffix(name, "s"), depth+1, false))
		v.Set(s)
	case reflect.Array:
		for i := range t.Len() {
			v.Index(i).Set(w.build(t.Elem(), name, depth+1, false))
		}
	case reflect.Map:
		if t.Key().Kind() == reflect.String {
			m := reflect.MakeMap(t)
			m.SetMapIndex(reflect.ValueOf("probe").Convert(t.Key()), w.build(t.Elem(), "probe", depth+1, false))
			v.Set(m)
		}
	case reflect.Struct:
		for i := range t.NumField() {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			jn, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if jn == "-" {
				continue
			}
			if jn == "" {
				jn = f.Name
			}
			v.Field(i).Set(w.build(f.Type, jn, depth+1, false))
		}
	}
	return v
}

var wireJSONMarshaler = reflect.TypeFor[json.Marshaler]()

// buildMinimal is the other input a probe sends: the zero value, except
// that a string field whose name an earlier answer carried (an id) gets
// that value, so the least a client can send is probed too. Many inputs
// succeed only this way: a sort, a role or a filter left empty takes its
// default, where any plausible text is refused as unknown.
func (w *wireWorld) buildMinimal(t reflect.Type, name string, depth int) reflect.Value {
	v := reflect.New(t).Elem()
	if depth > wireMaxDepth {
		return v
	}
	switch t.Kind() {
	case reflect.String:
		if s, ok := w.pooled(strings.ToLower(name)); ok {
			v.SetString(s)
		}
	case reflect.Struct:
		if t == reflect.TypeFor[time.Time]() {
			return v
		}
		for i := range t.NumField() {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			jn, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if jn == "-" {
				continue
			}
			if jn == "" {
				if f.Anonymous {
					v.Field(i).Set(w.buildMinimal(f.Type, "", depth+1))
					continue
				}
				jn = f.Name
			}
			v.Field(i).Set(w.buildMinimal(f.Type, jn, depth+1))
		}
	}
	return v
}

// encodeJSON writes v the way a typed client in another language would:
// encoding/json's names and shapes, except that a string-kinded type with
// its own MarshalJSON (auth.Token, which hides itself on purpose, as the
// password field does) is written as its text. A client sends the password
// it holds, not the placeholder a Go log line shows.
func encodeJSON(v reflect.Value) any {
	if !v.IsValid() {
		return nil
	}
	t := v.Type()
	if t.Kind() == reflect.String {
		return v.String()
	}
	if t.Implements(wireJSONMarshaler) {
		b, err := json.Marshal(v.Interface())
		if err != nil {
			return nil
		}
		return json.RawMessage(b)
	}
	switch t.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return nil
		}
		return encodeJSON(v.Elem())
	case reflect.Slice:
		if v.IsNil() {
			return nil
		}
		if t.Elem().Kind() == reflect.Uint8 {
			return v.Bytes()
		}
		fallthrough
	case reflect.Array:
		out := make([]any, v.Len())
		for i := range v.Len() {
			out[i] = encodeJSON(v.Index(i))
		}
		return out
	case reflect.Map:
		if v.IsNil() {
			return nil
		}
		out := map[string]any{}
		iter := v.MapRange()
		for iter.Next() {
			out[fmt.Sprint(iter.Key().Interface())] = encodeJSON(iter.Value())
		}
		return out
	case reflect.Struct:
		out := map[string]any{}
		encodeFields(v, out)
		return out
	}
	return v.Interface()
}

// encodeFields writes a struct's exported fields into out, lifting an
// untagged embedded struct's fields as encoding/json does.
func encodeFields(v reflect.Value, out map[string]any) {
	t := v.Type()
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() && !f.Anonymous {
			continue
		}
		jn, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
		if jn == "-" {
			continue
		}
		fv := v.Field(i)
		if f.Anonymous && jn == "" {
			ev := fv
			if ev.Kind() == reflect.Pointer {
				if ev.IsNil() {
					continue
				}
				ev = ev.Elem()
			}
			if ev.Kind() == reflect.Struct {
				encodeFields(ev, out)
				continue
			}
		}
		if !f.IsExported() {
			continue
		}
		if jn == "" {
			jn = f.Name
		}
		val := encodeJSON(fv)
		if strings.Contains(opts, "string") {
			val = fmt.Sprint(val)
		}
		out[jn] = val
	}
}

// queryString writes a query input as the flat query string a client
// sends: every top-level field with a one-value text form, numbers and
// bools included. A field with no such form (an object, a list) cannot be
// sent in a query and is returned in skipped.
func queryString(v reflect.Value) (q url.Values, skipped []string) {
	q = url.Values{}
	enc, ok := encodeJSON(v).(map[string]any)
	if !ok {
		return q, nil
	}
	for k, val := range enc {
		switch x := val.(type) {
		case nil:
		case string:
			q.Set(k, x)
		case bool:
			q.Set(k, strconv.FormatBool(x))
		case json.RawMessage:
			var s string
			if json.Unmarshal(x, &s) == nil {
				q.Set(k, s)
			} else if string(x) != "null" {
				skipped = append(skipped, k)
			}
		default:
			rv := reflect.ValueOf(val)
			switch rv.Kind() {
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
				reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
				reflect.Float32, reflect.Float64:
				q.Set(k, fmt.Sprint(val))
			default:
				skipped = append(skipped, k)
			}
		}
	}
	sort.Strings(skipped)
	return q, skipped
}

// browser returns a browser over the judged handler holding a fresh,
// fresh-signed-in session of userID; "" for a signed-out browser.
func (w *wireWorld) browser(userID string) *authtest.Browser {
	b := w.e.Browser(w)
	if userID != "" {
		b.SetSession(w.e.SignIn(userID))
	}
	return b
}

// probe sends op the input built from its Go type, as b.
func (w *wireWorld) probe(b *authtest.Browser, op auth.Operation, minimal bool) *authtest.Response {
	in := w.build(op.InputType(), "", 0, minimal)
	path := "/auth" + op.Route()
	if op.Info().Kind == auth.Query {
		q, skipped := queryString(in)
		for _, s := range skipped {
			key := string(op.Info().ID) + "." + s
			if _, ok := wireQueryShapeAllowed[key]; !ok {
				w.t.Errorf("wire: query %s has input field %q with no query-string form; a GET input must be flat", op.Info().ID, s)
			}
		}
		if len(q) > 0 {
			path += "?" + q.Encode()
		}
		return b.Get(path)
	}
	return b.Post(path, encodeJSON(in))
}

// sweep probes every operation once, each from a fresh session of the
// main user (a pending one for the operations that need it). The
// operations in wireLastOps run only on the final pass, after every other
// one, because they end the main user's account or sessions.
func (w *wireWorld) sweep(final bool) {
	last := map[auth.EndpointID]int{}
	for i, id := range wireLastOps {
		last[id] = i + 1
	}
	ops := w.e.Auth.Operations()
	sort.SliceStable(ops, func(i, j int) bool { return last[ops[i].Info().ID] < last[ops[j].Info().ID] })
	for _, op := range ops {
		if last[op.Info().ID] > 0 && !final {
			continue
		}
		for _, minimal := range []bool{true, false} {
			if _, err := w.e.Auth.User(context.Background(), w.mainID); err != nil {
				// core.account-delete succeeded on the first variant.
				break
			}
			// A fresh target per call: an admin probe that bans its
			// target or makes it an admin must not change what the next
			// probe finds.
			w.pin("userid", w.e.CreateUser("Victim", authtest.Identity{Kind: email.KindEmail, Value: fmt.Sprintf("victim%d@example.test", w.next())}).ID)
			var b *authtest.Browser
			switch op.Info().Require {
			case auth.PendingSecondFactor:
				b = w.pendingBrowser()
			default:
				b = w.browser(w.mainID)
			}
			w.probe(b, op, minimal)
			if !final {
				for _, id := range []string{w.mainID, w.tfUserID} {
					if _, err := w.e.Auth.User(context.Background(), id); err != nil {
						w.t.Fatalf("wire: probing %s (minimal %v) removed user %s (%v); add it to wireLastOps", op.Info().ID, minimal, id, err)
					}
				}
			}
		}
	}
}

// report logs the operations no call drove to success, with what they
// answered, so the coverage of the redacted-token rule is visible.
func (w *wireWorld) report() (ok, total int) {
	var missed []string
	for id, r := range w.results {
		total++
		if r.ok {
			ok++
			continue
		}
		var answers []string
		for a, n := range r.answers {
			answers = append(answers, fmt.Sprintf("%s x%d", a, n))
		}
		sort.Strings(answers)
		missed = append(missed, fmt.Sprintf("%s: %s", id, strings.Join(answers, ", ")))
	}
	sort.Strings(missed)
	w.t.Logf("wire: %d of %d operations answered success at least once; not driven to success:\n  %s", ok, total, strings.Join(missed, "\n  "))
	return ok, total
}

// errWireFlow marks a scripted step that did not go as the flow expects.
var errWireFlow = errors.New("wire flow step failed")

// TestWireContract walks every operation through the HTTP handler on every
// engine; see the comment at the top of this file.
func TestWireContract(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newWireWorld(t, e, false)
		w.flows()
		for i := range wireSweepPasses {
			w.sweep(i == wireSweepPasses-1)
		}
		ok, total := w.report()
		if ok < wireMinSuccess {
			t.Errorf("wire: only %d of %d operations reached success; the probes or the flows regressed (floor %d)", ok, total, wireMinSuccess)
		}
	})
}

// TestWireContract_ProofOfWork walks the same operations with proof of work as
// the rate challenger instead of the captcha, and requires its challenge
// route to answer a client.
func TestWireContract_ProofOfWork(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newWireWorld(t, e, true)
		w.flows()
		for i := range wireSweepPasses {
			w.sweep(i == wireSweepPasses-1)
		}
		ok, total := w.report()
		if ok < wireMinSuccess {
			t.Errorf("wire: only %d of %d operations reached success (floor %d)", ok, total, wireMinSuccess)
		}
		if r := w.results[pow.EndpointChallenge]; r == nil || !r.ok {
			t.Errorf("%s never answered success: %+v", pow.EndpointChallenge, r)
		}
	})
}

// wireMinSuccess is a floor on the operations driven to success, set just
// under what the probes and flows reach today, so the redacted-token rule
// keeps its coverage (148 of 185 on SQLite, 2026-10-09).
const wireMinSuccess = 140
