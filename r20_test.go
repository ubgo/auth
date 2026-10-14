package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/verificationtest"
)

// Round 20: better-auth's escape hatches (disableCSRFCheck,
// disableOriginCheck) as opt-ins, and verification tokens in a pluggable
// store.

// logged builds an Auth with opts and returns what New logged.
func logged(t *testing.T, opts ...auth.Option) (*auth.Auth, string) {
	t.Helper()
	var buf bytes.Buffer
	a, err := newAuth(append(opts, auth.WithLogger(slog.New(slog.NewTextHandler(&buf, nil))))...)
	if err != nil {
		t.Fatal(err)
	}
	return a, buf.String()
}

func TestWithoutCSRFCheck(t *testing.T) {
	cross := auth.Request{Transport: auth.TransportHTTP, Client: auth.Client{FetchSite: auth.FetchSiteCrossSite, Origin: "https://evil.example"}}
	cookie := auth.Request{Transport: auth.TransportHTTP, Credential: auth.CredentialCookie, Token: "t", Client: auth.Client{Origin: "https://evil.example"}}

	// Off by default: both refused, and nothing is logged about it.
	p := newTestPlugin()
	a, log := logged(t, auth.WithPlugins(p), auth.WithFetchMetadata())
	if strings.Contains(log, auth.WarnCSRFCheckOff) {
		t.Fatalf("warned with the check on: %s", log)
	}
	for _, req := range []auth.Request{cross, cookie} {
		if _, err := p.echo.Call(a.WithRequest(context.Background(), req), echoIn{Text: "x"}); !errors.Is(err, auth.ErrOriginNotTrusted) {
			t.Fatalf("default: %v, want ErrOriginNotTrusted", err)
		}
	}

	// On: neither is refused for its origin, and New warns.
	p = newTestPlugin()
	a, log = logged(t, auth.WithPlugins(p), auth.WithFetchMetadata(), auth.WithoutCSRFCheck())
	if !strings.Contains(log, "level=WARN") || !strings.Contains(log, auth.WarnCSRFCheckOff) {
		t.Fatalf("no start-up warning: %q", log)
	}
	if _, err := p.echo.Call(a.WithRequest(context.Background(), cross), echoIn{Text: "x"}); err != nil {
		t.Fatalf("cross-site mutation with the check off: %v", err)
	}
	if _, err := p.echo.Call(a.WithRequest(context.Background(), cookie), echoIn{Text: "x"}); errors.Is(err, auth.ErrOriginNotTrusted) {
		t.Fatal("a cookie mutation from an untrusted origin was refused with the check off")
	}
	// Return URLs are not its business.
	if a.TrustsReturnURL("https://evil.example/x") {
		t.Fatal("WithoutCSRFCheck opened return URLs")
	}
}

func TestWithoutOriginCheck(t *testing.T) {
	a, log := logged(t, auth.WithPlugins(signIn{on: true}))
	if strings.Contains(log, auth.WarnOriginCheckOff) || a.TrustsReturnURL("https://evil.example/x") {
		t.Fatalf("default: warned %q or trusted an untrusted origin", log)
	}
	a, log = logged(t, auth.WithPlugins(signIn{on: true}), auth.WithoutOriginCheck())
	if !strings.Contains(log, "level=WARN") || !strings.Contains(log, auth.WarnOriginCheckOff) {
		t.Fatalf("no start-up warning: %q", log)
	}
	for _, ok := range []string{"https://evil.example/x", "//evil.example", "/path", "myapp://cb", "http://10.0.0.1:9/x"} {
		if !a.TrustsReturnURL(ok) {
			t.Errorf("%q refused with the check off", ok)
		}
	}
	for _, bad := range []string{"", "/a\r\nSet-Cookie: x=1", "https://e.example/\n", "/\\evil.example"} {
		if a.TrustsReturnURL(bad) {
			t.Errorf("%q accepted: an empty target, a line break or a backslash stays refused", bad)
		}
	}
	// The CSRF origin check is not its business.
	if a.TrustsOrigin("https://evil.example") {
		t.Fatal("WithoutOriginCheck trusted an origin for mutations")
	}
	// It also lets WithErrorURL name any host.
	if _, err := newAuth(auth.WithPlugins(signIn{on: true}), auth.WithoutOriginCheck(), auth.WithErrorURL("https://elsewhere.example/err")); err != nil {
		t.Fatalf("WithErrorURL on another host with the check off: %v", err)
	}
}

func TestMemoryVerificationStore_Contract(t *testing.T) {
	clock := func() time.Time { return time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC) }
	verificationtest.Run(t, func(*testing.T) auth.VerificationStore { return auth.NewMemoryVerificationStore(clock) })
	verificationtest.Run(t, func(*testing.T) auth.VerificationStore {
		return auth.NewStorageVerificationStore(auth.NewMemoryStorage(nil).(auth.GetAndDeleter))
	})
}

// The store's records hold no token and no identifier in a key.
func TestStorageVerificationStore_KeysAreHashed(t *testing.T) {
	kv := &recordingKV{GetAndDeleter: auth.NewMemoryStorage(nil).(auth.GetAndDeleter)}
	s := auth.NewStorageVerificationStore(kv)
	ctx := context.Background()
	now := time.Now()
	secret, ident := "the-raw-token", "ada@example.com"
	h := auth.HashToken(auth.Token(secret))
	if err := s.Insert(ctx, auth.Verification{ID: "v", Identifier: ident, Purpose: "p", ExpiresAt: now.Add(time.Hour), CreatedAt: now}, h); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeAll(ctx, "p", ident, now); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteIdentifiers(ctx, []string{ident}, now); err != nil {
		t.Fatal(err)
	}
	if len(kv.keys) == 0 {
		t.Fatal("no key recorded")
	}
	for _, k := range kv.keys {
		if strings.Contains(k, secret) || strings.Contains(k, ident) {
			t.Fatalf("key %q holds a raw token or identifier", k)
		}
	}
	if n, err := s.Sweep(ctx, now); n != 0 || err != nil {
		t.Fatalf("Sweep = %d %v; a KV store expires records itself", n, err)
	}
}

// recordingKV records every key written or read.
type recordingKV struct {
	auth.GetAndDeleter
	keys []string
	ttls map[string]time.Duration
}

func (r *recordingKV) Get(ctx context.Context, k string) (string, bool, error) {
	r.keys = append(r.keys, k)
	return r.GetAndDeleter.Get(ctx, k)
}

func (r *recordingKV) Set(ctx context.Context, k, v string, ttl time.Duration) error {
	r.keys = append(r.keys, k)
	if r.ttls == nil {
		r.ttls = map[string]time.Duration{}
	}
	r.ttls[k] = ttl
	return r.GetAndDeleter.Set(ctx, k, v, ttl)
}

func (r *recordingKV) Increment(ctx context.Context, k string, ttl time.Duration) (int64, error) {
	r.keys = append(r.keys, k)
	return r.GetAndDeleter.Increment(ctx, k, ttl)
}

// A failing store's errors reach the caller, never a silent success.
func TestStorageVerificationStore_Faults(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	v := auth.Verification{ID: "v", Identifier: "i", Purpose: "p", ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	f := &faultGD{GetAndDeleter: auth.NewMemoryStorage(nil).(auth.GetAndDeleter)}
	s := auth.NewStorageVerificationStore(f)
	f.fail = true
	if err := s.Insert(ctx, v, []byte("h")); err == nil {
		t.Fatal("Insert over a failing store succeeded")
	}
	if _, err := s.Consume(ctx, "p", []byte("h"), now); err == nil || errors.Is(err, auth.ErrTokenInvalid) {
		t.Fatalf("Consume over a failing store = %v, want the store's error", err)
	}
	if err := s.ConsumeAll(ctx, "p", "i", now); err == nil {
		t.Fatal("ConsumeAll over a failing store succeeded")
	}
	if err := s.DeleteIdentifiers(ctx, []string{"i"}, now); err == nil {
		t.Fatal("DeleteIdentifiers over a failing store succeeded")
	}
	// A record that is not JSON, and a counter that is not a number.
	f.fail = false
	_ = f.Set(ctx, "auth:verification:p:"+"68", "{", time.Minute)
	if _, err := s.Consume(ctx, "p", []byte("h"), now); err == nil || errors.Is(err, auth.ErrTokenInvalid) {
		t.Fatalf("Consume of a corrupt record = %v, want an error", err)
	}
	if err := s.Insert(ctx, v, []byte("h2")); err != nil {
		t.Fatal(err)
	}
	f.badCounter = true
	if _, err := s.Consume(ctx, "p", []byte("h2"), now); err == nil || errors.Is(err, auth.ErrTokenInvalid) {
		t.Fatalf("Consume with a corrupt counter = %v, want an error", err)
	}
}

// faultGD fails every call while fail is set, and reads every counter as
// garbage while badCounter is.
type faultGD struct {
	auth.GetAndDeleter
	fail, badCounter bool
}

var errFaultGD = errors.New("kv: down")

func (f *faultGD) Get(ctx context.Context, k string) (string, bool, error) {
	if f.fail {
		return "", false, errFaultGD
	}
	if f.badCounter && strings.Contains(k, "-cutoff:") {
		return "x", true, nil
	}
	return f.GetAndDeleter.Get(ctx, k)
}

func (f *faultGD) Set(ctx context.Context, k, v string, ttl time.Duration) error {
	if f.fail {
		return errFaultGD
	}
	return f.GetAndDeleter.Set(ctx, k, v, ttl)
}

func (f *faultGD) GetAndDelete(ctx context.Context, k string) (string, bool, error) {
	if f.fail {
		return "", false, errFaultGD
	}
	return f.GetAndDeleter.GetAndDelete(ctx, k)
}

func (f *faultGD) Increment(ctx context.Context, k string, ttl time.Duration) (int64, error) {
	if f.fail {
		return 0, errFaultGD
	}
	return f.GetAndDeleter.Increment(ctx, k, ttl)
}

// WithVerificationStore is the store the Auth uses.
func TestWithVerificationStore(t *testing.T) {
	s := auth.NewMemoryVerificationStore(nil)
	a, err := newAuth(auth.WithPlugins(signIn{on: true}), auth.WithVerificationStore(s))
	if err != nil {
		t.Fatal(err)
	}
	if a.VerificationStore() != s {
		t.Fatal("VerificationStore is not the one passed")
	}
	b, err := newAuth(auth.WithPlugins(signIn{on: true}))
	if err != nil || b.VerificationStore() == nil {
		t.Fatalf("no default store: %v", err)
	}
}

// fieldsAuth declares app columns of every type and lists all but one as
// sign-up fields.
func fieldsAuth(t *testing.T, extra ...auth.Option) *auth.Auth {
	t.Helper()
	a, err := newAuth(append([]auth.Option{auth.WithPlugins(signIn{on: true}),
		auth.WithUserColumns(
			auth.ColumnExtension{Name: "plan", Type: auth.ColumnText, Nullable: true},
			auth.ColumnExtension{Name: "seats", Type: auth.ColumnInt, Nullable: true},
			auth.ColumnExtension{Name: "beta", Type: auth.ColumnBool, Default: "false"},
			auth.ColumnExtension{Name: "trial_ends", Type: auth.ColumnTimestamp, Nullable: true},
			auth.ColumnExtension{Name: "role", Type: auth.ColumnText, Nullable: true},
		),
		auth.WithSignUpFields("plan", "seats", "beta", "trial_ends"),
	}, extra...)...)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestCheckFields(t *testing.T) {
	a := fieldsAuth(t)
	ok := []auth.Fields{
		nil, {},
		{"plan": json.RawMessage(`"pro"`), "seats": json.RawMessage(`5`), "beta": json.RawMessage(`true`), "trial_ends": json.RawMessage(`"2026-11-01T00:00:00Z"`)},
		{"plan": json.RawMessage(`null`), "seats": json.RawMessage(` null `)},
	}
	for _, f := range ok {
		if err := a.CheckFields(f); err != nil {
			t.Errorf("%v refused: %v", f, err)
		}
	}
	bad := map[string]auth.Fields{
		"not listed":          {"role": json.RawMessage(`"admin"`)},
		"core column":         {"name": json.RawMessage(`"x"`)},
		"unknown":             {"nope": json.RawMessage(`1`)},
		"number for text":     {"plan": json.RawMessage(`5`)},
		"string for int":      {"seats": json.RawMessage(`"5"`)},
		"fraction for int":    {"seats": json.RawMessage(`5.5`)},
		"string for bool":     {"beta": json.RawMessage(`"true"`)},
		"null for NOT NULL":   {"beta": json.RawMessage(`null`)},
		"not a time":          {"trial_ends": json.RawMessage(`"tomorrow"`)},
		"two values":          {"plan": json.RawMessage(`"a" "b"`)},
		"broken JSON":         {"plan": json.RawMessage(`"a`)},
		"one bad among goods": {"plan": json.RawMessage(`"pro"`), "seats": json.RawMessage(`"x"`)},
	}
	for name, f := range bad {
		if err := a.CheckFields(f); !errors.Is(err, auth.ErrFieldInvalid) {
			t.Errorf("%s: %v, want ErrFieldInvalid", name, err)
		}
	}
}

func TestWithSignUpFields_RefusesColumnsTheAppDidNotDeclare(t *testing.T) {
	for name, col := range map[string]string{"core": "name", "undeclared": "plan", "plugin": "custom_flag"} {
		_, err := newAuth(auth.WithPlugins(signIn{on: true}, colPlugin{name: "colp", cols: []auth.ColumnExtension{{Table: auth.TableNameUser, Name: "custom_flag", Type: auth.ColumnBool, Default: "false"}}}),
			auth.WithSignUpFields(col))
		if !errors.Is(err, auth.ErrBadOperation) {
			t.Errorf("%s column %q: %v, want ErrBadOperation", name, col, err)
		}
	}
}

func TestIssueCodeWith_RefusesBadOptions(t *testing.T) {
	a, err := newAuth(auth.WithPlugins(signIn{on: true}))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	gen := func(context.Context) (string, error) { return "123456", nil }
	if _, err := a.IssueCodeWith(ctx, "p", "s", time.Minute, auth.CodeOptions{Reuse: true, Generate: gen}); !errors.Is(err, auth.ErrNoSecret) {
		t.Fatalf("Reuse with Generate and no secret: %v", err)
	}
	long := strings.Repeat("9", auth.MaxGeneratedCodeLength+1)
	if _, err := a.IssueCodeWith(ctx, "p", "s", time.Minute, auth.CodeOptions{Generate: func(context.Context) (string, error) { return long, nil }}); !errors.Is(err, auth.ErrBadOperation) {
		t.Fatalf("a generated code over %d bytes: %v", auth.MaxGeneratedCodeLength, err)
	}
	if _, err := a.IssueCodeWith(ctx, "p", "s", time.Minute, auth.CodeOptions{Reuse: true}); !errors.Is(err, auth.ErrNoSecret) {
		t.Fatalf("Reuse without a secret: %v", err)
	}
	failing := errors.New("gen down")
	if _, err := a.IssueCodeWith(ctx, "p", "s", time.Minute, auth.CodeOptions{Generate: func(context.Context) (string, error) { return "", failing }}); !errors.Is(err, failing) {
		t.Fatalf("a failing generator: %v", err)
	}
	if _, err := a.IssueCodeWith(ctx, "p", "s", time.Minute, auth.CodeOptions{Generate: func(context.Context) (string, error) { return "", nil }}); !errors.Is(err, auth.ErrBadOperation) {
		t.Fatal("an empty generated code was accepted")
	}
	if err := a.IssueVerificationToken(ctx, "p", "i", "", time.Minute, ""); err == nil {
		t.Fatal("an empty verification token was accepted")
	}
}

// A revocation cutoff expires, so the store does not grow forever, and it
// outlives every token it guards: at least MinVerificationCutoffTTL, and at
// least the longest lifetime the store has issued.
func TestStorageVerificationStore_CutoffsExpireAfterTheTokensTheyGuard(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	kv := &recordingKV{GetAndDeleter: auth.NewMemoryStorage(nil).(auth.GetAndDeleter)}
	s := auth.NewStorageVerificationStore(kv)
	cutoffTTLs := func() []time.Duration {
		var out []time.Duration
		for k, ttl := range kv.ttls {
			if strings.Contains(k, "-cutoff:") {
				out = append(out, ttl)
			}
		}
		return out
	}
	if err := s.ConsumeAll(ctx, "p", "i", now); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteIdentifiers(ctx, []string{"i"}, now); err != nil {
		t.Fatal(err)
	}
	got := cutoffTTLs()
	if len(got) != 2 {
		t.Fatalf("cutoffs written: %v", got)
	}
	for _, ttl := range got {
		if ttl != auth.MinVerificationCutoffTTL {
			t.Fatalf("cutoff ttl %v, want %v: never 0 (forever), never shorter", ttl, auth.MinVerificationCutoffTTL)
		}
	}
	long := 30 * 24 * time.Hour
	if err := s.Insert(ctx, auth.Verification{ID: "v", Identifier: "i", Purpose: "p", ExpiresAt: now.Add(long), CreatedAt: now}, []byte("h")); err != nil {
		t.Fatal(err)
	}
	kv.ttls = nil
	if err := s.ConsumeAll(ctx, "p", "i", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if got := cutoffTTLs(); len(got) != 1 || got[0] < long {
		t.Fatalf("cutoff ttl after a %v token = %v, want at least the token's life", long, got)
	}
}

// splitReq is a sign-up body's own keys, with an embedded struct and a
// renamed, an untagged and a skipped field.
type splitReq struct {
	splitEmbedded
	Email   string `json:"email"`
	Untag   int
	Skipped string `json:"-"`
	hidden  string
}

type splitEmbedded struct {
	Name string `json:"name"`
}

func TestSplitBody(t *testing.T) {
	var r splitReq
	rest, err := auth.SplitBody([]byte(`{"email":"a@b.c","name":"Ada","Untag":3,"plan":"pro","seats":2,"Skipped":"x"}`), &r)
	if err != nil {
		t.Fatal(err)
	}
	if r.Email != "a@b.c" || r.Name != "Ada" || r.Untag != 3 || r.Skipped != "" {
		t.Fatalf("decoded %+v", r)
	}
	if len(rest) != 3 || string(rest["plan"]) != `"pro"` || string(rest["seats"]) != "2" || string(rest["Skipped"]) != `"x"` {
		t.Fatalf("rest = %v", rest)
	}
	// An unexported field is not a key: "hidden" is a field of the request,
	// not one of its own.
	if rest, err := auth.SplitBody([]byte(`{"hidden":"h"}`), &r); err != nil || r.hidden != "" || string(rest["hidden"]) != `"h"` {
		t.Fatalf("unexported field: %v %v %q", rest, err, r.hidden)
	}
	if rest, err := auth.SplitBody([]byte(`{"EMAIL":"x"}`), &r); err != nil || len(rest) != 0 || r.Email != "x" {
		t.Fatalf("case-insensitive key: %v %v %q", rest, err, r.Email)
	}
	for name, body := range map[string]string{"wrong type": `{"email":5}`, "not an object": `[1]`, "broken": `{"email":`} {
		if _, err := auth.SplitBody([]byte(body), &r); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := auth.SplitBody([]byte(`{}`), r); err == nil {
		t.Error("a non-pointer destination accepted")
	}
	type nested struct {
		In struct {
			A int `json:"a"`
		} `json:"in"`
	}
	var n nested
	if _, err := auth.SplitBody([]byte(`{"in":{"a":1,"b":2}}`), &n); err == nil {
		t.Error("an unknown nested key accepted")
	}
}

func TestMergeFields(t *testing.T) {
	a := fieldsAuth(t)
	nested := auth.Fields{"plan": json.RawMessage(`"pro"`)}
	if got, err := a.MergeFields(nested, nil); err != nil || len(got) != 1 {
		t.Fatalf("empty top = %v %v", got, err)
	}
	got, err := a.MergeFields(nested, auth.Fields{"seats": json.RawMessage(`2`)})
	if err != nil || len(got) != 2 || string(got["seats"]) != "2" || string(got["plan"]) != `"pro"` {
		t.Fatalf("union = %v %v", got, err)
	}
	if _, err := a.MergeFields(nested, auth.Fields{"role": json.RawMessage(`"admin"`)}); !errors.Is(err, auth.ErrBadRequest) {
		t.Fatalf("an undeclared top key = %v, want ErrBadRequest", err)
	}
	if _, err := a.MergeFields(nested, auth.Fields{"plan": json.RawMessage(`"free"`)}); !errors.Is(err, auth.ErrFieldInvalid) {
		t.Fatalf("a key in both = %v, want ErrFieldInvalid", err)
	}
}
