package authhttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/lastlogin"
)

// updateGolden rewrites testdata/typescript_client.golden.ts from the
// generator: go test ./authhttp -run TypeScript -update.
var updateGolden = flag.Bool("update", false, "rewrite the TypeScript golden file")

const tsGolden = "testdata/typescript_client.golden.ts"

// Input and output shapes of the TypeScript test plugin: every rule the
// generator applies, once.
type (
	tsListRequest struct {
		Query  string `json:"query,omitempty"`
		Page   int    `json:"page,omitempty,string"`
		Limit  int    `json:"limit,omitempty"`
		Strict bool   `json:"strict"`
	}
	tsBase struct {
		ID      string    `json:"id"`
		Created time.Time `json:"createdAt"`
	}
	tsItem struct {
		tsBase
		Tags   []string          `json:"tags"`
		Labels map[string]int    `json:"labels,omitempty"`
		Parent *tsItem           `json:"parent"`
		Extra  json.RawMessage   `json:"extra,omitempty"`
		Any    any               `json:"any"`
		Grid   [2]float64        `json:"grid"`
		Pick   []*string         `json:"pick"`
		Inline struct{ N uint8 } `json:"inline"`
		Key    auth.WireToken    `json:"key"`
		Odd    string            `json:"odd-name"`
	}
	tsPage struct {
		Items []tsItem `json:"items"`
		Total int64    `json:"total"`
	}
	tsEmpty struct{}
	// tsConsent has the field the client fills (oauth_query) and one it
	// does not, so the golden pins Fill and the op's fill table.
	tsConsent struct {
		Query  string `json:"oauth_query"`
		Accept bool   `json:"accept"`
	}
	// tsOpaque writes its own JSON, so the generator cannot see its
	// fields and must not fill its oauth_query.
	tsOpaque struct {
		Query string `json:"oauth_query"`
	}
	// tsA_B and tsAB both become AuthhttpTestTsAB in TypeScript.
	tsA_B struct {
		A string `json:"a"`
	}
	tsAB struct {
		B string `json:"b"`
	}
	// Ops in package authhttp_test is AuthhttpTestOps, the operation
	// table's name of a plugin called authhttp_test.
	Ops struct {
		N int `json:"n"`
	}
)

// tsPlugin serves one query, one mutation with no input fields and one
// with a deep output, under ids with dashes and underscores.
type tsPlugin struct {
	name string
	ops  []auth.Operation
}

func (p tsPlugin) Name() string                 { return p.name }
func (p tsPlugin) SignsIn() bool                { return true }
func (p tsPlugin) Operations() []auth.Operation { return p.ops }

func newTSPlugin(name string) tsPlugin {
	list := auth.Define(auth.OpInfo{ID: auth.EndpointID(name + ".list-items"), Kind: auth.Query, Require: auth.SignedIn, Path: "/items"},
		func(context.Context, *auth.Call, tsListRequest) (tsPage, error) { return tsPage{}, nil })
	touch := auth.Define(auth.OpInfo{ID: auth.EndpointID(name + ".touch"), Kind: auth.Mutation, Require: auth.Public, Path: "/touch"},
		func(context.Context, *auth.Call, tsEmpty) (tsEmpty, error) { return tsEmpty{}, nil })
	save := auth.Define(auth.OpInfo{ID: auth.EndpointID(name + ".save_item"), Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/save"},
		func(context.Context, *auth.Call, tsItem) (*tsItem, error) { return nil, nil })
	// A sign-in carries signIn in the table; a second factor's promotion,
	// though also a SignIn operation, does not.
	signIn := auth.Define(auth.OpInfo{ID: auth.EndpointID(name + ".sign-in"), Kind: auth.Mutation, Require: auth.Public, Path: "/sign-in", SignIn: true},
		func(context.Context, *auth.Call, tsEmpty) (tsEmpty, error) { return tsEmpty{}, nil })
	promote := auth.Define(auth.OpInfo{ID: auth.EndpointID(name + ".verify"), Kind: auth.Mutation, Require: auth.PendingSecondFactor, Path: "/verify", SignIn: true},
		func(context.Context, *auth.Call, tsEmpty) (tsEmpty, error) { return tsEmpty{}, nil })
	consent := auth.Define(auth.OpInfo{ID: auth.EndpointID(name + ".consent"), Kind: auth.Mutation, Require: auth.SignedIn, Path: "/consent"},
		func(context.Context, *auth.Call, *tsConsent) (tsEmpty, error) { return tsEmpty{}, nil })
	return tsPlugin{name: name, ops: []auth.Operation{list, touch, save, signIn, promote, consent}}
}

func newTSAuth(t *testing.T, plugins ...auth.Plugin) *auth.Auth {
	t.Helper()
	a, err := auth.New(auth.WithBaseURL(base), auth.WithPlugins(plugins...))
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	return a
}

// TestTypeScriptClient_Golden: the generated client.ts for a plugin that
// exercises every type rule matches the reviewed golden file byte for byte,
// two runs agree, and the other three files are the runtime, the error
// codes and the fixed index.
func TestTypeScriptClient_Golden(t *testing.T) {
	a := newTSAuth(t, newTSPlugin("tsp"))
	files, err := authhttp.TypeScriptClient(a)
	if err != nil {
		t.Fatal(err)
	}
	again, err := authhttp.TypeScriptClient(a)
	if err != nil {
		t.Fatal(err)
	}
	for name := range files {
		if !bytes.Equal(files[name], again[name]) {
			t.Fatalf("two runs rendered a different %s", name)
		}
	}
	if len(files) != 5 {
		t.Fatalf("files = %d, want 5", len(files))
	}
	client := files[authhttp.TSFileClient]
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(tsGolden), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(tsGolden, client, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(tsGolden)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if !bytes.Equal(client, want) {
		t.Fatalf("client.ts differs from %s (run with -update after reviewing):\n%s", tsGolden, client)
	}
	if !bytes.Equal(files[authhttp.TSFileErrorCodes], authhttp.TypeScriptErrorCodes()) {
		t.Fatal("error-codes.ts is not TypeScriptErrorCodes")
	}
	if !bytes.Contains(files[authhttp.TSFileErrorCodes], []byte(`"auth.signed_out": { status: 401,`)) {
		t.Fatal("error-codes.ts lacks the core's codes")
	}
	for _, mod := range []string{authhttp.TSFileClient, authhttp.TSFileRuntime, authhttp.TSFileErrorCodes, authhttp.TSFileExtensions} {
		if !bytes.Contains(files[authhttp.TSFileIndex], []byte(`export * from "./`+mod+`";`)) {
			t.Errorf("index.ts does not re-export %s", mod)
		}
	}
}

// TestTypeScriptClient_EveryOperationIsCallable: each operation the Auth
// serves appears in client.ts with its id, method and route, and nothing
// else does.
func TestTypeScriptClient_EveryOperationIsCallable(t *testing.T) {
	a := newTSAuth(t, newTSPlugin("tsp"))
	files, err := authhttp.TypeScriptClient(a)
	if err != nil {
		t.Fatal(err)
	}
	client := string(files[authhttp.TSFileClient])
	for _, op := range a.Operations() {
		want := `id: "` + string(op.Info().ID) + `", method: "` + authhttp.MethodOf(op.Info().Kind) + `", path: "` + op.Route() + `"`
		if !strings.Contains(client, want) {
			t.Errorf("client.ts lacks %s", want)
		}
	}
	if n := strings.Count(client, `{ id: "`); n != len(a.Operations()) {
		t.Fatalf("client.ts has %d operations, the Auth serves %d", n, len(a.Operations()))
	}
}

// TestTypeScriptClient_RefusesCollisions: a name two things would share is
// an error naming it, never a silently merged or shadowed declaration.
func TestTypeScriptClient_RefusesCollisions(t *testing.T) {
	twin := newTSPlugin("twin")
	twin.ops = append(twin.ops, auth.Define(auth.OpInfo{ID: "twin.list_items", Kind: auth.Mutation, Require: auth.Public, Path: "/other"},
		func(context.Context, *auth.Call, tsEmpty) (tsEmpty, error) { return tsEmpty{}, nil }))
	shadow := tsPlugin{name: "shadow", ops: []auth.Operation{auth.Define(auth.OpInfo{ID: "shadow.err", Kind: auth.Query, Require: auth.Public, Path: "/err"},
		func(context.Context, *auth.Call, tsEmpty) (auth.Error, error) { return auth.Error{}, nil })}}
	alike := tsPlugin{name: "alike", ops: []auth.Operation{auth.Define(auth.OpInfo{ID: "alike.pair", Kind: auth.Mutation, Require: auth.Public, Path: "/pair"},
		func(context.Context, *auth.Call, tsA_B) (tsAB, error) { return tsAB{}, nil })}}
	opsName := tsPlugin{name: "authhttp_test", ops: []auth.Operation{auth.Define(auth.OpInfo{ID: "authhttp_test.ops", Kind: auth.Query, Require: auth.Public, Path: "/ops"},
		func(context.Context, *auth.Call, tsEmpty) (Ops, error) { return Ops{}, nil })}}
	for _, tc := range []struct {
		name   string
		plugin auth.Plugin
		want   string
	}{
		{"two operations, one method", twin, "list_items"},
		{"plugin named a keyword", newTSPlugin("delete"), "keyword"},
		{"plugin named a core method", newTSPlugin("session"), "core's method"},
		{"type named a runtime export", shadow, "AuthError"},
		{"two Go types, one TypeScript name", alike, "AuthhttpTestTsAB"},
		{"a Go type named like a plugin's table", opsName, "AuthhttpTestOps"},
		{"plugin named a runtime export", newTSPlugin("memory_token_store"), "memoryTokenStore"},
		{"plugin named an extension export", newTSPlugin("oauth_popup"), "oauthPopup"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := authhttp.TypeScriptClient(newTSAuth(t, tc.plugin))
			if !errors.Is(err, authhttp.ErrTypeScriptName) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want ErrTypeScriptName naming %q", err, tc.want)
			}
			if _, err := authhttp.TypeScriptMethods(newTSAuth(t, tc.plugin)); !errors.Is(err, authhttp.ErrTypeScriptName) {
				t.Fatalf("TypeScriptMethods: err = %v, want ErrTypeScriptName", err)
			}
		})
	}
}

// TestTypeScriptClient_RuntimeSpeaksTheWire: the hand-written runtime names
// the bearer-mode headers exactly as authhttp does, the signed-out code a
// refused sign-out clears the token on exactly as the core declares it, and
// the member a standard's error body carries the library's error under, so
// renaming one in Go fails here instead of silently breaking every bearer
// client.
func TestTypeScriptClient_RuntimeSpeaksTheWire(t *testing.T) {
	files, err := authhttp.TypeScriptClient(newTSAuth(t, newTSPlugin("tsp")))
	if err != nil {
		t.Fatal(err)
	}
	runtime := string(files[authhttp.TSFileRuntime])
	for name, value := range map[string]string{
		"TOKEN_MODE_HEADER":     authhttp.TokenModeHeader,
		"TOKEN_MODE_BEARER":     authhttp.TokenModeBearer,
		"SET_TOKEN_HEADER":      authhttp.SetTokenHeader,
		"SIGNED_OUT_CODE":       auth.ErrSignedOut.Code,
		"PROTOCOL_ERROR_MEMBER": authhttp.ProtocolErrorMember,
	} {
		if !strings.Contains(runtime, "const "+name+` = "`+value+`";`) {
			t.Errorf("runtime.ts does not define %s as %q", name, value)
		}
	}
}

// TestTypeScriptMethods_ListsTheClient: every method the client has is
// listed once, core first and then by namespace and name, with the route
// and the types client.ts declares. TestTypeScriptClient_RefusesCollisions
// proves it refuses what TypeScriptClient refuses.
func TestTypeScriptMethods_ListsTheClient(t *testing.T) {
	// Two plugins, listed out of order, so the namespaces must be sorted.
	a := newTSAuth(t, newTSPlugin("tsq"), newTSPlugin("tsp"))
	methods, err := authhttp.TypeScriptMethods(a)
	if err != nil {
		t.Fatal(err)
	}
	if len(methods) != len(a.Operations()) {
		t.Fatalf("methods = %d, the Auth serves %d operations", len(methods), len(a.Operations()))
	}
	files, err := authhttp.TypeScriptClient(a)
	if err != nil {
		t.Fatal(err)
	}
	client := string(files[authhttp.TSFileClient])
	seenPlugin := false
	for i, m := range methods {
		if m.Namespace == "" {
			if seenPlugin || m.Plugin != auth.CorePluginName {
				t.Fatalf("method %d %+v: the core's methods must come first, with no namespace", i, m)
			}
		} else {
			seenPlugin = true
		}
		if i > 0 && (methods[i-1].Namespace > m.Namespace || methods[i-1].Namespace == m.Namespace && methods[i-1].Name >= m.Name) {
			t.Fatalf("methods %s.%s and %s.%s are out of order", methods[i-1].Namespace, methods[i-1].Name, m.Namespace, m.Name)
		}
		want := "  readonly " + m.Name + ": Op<" + m.Input + ", " + m.Output + ">;"
		if !strings.Contains(client, want) {
			t.Errorf("client.ts lacks %q", want)
		}
	}
	var save authhttp.TSMethod
	for _, m := range methods {
		if m.ID == "tsp.save_item" {
			save = m
		}
	}
	if save.Namespace != "tsp" || save.Name != "saveItem" || save.HTTPMethod != "POST" || save.Path != "/tsp/save" || save.Require != auth.FreshSignIn || save.Input != "AuthhttpTestTsItem" || save.Output != "AuthhttpTestTsItem | null" {
		t.Fatalf("save = %+v", save)
	}
}

// TestTypeScriptClient_FlagsSignInsAndFills: the table marks a sign-in
// operation signIn (lastLoginMethod records from it) but not a second
// factor's promotion, and an input's oauth_query is filled by the client
// and optional in the method's type.
func TestTypeScriptClient_FlagsSignInsAndFills(t *testing.T) {
	files, err := authhttp.TypeScriptClient(newTSAuth(t, newTSPlugin("tsp")))
	if err != nil {
		t.Fatal(err)
	}
	client := string(files[authhttp.TSFileClient])
	for _, want := range []string{
		`signIn: { id: "tsp.sign-in", method: "POST", path: "/tsp/sign-in", signIn: true },`,
		`verify: { id: "tsp.verify", method: "POST", path: "/tsp/verify" },`,
		`consent: { id: "tsp.consent", method: "POST", path: "/tsp/consent", fill: { oauth_query: "oauthQuery" } },`,
		`readonly consent: Op<Fill<AuthhttpTestTsConsent | null, "oauth_query">, AuthhttpTestTsEmpty>;`,
	} {
		if !strings.Contains(client, want) {
			t.Errorf("client.ts lacks %s", want)
		}
	}
}

func (tsOpaque) MarshalJSON() ([]byte, error) { return []byte(`{}`), nil }

// TestTypeScriptClient_FillsOnlyVisibleFields: an input that writes its own
// JSON or is not a struct has no field the client can see, so its operation
// carries no fill even when the Go type has an oauth_query field.
func TestTypeScriptClient_FillsOnlyVisibleFields(t *testing.T) {
	opaque := auth.Define(auth.OpInfo{ID: "tso.opaque", Kind: auth.Mutation, Require: auth.SignedIn, Path: "/opaque"},
		func(context.Context, *auth.Call, tsOpaque) (tsEmpty, error) { return tsEmpty{}, nil })
	bag := auth.Define(auth.OpInfo{ID: "tso.bag", Kind: auth.Mutation, Require: auth.SignedIn, Path: "/bag"},
		func(context.Context, *auth.Call, map[string]string) (tsEmpty, error) { return tsEmpty{}, nil })
	files, err := authhttp.TypeScriptClient(newTSAuth(t, tsPlugin{name: "tso", ops: []auth.Operation{opaque, bag}}))
	if err != nil {
		t.Fatal(err)
	}
	client := string(files[authhttp.TSFileClient])
	for _, want := range []string{
		`opaque: { id: "tso.opaque", method: "POST", path: "/tso/opaque" },`,
		`bag: { id: "tso.bag", method: "POST", path: "/tso/bag" },`,
	} {
		if !strings.Contains(client, want) {
			t.Errorf("client.ts lacks %s", want)
		}
	}
}

// TestTypeScriptClient_LastLoginRoutes: the routes extensions.ts's
// lastLoginMethod() calls are plugin/lastlogin's operations under
// WithCookie, id, method and path, so a renamed route fails here instead
// of silently 404ing every client.
func TestTypeScriptClient_LastLoginRoutes(t *testing.T) {
	a := newTSAuth(t, newTSPlugin("tsp"), lastlogin.New(lastlogin.WithCookie("", 0)))
	files, err := authhttp.TypeScriptClient(a)
	if err != nil {
		t.Fatal(err)
	}
	ext := string(files[authhttp.TSFileExtensions])
	found := 0
	for _, op := range a.Operations() {
		if op.Plugin() != lastlogin.PluginName {
			continue
		}
		found++
		want := `{ id: "` + string(op.Info().ID) + `", method: "` + authhttp.MethodOf(op.Info().Kind) + `", path: "` + op.Route() + `" }`
		if !strings.Contains(ext, want) {
			t.Errorf("extensions.ts lacks %s", want)
		}
	}
	if found != 2 {
		t.Fatalf("lastlogin serves %d operations under WithCookie, want 2", found)
	}
	// The popup reads the session back through the generated core table.
	if !strings.Contains(string(files[authhttp.TSFileClient]), `session: { id: "core.session", method: "GET", path: "/session" }`) || !strings.Contains(ext, "ctx.call(coreOps.session)") {
		t.Fatal("extensions.ts no longer reads the session through coreOps.session")
	}
}
