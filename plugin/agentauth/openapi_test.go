package agentauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// petSpec is a small OpenAPI document: path-level and referenced
// parameters, a referenced body schema, outputs from 200 and 201, an
// operation without an operationId, and non-operation keys.
const petSpec = `{
  "openapi": "3.0.0",
  "info": {"title": "Pet Store", "description": "Pets as a service"},
  "paths": {
    "/pets/{petId}": {
      "parameters": [{"$ref": "#/components/parameters/PetId"}],
      "summary": "not an operation",
      "x-internal": {"operationId": "nope"},
      "get": {"operationId": "getPet", "summary": "Get a pet",
        "parameters": [{"name": "X-Trace", "in": "header"}, {"name": "verbose", "in": "query", "schema": {"type": "boolean"}}],
        "responses": {"200": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Pet"}}}}}},
      "delete": {"operationId": "deletePet", "description": "Delete a pet"}
    },
    "/pets": {
      "post": {"operationId": "createPet",
        "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/NewPet"}}}},
        "responses": {"201": {"content": {"application/json": {"schema": {"type": "object"}}}}}},
      "get": {"summary": "no id"}
    }
  },
  "components": {
    "parameters": {"PetId": {"name": "petId", "in": "path", "required": true, "schema": {"type": "string"}, "description": "The pet"}},
    "schemas": {
      "Pet": {"type": "object", "properties": {"id": {"type": "string"}}},
      "NewPet": {"type": "object", "properties": {"name": {"type": "string"}, "tag": {"type": "string"}}, "required": ["name"]}
    }
  }
}`

func TestFromOpenAPI_DerivesCapabilities(t *testing.T) {
	caps, err := FromOpenAPI([]byte(petSpec))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range caps {
		names = append(names, c.Name)
	}
	if !slices.Equal(names, []string{"createPet", "getPet", "deletePet"}) {
		t.Fatalf("names in path, then method order: %v", names)
	}
	var get map[string]any
	_ = json.Unmarshal(caps[1].Input, &get)
	props, _ := get["properties"].(map[string]any)
	pet, _ := props["petId"].(map[string]any)
	if caps[1].Description != "Get a pet" || pet["description"] != "The pet" || props["verbose"] == nil || props["X-Trace"] == nil ||
		!slices.Equal(get["required"].([]any), []any{"petId"}) {
		t.Fatalf("getPet input: %s", caps[1].Input)
	}
	if string(caps[1].Output) != `{"properties":{"id":{"type":"string"}},"type":"object"}` {
		t.Fatalf("getPet output: %s", caps[1].Output)
	}
	var post map[string]any
	_ = json.Unmarshal(caps[0].Input, &post)
	if !strings.Contains(string(caps[0].Input), `"tag"`) || !slices.Equal(post["required"].([]any), []any{"name"}) || string(caps[0].Output) != `{"type":"object"}` {
		t.Fatalf("createPet: %s %s", caps[0].Input, caps[0].Output)
	}
	if caps[2].Description != "Delete a pet" || caps[2].Output != nil {
		t.Fatalf("deletePet: %+v", caps[2])
	}
	if _, err := FromOpenAPI([]byte("{")); !errors.Is(err, ErrBadOpenAPI) {
		t.Fatalf("malformed: %v", err)
	}
	dup := `{"paths":{"/a":{"get":{"operationId":"x"}},"/b":{"get":{"operationId":"x"}}}}`
	if _, err := FromOpenAPI([]byte(dup)); !errors.Is(err, ErrBadOpenAPI) {
		t.Fatalf("duplicate operationId: %v", err)
	}
	if caps, err := FromOpenAPI([]byte(`{"paths":{"/a":{"get":{"operationId":"bare"}}}}`)); err != nil || caps[0].Description != "bare" || caps[0].Input != nil {
		t.Fatalf("bare operation: %+v %v", caps, err)
	}
}

func TestResolveRef(t *testing.T) {
	root := map[string]any{"a": map[string]any{"b/c": "slash", "d~e": "tilde"}}
	if resolveRef(root, map[string]any{"$ref": "#/a/b~1c"}) != "slash" || resolveRef(root, map[string]any{"$ref": "#/a/d~0e"}) != "tilde" {
		t.Fatal("escapes")
	}
	missing := map[string]any{"$ref": "#/zzz"}
	if got, _ := resolveRef(root, missing).(map[string]any); got["$ref"] != "#/zzz" {
		t.Fatal("an unresolvable ref stays")
	}
	remote := map[string]any{"$ref": "https://x/y"}
	if got, _ := resolveRef(root, remote).(map[string]any); got["$ref"] != "https://x/y" {
		t.Fatal("a remote ref stays")
	}
	if resolveRef(root, map[string]any{"$ref": "#/a/b~1c/deeper"}).(map[string]any)["$ref"] == nil {
		t.Fatal("walking past a leaf stays")
	}
}

func TestArgString(t *testing.T) {
	cases := map[string]any{"x": "x", "7": float64(7), "1.5": 1.5, "true": true, "42": json.Number("42"), `{"a":1}`: map[string]any{"a": 1}}
	for want, v := range cases {
		if got := argString(v); got != want {
			t.Errorf("%v: %q, want %q", v, got, want)
		}
	}
}

// upstream records what the proxy sent.
type upstream struct {
	method, path, query, body string
	header                    http.Header
}

func petServer(t *testing.T, got *upstream, status int, contentType, answer string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		*got = upstream{method: r.Method, path: r.URL.EscapedPath(), query: r.URL.RawQuery, body: string(b), header: r.Header}
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, answer)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestOpenAPIHandler_Proxies(t *testing.T) {
	ctx := context.Background()
	var got upstream
	srv := petServer(t, &got, http.StatusOK, "application/json; charset=utf-8", `{"id":"p/1"}`)
	var headerCalls []string
	exec, err := OpenAPIHandler([]byte(petSpec), OpenAPIHandlerOptions{BaseURL: srv.URL + "/v1/", Headers: func(_ context.Context, capability string, s AgentSession) (http.Header, error) {
		headerCalls = append(headerCalls, capability+":"+s.User.ID)
		return http.Header{"x-trace": {"server"}, "Authorization": {"Bearer upstream"}}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec(ctx, Execution{Capability: Capability{Name: "getPet"}, Session: AgentSession{User: SessionUser{ID: "u1"}},
		Arguments: map[string]any{"petId": "p/1", "verbose": true, "X-Trace": "agent", "extra": 1}})
	if err != nil {
		t.Fatal(err)
	}
	if raw, ok := out.(json.RawMessage); !ok || string(raw) != `{"id":"p/1"}` {
		t.Fatalf("json answer: %#v", out)
	}
	if got.method != http.MethodGet || got.path != "/v1/pets/p%2F1" || got.query != "verbose=true" || got.body != "" ||
		got.header.Get("X-Trace") != "server" || got.header.Get("Authorization") != "Bearer upstream" || got.header.Get("Content-Type") != contentTypeJSON {
		t.Fatalf("upstream request: %+v", got)
	}
	if !slices.Equal(headerCalls, []string{"getPet:u1"}) {
		t.Fatalf("headers resolved per call: %v", headerCalls)
	}
	if _, err := exec(ctx, Execution{Capability: Capability{Name: "getPet"}, Arguments: map[string]any{"petId": ".."}}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("dot segment: %v", err)
	}
	if _, err := exec(ctx, Execution{Capability: Capability{Name: "unknown"}}); !errors.Is(err, ErrCapabilityNotFound) {
		t.Fatalf("unknown capability: %v", err)
	}

	if _, err := exec(ctx, Execution{Capability: Capability{Name: "createPet"}, Arguments: map[string]any{"name": "Rex", "tag": "dog"}}); err != nil {
		t.Fatal(err)
	}
	if got.method != http.MethodPost || got.path != "/v1/pets" || got.body != `{"name":"Rex","tag":"dog"}` {
		t.Fatalf("body: %+v", got)
	}
	if _, err := exec(ctx, Execution{Capability: Capability{Name: "deletePet"}, Arguments: map[string]any{"petId": 7.0, "stray": 1}}); err != nil {
		t.Fatal(err)
	}
	if got.method != http.MethodDelete || got.path != "/v1/pets/7" || got.body != "" {
		t.Fatalf("an operation without a body sends none: %+v", got)
	}
}

func TestOpenAPIHandler_Answers(t *testing.T) {
	ctx := context.Background()
	var got upstream
	call := func(status int, ct, answer string) (any, error) {
		srv := petServer(t, &got, status, ct, answer)
		exec, err := OpenAPIHandler([]byte(petSpec), OpenAPIHandlerOptions{BaseURL: srv.URL, Client: srv.Client()})
		if err != nil {
			t.Fatal(err)
		}
		return exec(ctx, Execution{Capability: Capability{Name: "deletePet"}, Arguments: map[string]any{"petId": "1"}})
	}
	if out, err := call(http.StatusOK, "text/plain", "gone"); err != nil || out != "gone" {
		t.Fatalf("text: %#v %v", out, err)
	}
	if out, err := call(http.StatusAccepted, "application/json", `{"status_url":"/jobs/1"}`); err != nil || string(out.(json.RawMessage)) != `{"status_url":"/jobs/1"}` {
		t.Fatalf("202: %#v %v", out, err)
	}
	if out, err := call(http.StatusOK, "application/json", `not json`); err != nil || out != "not json" {
		t.Fatalf("invalid json falls back to text: %#v %v", out, err)
	}
	if _, err := call(http.StatusNotFound, "text/plain", "no pet"); !errors.Is(err, ErrUpstream) || !strings.Contains(err.Error(), "404: no pet") {
		t.Fatalf("404: %v", err)
	}
	if _, err := call(http.StatusOK, "text/plain", strings.Repeat("x", maxUpstreamBytes+1)); !errors.Is(err, ErrUpstream) {
		t.Fatalf("oversized: %v", err)
	}
	if _, err := OpenAPIHandler([]byte(petSpec), OpenAPIHandlerOptions{BaseURL: "/relative"}); !errors.Is(err, ErrBadOpenAPI) {
		t.Fatalf("relative base: %v", err)
	}
	if _, err := OpenAPIHandler([]byte("["), OpenAPIHandlerOptions{BaseURL: "https://x"}); !errors.Is(err, ErrBadOpenAPI) {
		t.Fatalf("bad spec: %v", err)
	}
	failing := errors.New("no token")
	exec, _ := OpenAPIHandler([]byte(petSpec), OpenAPIHandlerOptions{BaseURL: "https://api.example.com", Headers: func(context.Context, string, AgentSession) (http.Header, error) {
		return nil, failing
	}})
	if _, err := exec(ctx, Execution{Capability: Capability{Name: "deletePet"}, Arguments: map[string]any{"petId": "1"}}); !errors.Is(err, failing) {
		t.Fatalf("headers error: %v", err)
	}
	unreachable, _ := OpenAPIHandler([]byte(petSpec), OpenAPIHandlerOptions{BaseURL: "http://127.0.0.1:1"})
	if _, err := unreachable(ctx, Execution{Capability: Capability{Name: "deletePet"}, Arguments: map[string]any{"petId": "1"}}); err == nil {
		t.Fatal("unreachable upstream")
	}
}

func TestFilters(t *testing.T) {
	ctx := context.Background()
	get, post := OperationInfo{Name: "a", Method: http.MethodGet}, OperationInfo{Name: "b", Method: http.MethodPost}
	if ok, _ := AllOperations()(ctx, post, HostCapabilitiesContext{}); !ok {
		t.Fatal("all")
	}
	reads := OperationsWithMethod("get", "HEAD")
	if ok, _ := reads(ctx, get, HostCapabilitiesContext{}); !ok {
		t.Fatal("get")
	}
	if ok, _ := reads(ctx, post, HostCapabilitiesContext{}); ok {
		t.Fatal("post")
	}
	if StrengthForAll(StrengthWebAuthn)(get) != StrengthWebAuthn {
		t.Fatal("for all")
	}
	by := StrengthByMethod(map[string]ApprovalStrength{"post": StrengthWebAuthn})
	if by(post) != StrengthWebAuthn || by(get) != "" {
		t.Fatal("by method")
	}
}

func TestFromOpenAPISpec_BuildsOptions(t *testing.T) {
	ctx := context.Background()
	opts, err := FromOpenAPISpec([]byte(petSpec), OpenAPIOptions{
		OpenAPIHandlerOptions: OpenAPIHandlerOptions{BaseURL: "https://api.example.com"},
		HostCapabilities:      OperationsWithMethod(http.MethodGet),
		Strength:              StrengthByMethod(map[string]ApprovalStrength{http.MethodDelete: StrengthWebAuthn}),
		Location:              "https://api.example.com/agent/execute",
	})
	if err != nil {
		t.Fatal(err)
	}
	p := New(append(opts, Issuer(testIssuer), ProofOfPresence(&fakePresence{}))...)
	if err := p.Validate(nil); err != nil {
		t.Fatal(err)
	}
	if p.providerName != "Pet Store" || p.description != "Pets as a service" || len(p.capabilities) != 3 || p.onExecute == nil {
		t.Fatalf("plugin: %+v", p)
	}
	del, _ := p.capability("deletePet")
	getPet, _ := p.capability("getPet")
	if del.ApprovalStrength != StrengthWebAuthn || getPet.ApprovalStrength != "" || getPet.Location != "https://api.example.com/agent/execute" {
		t.Fatalf("strength and location: %+v %+v", del, getPet)
	}
	budget, err := p.hostBudget(ctx, HostCapabilitiesContext{})
	if err != nil || !slices.Equal(budget, []string{"getPet"}) {
		t.Fatalf("budget: %v %v", budget, err)
	}
	boom := errors.New("boom")
	opts, _ = FromOpenAPISpec([]byte(`{"paths":{"/a":{"get":{"operationId":"a"}}}}`), OpenAPIOptions{
		OpenAPIHandlerOptions: OpenAPIHandlerOptions{BaseURL: "https://api.example.com"},
		HostCapabilities: func(context.Context, OperationInfo, HostCapabilitiesContext) (bool, error) {
			return false, boom
		},
	})
	q := New(opts...)
	if q.providerName != defaultProviderName {
		t.Fatal("no title keeps the default name")
	}
	if _, err := q.hostBudget(ctx, HostCapabilitiesContext{}); !errors.Is(err, boom) {
		t.Fatalf("filter error: %v", err)
	}
	if _, err := FromOpenAPISpec([]byte("{"), OpenAPIOptions{}); !errors.Is(err, ErrBadOpenAPI) {
		t.Fatal("bad spec")
	}
	if _, err := FromOpenAPISpec([]byte(petSpec), OpenAPIOptions{}); !errors.Is(err, ErrBadOpenAPI) {
		t.Fatal("no base URL")
	}
}
