package authhttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

// openAPIDoc is the decoded document, enough of it for the assertions.
type openAPIDoc struct {
	OpenAPI string         `json:"openapi"`
	Info    map[string]any `json:"info"`
	Servers []struct {
		URL string `json:"url"`
	} `json:"servers"`
	Tags  []struct{ Name string } `json:"tags"`
	Paths map[string]map[string]struct {
		OperationID string           `json:"operationId"`
		Tags        []string         `json:"tags"`
		Security    []map[string]any `json:"security"`
		Parameters  []map[string]any `json:"parameters"`
		RequestBody *struct {
			Content map[string]any `json:"content"`
		} `json:"requestBody"`
		Responses map[string]any `json:"responses"`
	} `json:"paths"`
	Components struct {
		Schemas         map[string]any `json:"schemas"`
		SecuritySchemes map[string]any `json:"securitySchemes"`
	} `json:"components"`
}

func decodeOpenAPI(t *testing.T, raw []byte) openAPIDoc {
	t.Helper()
	var doc openAPIDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode: %v\n%s", err, raw)
	}
	return doc
}

// TestOpenAPI_ServedOnlyWhenAsked: the route exists only with the option,
// and then answers the same bytes OpenAPIDocument writes.
func TestOpenAPI_ServedOnlyWhenAsked(t *testing.T) {
	a, _ := setup(t)
	info := authhttp.OpenAPIInfo{Title: "Test", Version: "1", Servers: []string{base}}
	without := authhttp.Handler(a, authhttp.Prefix(prefix))
	if rec := do(without, http.MethodGet, prefix+authhttp.OpenAPIPath, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("without OpenAPI: %d", rec.Code)
	}
	with := authhttp.Handler(a, authhttp.Prefix(prefix), authhttp.OpenAPI(info), authhttp.Health(), authhttp.AcceptForms())
	rec := do(with, http.MethodGet, prefix+authhttp.OpenAPIPath, "")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("GET openapi: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	want := authhttp.OpenAPIDocument(a, info, authhttp.Prefix(prefix), authhttp.Health(), authhttp.AcceptForms())
	if !bytes.Equal(rec.Body.Bytes(), want) {
		t.Fatal("the served document differs from OpenAPIDocument")
	}
	if again := authhttp.OpenAPIDocument(a, info, authhttp.Prefix(prefix), authhttp.Health(), authhttp.AcceptForms()); !bytes.Equal(want, again) {
		t.Fatal("two builds of one Auth differ: the document is not deterministic")
	}
	if rec := do(with, http.MethodPost, prefix+authhttp.OpenAPIPath, ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST openapi: %d", rec.Code)
	}

	doc := decodeOpenAPI(t, want)
	if doc.OpenAPI != authhttp.OpenAPIVersion || doc.Info["title"] != "Test" || doc.Servers[0].URL != base {
		t.Fatalf("header = %s %v %v", doc.OpenAPI, doc.Info, doc.Servers)
	}
	echo := doc.Paths[prefix+"/hp/echo"]["post"]
	if echo.OperationID != "hp.echo" || echo.Tags[0] != "hp" || echo.Security != nil {
		t.Fatalf("echo = %+v", echo)
	}
	if echo.RequestBody == nil || echo.RequestBody.Content["application/json"] == nil || echo.RequestBody.Content["application/x-www-form-urlencoded"] == nil {
		t.Fatalf("echo body = %+v", echo.RequestBody)
	}
	if echo.Responses["200"] == nil || echo.Responses["default"] == nil {
		t.Fatalf("echo responses = %v", echo.Responses)
	}
	query := doc.Paths[prefix+"/hp/query"]["get"]
	if query.RequestBody != nil || len(query.Parameters) != 1 || query.Parameters[0]["name"] != "text" {
		t.Fatalf("query = %+v", query)
	}
	health := doc.Paths[prefix+authhttp.HealthPath]["get"]
	if health.OperationID != "health" {
		t.Fatalf("health = %+v", health)
	}
	if doc.Components.Schemas["Error"] == nil || doc.Components.Schemas["authhttp_test.in"] == nil || doc.Components.Schemas["authhttp_test.out"] == nil {
		t.Fatalf("schemas = %v", keys(doc.Components.Schemas))
	}
	if doc.Components.SecuritySchemes["sessionCookie"] == nil || doc.Components.SecuritySchemes["bearerToken"] == nil {
		t.Fatalf("security schemes = %v", keys(doc.Components.SecuritySchemes))
	}
	if len(doc.Tags) != 2 || doc.Tags[0].Name != auth.CorePluginName || doc.Tags[1].Name != "hp" {
		t.Fatalf("tags = %v", doc.Tags)
	}
}

// TestOpenAPI_RequirementsBecomeSecurity: every requirement but Public lists
// both ways of being signed in, and the description says what is needed.
func TestOpenAPI_RequirementsBecomeSecurity(t *testing.T) {
	p := &reqPlugin{}
	for _, r := range auth.RequirementValues {
		p.ops = append(p.ops, auth.Define(auth.OpInfo{ID: auth.EndpointID("rq." + string(r)), Kind: auth.Query, Require: r, Path: "/" + string(r)},
			func(_ context.Context, _ *auth.Call, _ struct{}) (auth.Done, error) { return auth.Done{OK: true}, nil }))
	}
	a, err := auth.New(auth.WithBaseURL(base), auth.WithPlugins(p))
	if err != nil {
		t.Fatal(err)
	}
	doc := decodeOpenAPI(t, authhttp.OpenAPIDocument(a, authhttp.OpenAPIInfo{}, authhttp.Prefix(prefix)))
	if len(doc.Servers) != 0 {
		t.Fatalf("servers = %v without any", doc.Servers)
	}
	for _, r := range auth.RequirementValues {
		op := doc.Paths[prefix+"/rq/"+string(r)]["get"]
		if r == auth.Public {
			if op.Security != nil {
				t.Fatalf("public has security %v", op.Security)
			}
			continue
		}
		if len(op.Security) != 2 || op.Security[0]["sessionCookie"] == nil || op.Security[1]["bearerToken"] == nil {
			t.Fatalf("%s security = %v", r, op.Security)
		}
	}
}

type reqPlugin struct{ ops []auth.Operation }

func (p *reqPlugin) Name() string                 { return "rq" }
func (p *reqPlugin) SignsIn() bool                { return true }
func (p *reqPlugin) Operations() []auth.Operation { return p.ops }

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
