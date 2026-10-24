package agentauth

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
)

// Round c3: the branches the earlier unit tests left unasserted.

func TestMigrations_PerEngine(t *testing.T) {
	p := presencePlugin(t)
	my, err := p.TypedMigrations(auth.EngineMySQL, auth.TypesFor(auth.EngineMySQL))
	if err != nil || len(my) == 0 {
		t.Fatalf("mysql: %v", err)
	}
	// MySQL declares its indexes inside CREATE TABLE; the others create
	// them with their own statements.
	var inline, separate int
	for _, m := range my {
		for _, st := range m.Statements {
			inline += strings.Count(st, ", INDEX ")
			separate += strings.Count(st, "CREATE INDEX")
		}
	}
	if inline == 0 || separate != 0 {
		t.Fatalf("mysql indexes: %d inline, %d separate", inline, separate)
	}
	if _, err := p.TypedMigrations("oracle", auth.TypesFor("oracle")); err == nil {
		t.Fatal("an unknown engine has migrations")
	}
}

func TestInit_RefusesABaseURLThatIsNoIssuer(t *testing.T) {
	mailer := email.MailerFunc(func(context.Context, email.Mail) error { return nil })
	_, err := auth.New(auth.WithBaseURL("http://app.example.com"), auth.WithPlugins(email.New(email.Login(), email.SignInWithCode(), email.WithMailer(mailer)), New()))
	if !errors.Is(err, ErrBadIssuer) {
		t.Fatalf("plain http base URL: %v", err)
	}
}

func TestIssuerPath_UnparseableIssuer(t *testing.T) {
	if got := New(Issuer("https://[::1")).issuerPath(); got != "" {
		t.Fatalf("unparseable issuer path %q", got)
	}
}

func TestConstraint_JSONErrors(t *testing.T) {
	var c Constraint
	if err := c.UnmarshalJSON([]byte(`{"min":`)); err == nil {
		t.Fatal("a truncated operator object decoded")
	}
	inf := math.Inf(1)
	if _, err := (Constraint{Min: &inf}).MarshalJSON(); err == nil {
		t.Fatal("an infinite bound encoded")
	}
	if _, err := json.Marshal(Constraints{"amount": {Max: &inf}}); err == nil {
		t.Fatal("constraints with an infinite bound encoded")
	}
}

func TestAudience_StringOrArray(t *testing.T) {
	var a audience
	if err := json.Unmarshal([]byte(`["https://a","https://b"]`), &a); err != nil || len(a) != 2 || a[1] != "https://b" {
		t.Fatalf("array: %v %v", a, err)
	}
	if err := json.Unmarshal([]byte(`7`), &a); err == nil {
		t.Fatal("a number audience decoded")
	}
}

// beginFails is a PresenceVerifier whose user is enrolled and whose
// ceremony cannot start.
type beginFails struct{ err error }

func (beginFails) PresenceEnrolled(context.Context, string) (bool, error) { return true, nil }
func (b beginFails) BeginPresence(context.Context, string, string) (string, json.RawMessage, error) {
	return "", nil, b.err
}
func (beginFails) VerifyPresence(context.Context, string, string, string, json.RawMessage) error {
	return nil
}

func TestCheckPresence_BeginFailure(t *testing.T) {
	down := errors.New("passkey store down")
	p := presencePlugin(t, ProofOfPresence(beginFails{down}))
	if ch, err := p.checkPresence(context.Background(), "u", "ag1", nil); !errors.Is(err, down) || ch != nil {
		t.Fatalf("begin failure: %+v %v", ch, err)
	}
}

// A spec path item that is not an object is skipped; a parameter without
// a name is ignored, and an operation's parameter replaces the path's of
// the same name and location; an answer schema that is not JSON is none.
func TestFromOpenAPI_Irregular(t *testing.T) {
	spec := `{"paths": {
	  "/skip": "not an object",
	  "/items/{id}": {
	    "parameters": [{"name": "id", "in": "path", "description": "path level"}, {"in": "query"}],
	    "get": {"operationId": "getItem",
	      "parameters": [{"name": "id", "in": "path", "description": "operation level", "required": true}],
	      "responses": {"200": {"content": {"text/plain": {"schema": {"type": "string"}}}}}}
	  }}}`
	caps, err := FromOpenAPI([]byte(spec))
	if err != nil || len(caps) != 1 {
		t.Fatalf("%+v %v", caps, err)
	}
	if caps[0].Output != nil {
		t.Fatalf("a text answer has a JSON schema: %s", caps[0].Output)
	}
	var in struct {
		Properties map[string]struct {
			Description string `json:"description"`
		} `json:"properties"`
		Required []string `json:"required"`
	}
	if err := json.Unmarshal(caps[0].Input, &in); err != nil {
		t.Fatal(err)
	}
	if len(in.Properties) != 1 || in.Properties["id"].Description != "operation level" || len(in.Required) != 1 {
		t.Fatalf("parameters: %+v", in)
	}
}

// The proxy leaves out a parameter the agent did not send, refuses
// arguments it cannot encode or a path that is not a URL, and reports an
// answer cut short.
func TestOpenAPIHandler_RequestEdges(t *testing.T) {
	spec := `{"paths": {
	  "/things": {"post": {"operationId": "makeThing",
	    "parameters": [{"name": "trace", "in": "header"}],
	    "requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}}}},
	  "/bad%zz": {"get": {"operationId": "badPath"}}
	}}`
	var gotTrace []string
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTrace = r.Header.Values("Trace")
		b := make([]byte, 256)
		n, _ := r.Body.Read(b)
		gotBody = string(b[:n])
		if r.URL.Query().Get("cut") != "" || strings.Contains(gotBody, "cut") {
			w.Header().Set("Content-Length", "100")
			_, _ = w.Write([]byte(`{"partial":`))
			if hj, ok := w.(http.Hijacker); ok {
				if conn, _, err := hj.Hijack(); err == nil {
					_ = conn.Close()
				}
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	exec, err := OpenAPIHandler([]byte(spec), OpenAPIHandlerOptions{BaseURL: srv.URL, Client: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	run := func(name string, args map[string]any) (any, error) {
		return exec(context.Background(), Execution{Capability: Capability{Name: name}, Arguments: args})
	}
	if out, err := run("makeThing", map[string]any{"name": "x"}); err != nil || len(gotTrace) != 0 || gotBody != `{"name":"x"}` {
		t.Fatalf("no trace argument: %v %v %v %q", out, err, gotTrace, gotBody)
	}
	if _, err := run("makeThing", map[string]any{"name": make(chan int)}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unencodable argument: %v", err)
	}
	if _, err := run("badPath", nil); err == nil {
		t.Fatal("a path that is not a URL was requested")
	}
	if _, err := run("makeThing", map[string]any{"name": "cut"}); err == nil {
		t.Fatal("an answer cut short was accepted")
	}
}

// A pending agent's approval asks for presence unless its host is known
// and active; failing to read the host is an error, not a yes or a no.
func TestNeedsPresence_PendingAgentHostLookupFails(t *testing.T) {
	p := presencePlugin(t, ProofOfPresence(&fakePresence{}))
	need, err := p.needsPresence(context.Background(), agentRow{Status: string(AgentPending), HostID: "agh_x"}, 0, nil)
	if err == nil || need {
		t.Fatalf("no database: %v %v", need, err)
	}
}
