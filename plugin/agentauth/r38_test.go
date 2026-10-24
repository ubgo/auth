package agentauth

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
)

func TestCanonicalMetadata_ObjectsOfPrimitivesOnly(t *testing.T) {
	got, err := canonicalMetadata(json.RawMessage(` {"z": 1.50, "a": "x", "b": true, "n": null} `))
	if err != nil || got != `{"a":"x","b":true,"n":null,"z":1.50}` {
		t.Fatalf("canonical: %q %v", got, err)
	}
	if got, err := canonicalMetadata(json.RawMessage(`{}`)); err != nil || got != `{}` {
		t.Fatalf("empty object: %q %v", got, err)
	}
	for _, raw := range []string{`null`, `[]`, `"x"`, `{"a":{}}`, `{"a":[]}`, `{} {}`, `{"a":`, `{"a":"` + strings.Repeat("x", maxMetadataBytes) + `"}`} {
		if _, err := canonicalMetadata(json.RawMessage(raw)); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("%.40s: %v, want ErrInvalidRequest", raw, err)
		}
	}
}

func TestConfiguration_ClaimOnlyWithAutonomousMode(t *testing.T) {
	c, _ := newPlugin().doConfiguration(context.Background(), nil, struct{}{})
	if c.Endpoints["claim"] != testIssuer+PathClaim || c.Endpoints["revoke_host"] != testIssuer+PathRevokeHost || c.Endpoints["revoke_capability"] != testIssuer+PathRevokeCapability {
		t.Fatalf("both modes: %v", c.Endpoints)
	}
	c, _ = newPlugin(Modes(ModeDelegated)).doConfiguration(context.Background(), nil, struct{}{})
	if _, ok := c.Endpoints["claim"]; ok {
		t.Fatalf("claim listed without autonomous agents: %v", c.Endpoints)
	}
}

func TestMigrations_AddTheApprovalKind(t *testing.T) {
	p := New()
	mailer := email.MailerFunc(func(context.Context, email.Mail) error { return nil })
	if _, err := auth.New(auth.WithBaseURL(testIssuer), auth.WithPlugins(email.New(email.Login(), email.SignInWithCode(), email.WithMailer(mailer)), p)); err != nil {
		t.Fatal(err)
	}
	for _, engine := range []string{auth.EngineSQLite, auth.EnginePostgres, auth.EngineMySQL} {
		ms, err := p.TypedMigrations(engine, auth.TypesFor(engine))
		if err != nil || len(ms) != 3 || ms[1].Name != migrationKind || len(ms[1].Statements) != 1 ||
			ms[1].Statements[0] != "ALTER TABLE "+TableNameApproval+" ADD COLUMN "+ColKind+" "+auth.TypesFor(engine).Key+" NULL" {
			t.Fatalf("%s: %+v %v", engine, ms, err)
		}
	}
}

// The checks that need no database: missing credentials, an empty
// capability list, and a claim that is not one.
func TestManage_RefusesBeforeTheDatabase(t *testing.T) {
	ctx := context.Background()
	p := newPlugin()
	if _, err := p.callerAgent(ctx, &auth.Call{}, Bearer{}, "agt_x"); !errors.Is(err, ErrAuthenticationRequired) {
		t.Errorf("callerAgent without credentials: %v", err)
	}
	if _, err := p.doRevokeHost(ctx, &auth.Call{}, RevokeHostRequest{HostID: "agh_x"}); !errors.Is(err, ErrAuthenticationRequired) {
		t.Errorf("revoke host without credentials: %v", err)
	}
	if _, err := p.doRevokeCapability(ctx, &auth.Call{}, RevokeCapabilityRequest{AgentID: "agt_x"}); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("revoke no capability: %v", err)
	}
	if _, err := p.doClaim(ctx, &auth.Call{}, ClaimRequest{AgentID: "agt_x"}); !errors.Is(err, ErrAuthenticationRequired) {
		t.Errorf("claim without a token: %v", err)
	}
	claim := ApprovalKindClaim
	delegated := agentRow{Mode: string(ModeDelegated)}
	autonomous := agentRow{Mode: string(ModeAutonomous)}
	cases := []struct {
		name  string
		agent agentRow
		named *approvalRow
		want  error
	}{
		{"delegated agent", delegated, &approvalRow{Kind: &claim, Status: string(ApprovalPending)}, nil},
		{"named capability request", autonomous, &approvalRow{Status: string(ApprovalPending)}, nil},
		{"named resolved claim", autonomous, &approvalRow{Kind: &claim, Status: string(ApprovalApproved)}, ErrApprovalResolved},
		{"named claim, wrong code", autonomous, &approvalRow{Kind: &claim, Status: string(ApprovalPending), CodeHash: hashUserCode("ABCD-EFGH")}, ErrInvalidUserCode},
	}
	for _, c := range cases {
		row, err := p.matchClaim(ctx, c.agent, "WXYZ-WXYZ", c.named)
		if row != nil || !errors.Is(err, c.want) {
			t.Errorf("%s: %+v %v, want %v", c.name, row, err, c.want)
		}
	}
}
