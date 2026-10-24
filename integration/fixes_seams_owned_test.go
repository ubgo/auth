package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauthprovider"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/scim"
)

// Without auth.WithSecret, RP-initiated logout cannot sign its confirmation,
// so it is turned off rather than failing at its first request: a client
// cannot be given EnableEndSession (ErrNoSecret from CreateClient and
// UpdateClient), discovery does not advertise end_session_endpoint, and a
// browser that reaches the endpoint anyway gets 400 invalid_request, where
// it used to get 500 "auth: no secret configured".
func TestOAuthProvider_EndSessionWithoutASecret(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnvWith(t, e, nil)
		ctx := context.Background()
		spec := oauthprovider.ClientSpec{EnableEndSession: true, ClientMetadata: oauthprovider.ClientMetadata{Name: "rp", RedirectURIs: []string{opRedirect}}}
		if _, err := o.op.CreateClient(ctx, spec); !errors.Is(err, oauthprovider.ErrNoSecret) {
			t.Fatalf("create with EnableEndSession = %v, want ErrNoSecret", err)
		}
		spec.EnableEndSession = false
		reg := must[oauthprovider.Registration](t)(o.op.CreateClient(ctx, spec))
		spec.EnableEndSession = true
		if _, err := o.op.UpdateClient(ctx, reg.ClientID, spec); !errors.Is(err, oauthprovider.ErrNoSecret) {
			t.Fatalf("update to EnableEndSession = %v, want ErrNoSecret", err)
		}

		h := o.op.Handler()
		w := c1Do(h, http.MethodGet, "/.well-known/openid-configuration", "", "", nil)
		var doc map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil || w.Code != http.StatusOK {
			t.Fatalf("discovery = %d %s", w.Code, w.Body)
		}
		if _, ok := doc["end_session_endpoint"]; ok {
			t.Fatalf("end_session_endpoint advertised without a secret: %v", doc["end_session_endpoint"])
		}
		w = c1Do(h, http.MethodGet, "/oauth2/end-session", "", "", http.Header{"Accept": {"text/html"}, "Cookie": {"__Host-auth_session=" + o.token.Reveal()}})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("end-session without a hint = %d %s, want 400", w.Code, w.Body)
		}
	})
}

// A managed credential of a decommissioned connection answers what its
// static peers answer, 401 "SCIM connection is decommissioned", because its
// digest matched first and so the caller already holds the token. A revoked
// credential, and a token naming a real credential with the wrong secret,
// still answer "Invalid SCIM bearer token", so nothing is told to a caller
// that does not hold a working token.
func TestSCIM_DecommissionedManagedTokenIsToldSo(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newSCIMWorld(t, e, scim.ManagedConnections(scim.CredentialHashSecret([]byte(proxySecret)), scim.MaxActiveCredentials(2)))
		ctx := context.Background()
		made := must[scim.IssuedCredential](t)(w.sp.CreateManagedConnection(ctx, scim.CreateManagedRequest{CreationRequestID: "req-0000000000009", ProvisioningDomainID: "tenant-1", ActorID: "admin"}))
		rot := must[scim.IssuedCredential](t)(w.sp.RotateCredential(ctx, made.Connection.ID, "tenant-1", "admin", nil, nil))
		if err := w.sp.RevokeCredential(ctx, made.Connection.ID, "tenant-1", made.Credential.ID, "admin"); err != nil {
			t.Fatal(err)
		}
		if _, err := w.sp.DecommissionConnection(ctx, scim.DecommissionRequest{ConnectionID: made.Connection.ID, ProvisioningDomainID: "tenant-1", ActorID: "admin"}); err != nil {
			t.Fatal(err)
		}
		live := rot.Token.Reveal()
		// The same credential id with a different last secret character.
		last := "A"
		if strings.HasSuffix(live, last) {
			last = "B"
		}
		forged := live[:len(live)-1] + last
		for name, c := range map[string]struct{ token, detail string }{
			"decommissioned": {live, "SCIM connection is decommissioned"},
			"revoked":        {made.Token.Reveal(), "Invalid SCIM bearer token"},
			"wrong secret":   {forged, "Invalid SCIM bearer token"},
		} {
			code, body := w.do(t, http.MethodGet, "/Users", c.token, "")
			if code != http.StatusUnauthorized || body["detail"] != c.detail {
				t.Errorf("%s: %d %v, want 401 %q", name, code, body["detail"], c.detail)
			}
		}
	})
}

// Organization hooks built by WithHooksFrom get the *auth.Auth, and
// a.Conn(ctx) inside a hook is the operation's own transaction: the app's
// row written by AfterCreateOrg commits with the organization, is rolled
// back with it when the hook then fails, and BeforeDeleteOrg's delete is
// rolled back when a later hook refuses. Before WithHooksFrom a hook had
// only ctx and the app had to bind the Auth into a variable after auth.New.
func TestOrganization_HooksFromWriteInTheOperationsTransaction(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		table := tbl("app_project")
		if _, err := e.db.Exec("CREATE TABLE " + table + " (org_id VARCHAR(64) NOT NULL)"); err != nil {
			t.Fatal(err)
		}
		veto := errors.New("veto")
		rows := func(orgID string) int {
			t.Helper()
			var n int
			if err := e.db.QueryRow("SELECT COUNT(*) FROM "+table+" WHERE org_id = "+e.d.Placeholder(1), orgID).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n
		}
		write := func(ctx context.Context, a *auth.Auth, q, orgID string) error {
			conn, err := a.Conn(ctx)
			if err != nil {
				return err
			}
			_, err = conn.ExecContext(ctx, q, orgID)
			return err
		}
		insert := "INSERT INTO " + table + " (org_id) VALUES (" + e.d.Placeholder(1) + ")"
		remove := "DELETE FROM " + table + " WHERE org_id = " + e.d.Placeholder(1)
		var failed string
		w := orgSetup(t, e, organization.WithHooksFrom(func(a *auth.Auth) organization.Hooks {
			return organization.Hooks{
				AfterCreateOrg: func(ctx context.Context, org organization.Org, _ auth.User) error {
					if err := write(ctx, a, insert, org.ID); err != nil {
						return err
					}
					if org.Slug == "fails" {
						failed = org.ID
						return veto
					}
					return nil
				},
				BeforeDeleteOrg: func(ctx context.Context, org organization.Org) error {
					return write(ctx, a, remove, org.ID)
				},
				AfterDeleteOrg: func(context.Context, organization.Org) error { return veto },
			}
		}))
		if rows(w.o.ID) != 1 {
			t.Fatalf("the created organization's row was not written")
		}
		owner := request(w.a, w.owner.Token)
		if _, err := w.org.Create(owner, organization.CreateRequest{Name: "Fails", Slug: "fails"}); !errors.Is(err, veto) {
			t.Fatalf("failing hook: %v", err)
		}
		if failed == "" || rows(failed) != 0 || count(t, e, organization.TableNameOrg) != 1 {
			t.Fatalf("a failed create left its row (%q) or its organization", failed)
		}
		if err := w.org.Delete(owner, w.o.ID); !errors.Is(err, veto) {
			t.Fatalf("refused delete: %v", err)
		}
		if rows(w.o.ID) != 1 {
			t.Fatal("BeforeDeleteOrg's delete survived the refused delete")
		}
	})
}

// WithHooks and WithHooksFrom together are refused: one would silently
// replace the other.
func TestOrganization_HooksAndHooksFromRefused(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		org := organization.New(organization.WithHooks(organization.Hooks{}), organization.WithHooksFrom(func(*auth.Auth) organization.Hooks { return organization.Hooks{} }))
		if _, err := auth.New(e.withDB(), auth.WithBaseURL(testBaseURL), auth.WithPlugins(e.emailPlugin(), e.passwordPlugin(), org)); err == nil || !strings.Contains(err.Error(), "not both") {
			t.Fatalf("both hooks options = %v", err)
		}
	})
}
