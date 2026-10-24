package integration

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/audit"
	"github.com/ubgo/auth/plugin/password"
)

// storedRow is one audit_event row read straight from the database, bypassing
// the plugin, so a test sees what is on disk and not what Events returns.
type storedRow struct{ severity, ip, identifier, userAgent string }

// rawRows reads the stored severity, ip, identifier and user agent of every
// audit_event row of op with the given outcome.
func rawRows(t *testing.T, e *env, op auth.EndpointID, ok bool) []storedRow {
	t.Helper()
	q := "SELECT severity, ip, identifier, user_agent FROM " + tbl(audit.TableNameEvent) + " WHERE op = " + placeholder(e, 1) + " AND ok = " + placeholder(e, 2)
	rows, err := e.db.Query(q, string(op), ok)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []storedRow
	for rows.Next() {
		var r storedRow
		if err := rows.Scan(&r.severity, &r.ip, &r.identifier, &r.userAgent); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// placeholder is the n-th bind marker of the env's engine.
func placeholder(e *env, n int) string {
	if e.engine == auth.EnginePostgres {
		return "$" + string(rune('0'+n))
	}
	return "?"
}

// TestAuditBatch4_SeverityStoredQueriedAndOverridden: the default ranks a
// failed sign-in warn, an admin ban of another user alert and a good sign-up
// info, and the severity is in the stored column, not only in the answer; the
// filters select by it; the app's map and func override it.
func TestAuditBatch4_SeverityStoredQueriedAndOverridden(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newAuditWorld(t, e)
		if _, err := w.pw.SignIn(anon(w.a), password.SignInRequest{Identifier: "bob@example.com", Password: "wrong"}); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatal(err)
		}
		if err := w.ad.Ban(w.bossCtx(), w.bob.User.ID, "spam"); err != nil {
			t.Fatal(err)
		}
		if rows := rawRows(t, e, password.EndpointSignIn, false); len(rows) != 1 || rows[0].severity != "warn" {
			t.Fatalf("stored failed sign-in = %+v", rows)
		}
		if rows := rawRows(t, e, admin.EndpointBan, true); len(rows) != 1 || rows[0].severity != "alert" {
			t.Fatalf("stored ban = %+v", rows)
		}
		if rows := rawRows(t, e, password.EndpointSignUp, true); len(rows) == 0 || rows[0].severity != "info" {
			t.Fatalf("stored sign-up = %+v", rows)
		}

		alerts := must[audit.Page](t)(w.au.Events(context.Background(), audit.Query{Severity: audit.SeverityAlert}))
		if alerts.Total != 1 || alerts.Events[0].Op != admin.EndpointBan || alerts.Events[0].Severity != audit.SeverityAlert {
			t.Fatalf("alerts = %+v", alerts)
		}
		warnUp := must[audit.Page](t)(w.au.Events(context.Background(), audit.Query{MinSeverity: audit.SeverityWarn}))
		if warnUp.Total != 2 {
			t.Fatalf("warn and above = %+v", warnUp)
		}
		// The admin route serves the same filter (it takes an audit.Query).
		viaAdmin := must[audit.Page](t)(w.ad.Audit(w.bossCtx(), audit.Query{Severity: audit.SeverityWarn}))
		if viaAdmin.Total != 1 || viaAdmin.Events[0].Op != password.EndpointSignIn {
			t.Fatalf("admin route severity filter = %+v", viaAdmin)
		}
		if none := must[audit.Page](t)(w.au.Events(context.Background(), audit.Query{Severity: "urgent"})); none.Total != 0 {
			t.Fatalf("an unknown severity must match nothing: %+v", none)
		}
	})
}

// TestAuditBatch4_SeverityOverride: the app's map ranks sign-up as alert and
// its func ranks a failed sign-in as info, in the stored column.
func TestAuditBatch4_SeverityOverride(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newAuditWorld(t, e,
			audit.Severities(map[auth.EndpointID]audit.Severity{password.EndpointSignUp: audit.SeverityAlert}),
			audit.SeverityFunc(func(ev audit.Event, cur audit.Severity) audit.Severity {
				if ev.Op == password.EndpointSignIn && !ev.OK {
					return audit.SeverityInfo
				}
				return cur
			}))
		if _, err := o.pw.SignIn(anon(o.a), password.SignInRequest{Identifier: "bob@example.com", Password: "wrong"}); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatal(err)
		}
		if rows := rawRows(t, e, password.EndpointSignUp, true); len(rows) == 0 || rows[0].severity != "alert" {
			t.Fatalf("overridden sign-up = %+v", rows)
		}
		if rows := rawRows(t, e, password.EndpointSignIn, false); len(rows) != 1 || rows[0].severity != "info" {
			t.Fatalf("overridden failed sign-in = %+v", rows)
		}
	})
}

// TestAuditBatch4_RedactionRemovesDataFromTheStoredRow: with the default
// helper on, the database holds the /24 network and the masked address, not
// the IP and the email typed, on a success, a failure and a Go-side Record;
// without the option the same calls store everything.
func TestAuditBatch4_RedactionRemovesDataFromTheStoredRow(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newAuditWorld(t, e, audit.Redact(audit.MaskPIIRedactor))
		if _, err := w.pw.SignIn(anon(w.a), password.SignInRequest{Identifier: "bob@example.com", Password: "wrong"}); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatal(err)
		}
		if err := w.au.Record(context.Background(), audit.Event{Op: "app.import", OK: true, IP: "2001:db8:abcd:1234::1", Identifier: "carol@example.com"}); err != nil {
			t.Fatal(err)
		}
		for name, rows := range map[string][]storedRow{
			"failed sign-in": rawRows(t, e, password.EndpointSignIn, false),
			"sign-up":        rawRows(t, e, password.EndpointSignUp, true),
			"go-side record": rawRows(t, e, "app.import", true),
		} {
			if len(rows) == 0 {
				t.Fatalf("%s: no stored row", name)
			}
			for _, r := range rows {
				if strings.Contains(r.ip, "203.0.113.7") || strings.Contains(r.ip, "1234") || strings.Contains(r.identifier, "bob@") || strings.Contains(r.identifier, "carol@") {
					t.Fatalf("%s: personal data in the stored row: %+v", name, r)
				}
			}
		}
		if r := rawRows(t, e, password.EndpointSignIn, false)[0]; r.ip != "203.0.113.0/24" || r.identifier != "b***@example.com" {
			t.Fatalf("stored failed sign-in = %+v", r)
		}
		if r := rawRows(t, e, "app.import", true)[0]; r.ip != "2001:db8:abcd::/48" || r.identifier != "c***@example.com" {
			t.Fatalf("stored Record = %+v", r)
		}
	})
}

// TestAuditBatch4_NoRedactorStoresWhole: the control for the test above, so
// the masking cannot be an artifact of the harness: without the option the
// same call stores the address and identifier whole.
func TestAuditBatch4_NoRedactorStoresWhole(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		plain := newAuditWorld(t, e)
		if _, err := plain.pw.SignIn(anon(plain.a), password.SignInRequest{Identifier: "bob@example.com", Password: "wrong"}); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatal(err)
		}
		found := false
		for _, r := range rawRows(t, e, password.EndpointSignIn, false) {
			found = found || (r.ip == "203.0.113.7" && r.identifier == "bob@example.com")
		}
		if !found {
			t.Fatal("without Redact the row must keep the address and identifier")
		}
	})
}
