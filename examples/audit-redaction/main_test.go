package main

import (
	"bytes"
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/audit"
	"github.com/ubgo/auth/plugin/email"
)

// remoteAddr is the client address the requests come from; its /24 is what
// the log may keep.
const (
	remoteAddr   = "203.0.113.77:50000"
	maskedIP     = "203.0.113.0/24"
	aliceAddress = "alice@example.com"
	goodPassword = "correct horse battery staple"
)

// TestAuditRedaction: a sign-up is ranked warn by the app's map, a failed
// sign-in warn by the default, the monitoring account's failure info by the
// app's func, and the stored rows (read from the database, not through the
// plugin) hold the masked address and email and not the raw ones.
func TestAuditRedaction(t *testing.T) {
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	a, au, err := newApp(db, discardMailer{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := authhttp.Handler(a, authhttp.Prefix(authPrefix))

	send(t, h, "/auth/password/sign-up", `{"identifier":"`+aliceAddress+`","password":"`+goodPassword+`","name":"Alice"}`, http.StatusOK)
	send(t, h, "/auth/password/sign-in", `{"identifier":"`+aliceAddress+`","password":"wrong"}`, http.StatusUnauthorized)
	send(t, h, "/auth/password/sign-in", `{"identifier":"`+monitorAddress+`","password":"wrong"}`, http.StatusUnauthorized)

	rows, err := db.Query("SELECT op, ok, identifier, ip, severity FROM audit_event ORDER BY op, severity, identifier")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var op, identifier, ip, severity string
		var ok bool
		if err := rows.Scan(&op, &ok, &identifier, &ip, &severity); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(ip, "203.0.113.77") || strings.Contains(identifier, "alice@") || strings.Contains(identifier, "monitor@") {
			t.Fatalf("raw personal data stored: %s %s %s", op, identifier, ip)
		}
		if ip != maskedIP {
			t.Fatalf("stored ip = %q, want %q", ip, maskedIP)
		}
		got = append(got, op+"|"+identifier+"|"+severity)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"password.sign-in|m***@example.com|info",
		"password.sign-in|a***@example.com|warn",
		"password.sign-up|a***@example.com|warn",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("stored rows:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// The same filters the plugin serves: warn and above is two rows.
	page, err := au.Events(context.Background(), audit.Query{MinSeverity: audit.SeverityWarn})
	if err != nil || page.Total != 2 {
		t.Fatalf("warn and above = %+v %v", page, err)
	}
}

// send posts body to path from remoteAddr and checks the status.
func send(t *testing.T, h http.Handler, path, body string, status int) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
	r.RemoteAddr = remoteAddr
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", baseURL)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != status {
		t.Fatalf("POST %s = %d, want %d: %s", path, w.Code, status, w.Body)
	}
}

// discardMailer drops every mail.
type discardMailer struct{}

// Send drops m.
func (discardMailer) Send(context.Context, email.Mail) error { return nil }
