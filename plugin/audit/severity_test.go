package audit

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/ubgo/auth"
)

// TestDefaultSeverity pins the default ranking: it is the policy a reviewer
// reads the log by, so each rule has its row.
func TestDefaultSeverity(t *testing.T) {
	for name, tc := range map[string]struct {
		e    Event
		want Severity
	}{
		"sign-in ok":               {Event{Op: "password.sign-in", OK: true, ActorID: "u"}, SeverityInfo},
		"sign-in failed":           {Event{Op: "password.sign-in", Code: "auth.invalid_credentials"}, SeverityWarn},
		"rate blocked":             {Event{Op: "password.sign-in", Code: "rate.blocked"}, SeverityWarn},
		"rate challenged":          {Event{Op: "password.sign-in", Code: "rate.challenged"}, SeverityWarn},
		"rate logged":              {Event{Op: "password.sign-in", OK: true, Code: "rate.logged"}, SeverityInfo},
		"rate challenge passed":    {Event{Op: "password.sign-in", OK: true, Code: "rate.challenge_passed"}, SeverityInfo},
		"admin ban of another":     {Event{Op: "admin.ban", OK: true, ActorID: "a", SubjectID: "b"}, SeverityAlert},
		"admin impersonate":        {Event{Op: "admin.impersonate", OK: true, ActorID: "a", SubjectID: "b"}, SeverityAlert},
		"admin set password":       {Event{Op: "admin.set-password", OK: true, ActorID: "a", SubjectID: "b"}, SeverityAlert},
		"admin edit of another":    {Event{Op: "admin.update-user", OK: true, ActorID: "a", SubjectID: "b"}, SeverityWarn},
		"admin ban refused":        {Event{Op: "admin.ban", ActorID: "a", SubjectID: "b", Code: "auth.forbidden"}, SeverityWarn},
		"admin op on self":         {Event{Op: "admin.update-user", OK: true, ActorID: "a", SubjectID: "a"}, SeverityInfo},
		"own password change":      {Event{Op: "password.change", OK: true, ActorID: "a"}, SeverityInfo},
		"non-admin op with target": {Event{Op: "organization.remove-member", OK: true, ActorID: "a", SubjectID: "b"}, SeverityInfo},
	} {
		if got := DefaultSeverity(tc.e); got != tc.want {
			t.Errorf("%s: severity = %q, want %q", name, got, tc.want)
		}
	}
}

// TestSeverityOf_MapThenFunc: the app's map overrides the default for an
// operation, the func sees and may replace that result, and a func that
// returns garbage cannot write an unfilterable row.
func TestSeverityOf_MapThenFunc(t *testing.T) {
	signInOK := Event{Op: "password.sign-in", OK: true}
	p := newPlugin(t, Severities(map[auth.EndpointID]Severity{"password.sign-in": SeverityAlert}))
	if got := p.severityOf(signInOK); got != SeverityAlert {
		t.Fatalf("mapped severity = %q", got)
	}
	var sawCurrent Severity
	p = newPlugin(t,
		Severities(map[auth.EndpointID]Severity{"password.sign-in": SeverityWarn}),
		SeverityFunc(func(e Event, cur Severity) Severity {
			sawCurrent = cur
			if e.ActorID == "vip" {
				return SeverityAlert
			}
			return "bogus"
		}))
	if got := p.severityOf(Event{Op: "password.sign-in", OK: true, ActorID: "vip"}); got != SeverityAlert || sawCurrent != SeverityWarn {
		t.Fatalf("func result = %q (saw current %q)", got, sawCurrent)
	}
	if got := p.severityOf(signInOK); got != SeverityWarn {
		t.Fatalf("an invalid func result must fall back to the incoming severity, got %q", got)
	}
}

// TestSeverities_UnknownValueFailsInit: a typo in the map is refused when the
// app starts.
func TestSeverities_UnknownValueFailsInit(t *testing.T) {
	p := New(Severities(map[auth.EndpointID]Severity{"password.sign-in": "urgent"}))
	if _, err := auth.New(auth.WithPlugins(signIn{}, p)); err == nil || !strings.Contains(err.Error(), "urgent") {
		t.Fatalf("auth.New = %v, want the unknown severity named", err)
	}
}

// TestAtLeast: MinSeverity expands to the severity and everything above.
func TestAtLeast(t *testing.T) {
	if got := atLeast(SeverityWarn); len(got) != 2 || got[0] != "warn" || got[1] != "alert" {
		t.Fatalf("atLeast(warn) = %v", got)
	}
	if got := atLeast("nope"); got != nil {
		t.Fatalf("atLeast(unknown) = %v", got)
	}
}

// TestMaskPII: IPv4 to /24, IPv6 (and v4-mapped) to /48, an unparseable IP
// dropped, an email's local part masked, other identifiers untouched.
func TestMaskPII(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.77":                    "203.0.113.0/24",
		"2001:db8:abcd:1234:5678::1":      "2001:db8:abcd::/48",
		"::ffff:198.51.100.9":             "198.51.100.0/24",
		"fe80::1%eth0":                    "fe80::/48",
		"not an ip, maybe a name or mail": "",
		"":                                "",
	} {
		if got := maskIP(in); got != want {
			t.Errorf("maskIP(%q) = %q, want %q", in, got, want)
		}
		if got := maskIP(in); got != "" {
			if _, err := netip.ParsePrefix(got); err != nil {
				t.Errorf("maskIP(%q) = %q is not a prefix", in, got)
			}
		}
	}
	for in, want := range map[string]string{
		"bob@example.com": "b***@example.com", "@example.com": "***@example.com",
		"+15551234567": "+15551234567", "bobby": "bobby", "": "",
	} {
		if got := maskEmail(in); got != want {
			t.Errorf("maskEmail(%q) = %q, want %q", in, got, want)
		}
	}
	e := MaskPII(Event{IP: "203.0.113.7", Identifier: "bob@example.com", UserAgent: "UA"})
	if e.IP != "203.0.113.0/24" || e.Identifier != "b***@example.com" || e.UserAgent != "UA" {
		t.Fatalf("MaskPII = %+v", e)
	}
}

// TestRedact_KeepsTheFactsOfTheEvent: whatever a redactor returns, the
// operation, outcome, code, severity and type of the event are restored, and
// the personal fields it changed stay changed.
func TestRedact_KeepsTheFactsOfTheEvent(t *testing.T) {
	p := newPlugin(t, Redact(RedactorFunc(func(_ context.Context, e Event) Event {
		e.Op, e.OK, e.Code, e.Severity, e.Type, e.ID = "forged", true, "forged", SeverityInfo, "forged", "forged"
		e.IP, e.Identifier, e.UserAgent = "", "gone", ""
		return e
	})))
	in := Event{ID: "aud_1", Op: "password.sign-in", Code: "auth.x", Severity: SeverityWarn, Type: TypeUserSignedIn, IP: "203.0.113.7", Identifier: "bob@example.com", UserAgent: "UA"}
	out := p.redact(context.Background(), in)
	if out.Op != in.Op || out.OK != in.OK || out.Code != in.Code || out.Severity != in.Severity || out.Type != in.Type || out.ID != in.ID {
		t.Fatalf("facts changed: %+v", out)
	}
	if out.IP != "" || out.Identifier != "gone" || out.UserAgent != "" {
		t.Fatalf("personal fields not redacted: %+v", out)
	}
}

// TestRecord_SinkSeesSeverityAndRedactedEvent: the sink gets the severity
// decided from the whole event and the redacted personal fields, through
// every write path (Record here; the hooks and RateEvent share record).
func TestRecord_SinkSeesSeverityAndRedactedEvent(t *testing.T) {
	var got []Event
	p := newPlugin(t, To(SinkFunc(func(_ context.Context, e Event) error { got = append(got, e); return nil })),
		Redact(MaskPIIRedactor),
		SeverityFunc(func(e Event, cur Severity) Severity {
			if e.IP == "203.0.113.7" { // the real address, not the masked one
				return SeverityAlert
			}
			return cur
		}))
	if err := p.Record(context.Background(), Event{Op: "password.sign-in", OK: true, IP: "203.0.113.7", Identifier: "bob@example.com"}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Severity != SeverityAlert || got[0].IP != "203.0.113.0/24" || got[0].Identifier != "b***@example.com" {
		t.Fatalf("sink got %+v", got)
	}
}
