package audit

import (
	"context"
	"net/netip"
	"strings"
)

// Redactor removes personal data from an event before it is stored or sent
// to a Sink. It runs on every write path (the pipeline hooks, rate-limit
// events and Record), after the event's severity was decided from the full
// event, so a rule such as "alert on this IP range" still sees the real
// address.
//
// The returned event replaces the original, with one invariant the plugin
// enforces: only the personal fields can change (ActorID, SessionID,
// SubjectID, ImpersonatorID, Identifier, IP, UserAgent, OrgID). ID, At, Op,
// Plugin, Transport, OK, Code, Severity and Type are restored from the
// original, so a redactor cannot make a failure look like a success or move
// an event to another operation. It must be deterministic enough to run
// twice safely and must not retain e.
//
//ds:def id=redactor-audit-2h8vn5jc owner=@khanakia stability=stable
type Redactor interface {
	Redact(ctx context.Context, e Event) Event
}

// RedactorFunc adapts a function to Redactor.
type RedactorFunc func(ctx context.Context, e Event) Event

// Redact calls f.
func (f RedactorFunc) Redact(ctx context.Context, e Event) Event { return f(ctx, e) }

// Redact installs r to run on every event before it is written. Off by
// default: without it events are stored whole. Nil is refused. Redaction
// is lossy on purpose; a masked Identifier no longer matches Query.Identifier
// for the address that was typed.
func Redact(r Redactor) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("audit.Redact", r) {
			return
		}
		p.redactor = r
	}
}

// Prefix lengths MaskPII keeps of an address: a /24 names a network
// neighbourhood for IPv4 and a /48 a site for IPv6, which is enough to spot
// a region or an ISP and not enough to name a person.
const (
	maskedIPv4Bits = 24
	maskedIPv6Bits = 48
	// maskedLocal replaces the rest of an email's local part.
	maskedLocal = "***"
)

// MaskPII is the default redaction, a RedactorFunc-compatible function: the
// IP is truncated to its /24 (IPv4) or /48 (IPv6) network address, written
// as the prefix ("203.0.113.0/24"); an IP that does not parse is dropped,
// since an unparseable value can hold anything; an Identifier that is an
// email keeps the first character of its local part and the domain
// ("b***@example.com"). Other identifiers (phone numbers, usernames) and the
// user agent are left alone: mask them with a Redactor of your own if your
// policy counts them as personal data. Use it as
// audit.Redact(audit.RedactorFunc(audit.MaskPII)) with ctx ignored, or
// through MaskPIIRedactor.
func MaskPII(e Event) Event {
	e.IP = maskIP(e.IP)
	e.Identifier = maskEmail(e.Identifier)
	return e
}

// MaskPIIRedactor is MaskPII as a Redactor, ready for Redact.
//
//ds:def id=maskpii-audit-9d4tq7wz owner=@khanakia stability=stable
var MaskPIIRedactor Redactor = RedactorFunc(func(_ context.Context, e Event) Event { return MaskPII(e) })

// maskIP truncates ip to its network prefix; "" stays "" and an address that
// does not parse becomes "".
func maskIP(ip string) string {
	if ip == "" {
		return ""
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	a = a.WithZone("").Unmap()
	bits := maskedIPv6Bits
	if a.Is4() {
		bits = maskedIPv4Bits
	}
	// PrefixFrom cannot fail for these widths (both are within the family's
	// length), unlike Addr.Prefix, whose error branch could never run.
	return netip.PrefixFrom(a, bits).Masked().String()
}

// maskEmail masks the local part of an address, leaving anything without an
// "@" untouched.
func maskEmail(s string) string {
	at := strings.LastIndex(s, "@")
	if at < 0 {
		return s
	}
	local, domain := []rune(s[:at]), s[at:]
	if len(local) == 0 {
		return maskedLocal + domain
	}
	return string(local[:1]) + maskedLocal + domain
}

// redact applies the plugin's Redactor to e and restores the fields a
// redactor may not change (see Redactor). With none installed it is e.
func (p *Plugin) redact(ctx context.Context, e Event) Event {
	if p.redactor == nil {
		return e
	}
	r := p.redactor.Redact(ctx, e)
	r.ID, r.At, r.Op, r.Plugin, r.Transport = e.ID, e.At, e.Op, e.Plugin, e.Transport
	r.OK, r.Code, r.Severity, r.Type = e.OK, e.Code, e.Severity, e.Type
	return r
}
