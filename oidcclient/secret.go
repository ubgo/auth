package oidcclient

import (
	"fmt"
	"log/slog"
)

// Secret is a credential the package holds: the client secret, an access,
// refresh or ID token. It formats as "[redacted]" under every fmt verb and
// in slog, so a session or a config printed while debugging leaks nothing.
// Reveal is the one way to read it, which makes every use greppable.
//
// It marshals to JSON as its plain value on purpose: a SessionStore
// serialises sessions to keep them, and the stored form is sealed (cookie
// store) or kept server side. Never JSON-encode a Session into a log.
type Secret string

// redacted is what a Secret prints as.
const redacted = "[redacted]"

// Reveal returns the secret's value, for the one place that must send it.
func (s Secret) Reveal() string { return string(s) }

// IsZero reports whether the secret is empty.
func (s Secret) IsZero() bool { return s == "" }

// String returns "[redacted]".
func (s Secret) String() string { return redacted }

// GoString returns "[redacted]", so %#v hides it too.
func (s Secret) GoString() string { return redacted }

// Format writes "[redacted]" for every verb, %q and %x included.
func (s Secret) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

// LogValue returns "[redacted]" for slog.
func (s Secret) LogValue() slog.Value { return slog.StringValue(redacted) }
