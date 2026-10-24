package agentauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// CapabilityRequest is one requested capability: a bare name, or an object
// with a name and the constraints the agent proposes for its grant.
type CapabilityRequest struct {
	Name        string      `json:"name"`
	Constraints Constraints `json:"constraints,omitempty"`
}

// UnmarshalJSON accepts "name" or {"name": ..., "constraints": {...}}. The
// parameter is the JSON boundary the standard library mandates.
func (r *CapabilityRequest) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '"' {
		r.Constraints = nil
		return json.Unmarshal(b, &r.Name)
	}
	type plain CapabilityRequest
	var v plain
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*r = CapabilityRequest(v)
	return nil
}

// capabilityCovers reports whether a granted name covers a required one,
// "*" covers everything, "github.*" covers
// "github.create_issue", and a provider-prefixed required name
// ("acme.get_balance") is covered by its unprefixed grant.
func capabilityCovers(granted, required string) bool {
	if granted == required || granted == "*" {
		return true
	}
	if prefix, ok := strings.CutSuffix(granted, "*"); ok && strings.HasSuffix(prefix, ".") {
		return strings.HasPrefix(required, prefix)
	}
	if _, unprefixed, ok := strings.Cut(required, "."); ok {
		return granted == unprefixed
	}
	return false
}

// hasCapability reports whether any granted name covers required.
func hasCapability(granted []string, required string) bool {
	for _, g := range granted {
		if capabilityCovers(g, required) {
			return true
		}
	}
	return false
}

// checkCapabilityNames refuses a request naming nothing, too many names, a
// blocked name or, with a catalogue, a name outside it, and one that leaves
// out a capability's RequiredConstraints.
func (p *Plugin) checkCapabilityNames(reqs []CapabilityRequest) error {
	if len(reqs) > maxCapabilities {
		return ErrInvalidRequest
	}
	for _, r := range reqs {
		if r.Name == "" {
			return ErrInvalidRequest
		}
		for _, b := range p.blocked {
			if capabilityCovers(b, r.Name) {
				return ErrCapabilityBlocked
			}
		}
		if len(p.capabilities) == 0 {
			continue
		}
		def, ok := p.capability(r.Name)
		if !ok {
			return ErrInvalidCapabilities
		}
		for _, f := range def.RequiredConstraints {
			if _, ok := r.Constraints[f]; !ok {
				return ErrInvalidRequest
			}
		}
	}
	return nil
}

// grantExpiry is when a grant of capability made now expires: its
// GrantTTL, or never.
func (p *Plugin) grantExpiry(capability string) *time.Time {
	def, ok := p.capability(capability)
	if !ok || def.GrantTTL <= 0 {
		return nil
	}
	t := p.core.Now().Add(def.GrantTTL)
	return &t
}

// GrantView is a grant as the protocol shows it, section 5.3.
type GrantView struct {
	Capability  string          `json:"capability"`
	Status      GrantStatus     `json:"status"`
	GrantedBy   *string         `json:"granted_by,omitempty"`
	Constraints Constraints     `json:"constraints,omitempty"`
	ExpiresAt   *string         `json:"expires_at,omitempty"`
	Description string          `json:"description,omitempty"`
	Input       json.RawMessage `json:"input,omitempty"`
	Output      json.RawMessage `json:"output,omitempty"`
	Reason      *string         `json:"reason,omitempty"`
}

// grantViews formats grants for a response: an active grant shows
// who granted it, its constraints, expiry and the capability's schema; a
// denied one its reason.
func (p *Plugin) grantViews(grants []grantRow) []GrantView {
	out := make([]GrantView, 0, len(grants))
	for _, g := range grants {
		v := GrantView{Capability: g.Capability, Status: GrantStatus(g.Status)}
		switch GrantStatus(g.Status) {
		case GrantActive:
			v.GrantedBy, v.ExpiresAt = g.GrantedBy, timeString(g.ExpiresAt)
			v.Constraints, _ = g.constraints()
			if def, ok := p.capability(g.Capability); ok {
				v.Description, v.Input, v.Output = def.Description, def.Input, def.Output
			}
		case GrantDenied:
			v.Reason = g.Reason
		}
		out = append(out, v)
	}
	return out
}

// filterRequested keeps the grants of the requested names.
func filterRequested(grants []grantRow, reqs []CapabilityRequest) []grantRow {
	var out []grantRow
	for _, g := range grants {
		for _, r := range reqs {
			if r.Name == g.Capability {
				out = append(out, g)
				break
			}
		}
	}
	return out
}

// Approval tells the agent how the user approves it: for device
// authorization RFC 8628's shape; for CIBA only the method, the lifetime
// and the polling interval, since the request reaches the user directly.
type Approval struct {
	Method string `json:"method"`
	// DeviceCode is the approval request's id.
	DeviceCode              string `json:"device_code,omitempty"`
	VerificationURI         string `json:"verification_uri,omitempty"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	// UserCode is shown to the user, who types it on the approval page.
	UserCode  string `json:"user_code,omitempty"`
	ExpiresIn int64  `json:"expires_in"`
	Interval  int64  `json:"interval"`
}

// userCodeAlphabet leaves out 0, 1, I and O, which users misread.
const (
	userCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	userCodeLength   = 8
	userCodeGroup    = 4
	// byteRange is the number of values one random byte takes; bytes at or
	// above the largest multiple of the alphabet size are rejected so every
	// character is equally likely.
	byteRange = 256
	// randomBatch is how many random bytes are read per round; with a
	// 32-character alphabet none is rejected, so one round fills the code.
	randomBatch = 16
)

// newUserCode is eight characters from userCodeAlphabet, drawn without
// modulo bias, as "XXXX-XXXX". crypto/rand's Read never returns an error
// since Go 1.24 (it aborts the program instead), so neither does this.
func newUserCode() string {
	n := len(userCodeAlphabet)
	limit := byteRange - byteRange%n
	var out []byte
	buf := make([]byte, randomBatch)
	for len(out) < userCodeLength {
		_, _ = rand.Read(buf)
		for _, b := range buf {
			if int(b) >= limit || len(out) == userCodeLength {
				continue
			}
			out = append(out, userCodeAlphabet[int(b)%n])
		}
	}
	return string(out[:userCodeGroup]) + "-" + string(out[userCodeGroup:])
}

// normalizeUserCode upper-cases a typed code and restores its dash, so
// "abcd efgh" and "ABCD-EFGH" are one code.
func normalizeUserCode(code string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(code) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	s := b.String()
	if len(s) != userCodeLength {
		return strings.ToUpper(code)
	}
	return s[:userCodeGroup] + "-" + s[userCodeGroup:]
}

// hashUserCode is the stored form of a user code.
func hashUserCode(code string) []byte {
	sum := sha256.Sum256([]byte(normalizeUserCode(code)))
	return sum[:]
}

// userCodeMatches compares a typed code with a stored hash in constant
// time.
func userCodeMatches(code string, stored []byte) bool {
	return subtle.ConstantTimeCompare(hashUserCode(code), stored) == 1
}

// devicePageURL is the approval page: DeviceAuthorizationPage on the
// issuer's origin, or as given when absolute.
func (p *Plugin) devicePageURL() string {
	if strings.HasPrefix(p.devicePage, "https://") || strings.HasPrefix(p.devicePage, "http://") {
		return strings.TrimRight(p.devicePage, "/")
	}
	origin := p.issuer
	if i := strings.Index(origin, "://"); i >= 0 {
		if j := strings.IndexByte(origin[i+3:], '/'); j >= 0 {
			origin = origin[:i+3+j]
		}
	}
	path := p.devicePage
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return origin + path
}

// resolveApprovals moves an agent's pending approval requests to status.
func (p *Plugin) resolveApprovals(ctx context.Context, agentID string, status ApprovalStatus) error {
	_, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableApproval).Set(
		sqlb.Set(ApprovalStatusCol, string(status)), sqlb.Set(ApprovalUpdated, p.core.Now())).Where(
		sqlb.Eq(ApprovalAgent, agentID), sqlb.Eq(ApprovalStatusCol, string(ApprovalPending))))
	return err
}

// truncate cleans a display field from an agent: control characters and
// HTML tags removed, trimmed, cut to n runes (protocol section 8.10).
func truncate(s string, n int) string {
	var b strings.Builder
	inTag := false
	for _, r := range s {
		switch {
		case r == '<':
			inTag = true
		case r == '>' && inTag:
			inTag = false
		case inTag:
		case r < 0x20 && r != '\t' && r != '\n' && r != '\r', r == 0x7f:
		default:
			b.WriteRune(r)
		}
	}
	return auth.TruncateRunes(strings.TrimSpace(b.String()), n)
}
