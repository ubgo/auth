package siwe

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// The fixed parts of an ERC-4361 message, in the order the ABNF gives them.
// A message is parsed against these exactly: the text is what the wallet
// showed the person, so a lenient parser would accept a message that read
// differently from what was verified.
const (
	headerSuffix     = " wants you to sign in with your Ethereum account:"
	schemeSeparator  = "://"
	prefixURI        = "URI: "
	prefixVersion    = "Version: "
	prefixChainID    = "Chain ID: "
	prefixNonce      = "Nonce: "
	prefixIssuedAt   = "Issued At: "
	prefixExpiration = "Expiration Time: "
	prefixNotBefore  = "Not Before: "
	prefixRequestID  = "Request ID: "
	lineResources    = "Resources:"
	prefixResource   = "- "
	lineBreak        = "\n"
)

// Version is the only message version ERC-4361 defines.
const Version = "1"

// MinNonceLength is ERC-4361's lower bound on a nonce: at least eight
// alphanumeric characters.
const MinNonceLength = 8

// MaxMessageLength bounds the message the verify operation parses. A real
// sign-in message is a few hundred bytes; 8 KiB leaves room for a long
// statement and resource list while bounding the work an anonymous caller
// can ask for.
const MaxMessageLength = 8 << 10

// ErrMessageMalformed is ParseMessage's error for text that is not an
// ERC-4361 message. The wrapped detail names the first part that failed.
var ErrMessageMalformed = errors.New("siwe: not an ERC-4361 message")

// Message is one ERC-4361 "Sign-In with Ethereum" message. ParseMessage
// reads it from the text a wallet signed; String writes it back in the same
// form, so a client in Go (or a test) builds the exact text to sign.
type Message struct {
	// Scheme is the optional URI scheme before the domain ("https"); empty
	// when the message starts with the domain.
	Scheme string
	// Domain is the RFC 3986 authority asking for the sign-in: a host with an
	// optional port, such as "app.example.com" or "localhost:3000".
	Domain string
	// Address is the signing account in its EIP-55 checksummed form, as the
	// message carries it.
	Address string
	// Statement is the optional human-readable line the wallet shows; it has
	// no line break.
	Statement string
	// URI is the resource the sign-in is for, usually the page's origin.
	URI string
	// Version is always "1".
	Version string
	// ChainID is the EIP-155 chain the account is on (1 is Ethereum mainnet).
	ChainID int64
	// Nonce is the single-use value the nonce operation handed out.
	Nonce string
	// IssuedAt is when the message was made.
	IssuedAt time.Time
	// ExpirationTime and NotBefore are the optional validity window; nil
	// when the message has none.
	ExpirationTime *time.Time
	NotBefore      *time.Time
	// RequestID is an optional system-specific identifier.
	RequestID string
	// Resources are optional URIs the person agrees to, one per line.
	Resources []string
}

// ParseMessage reads an ERC-4361 message. It checks the grammar (the order of
// the lines, an address, a version of "1", a numeric chain, an alphanumeric
// nonce, RFC 3339 times, absolute URIs) and nothing about the deployment:
// whether the domain, chain and times are acceptable is the plugin's check.
func ParseMessage(text string) (Message, error) {
	if len(text) > MaxMessageLength {
		return Message{}, malformed("longer than MaxMessageLength")
	}
	lines := strings.Split(text, lineBreak)
	r := &lineReader{lines: lines}
	var m Message

	head, ok := r.next()
	if !ok || !strings.HasSuffix(head, headerSuffix) {
		return Message{}, malformed("header")
	}
	m.Domain = strings.TrimSuffix(head, headerSuffix)
	if scheme, rest, found := strings.Cut(m.Domain, schemeSeparator); found {
		m.Scheme, m.Domain = scheme, rest
		if !validScheme(m.Scheme) {
			return Message{}, malformed("scheme")
		}
	}
	if !validAuthority(m.Domain) {
		return Message{}, malformed("domain")
	}
	if m.Address, ok = r.next(); !ok {
		return Message{}, malformed("address")
	}
	if _, err := NormalizeAddress(m.Address); err != nil {
		return Message{}, malformed("address")
	}
	if blank, ok := r.next(); !ok || blank != "" {
		return Message{}, malformed("line after the address")
	}
	// Either "" (no statement) or a statement followed by "", then the URI.
	line, ok := r.next()
	if !ok {
		return Message{}, malformed("statement")
	}
	if line != "" {
		m.Statement = line
		if blank, ok := r.next(); !ok || blank != "" {
			return Message{}, malformed("line after the statement")
		}
	}

	var err error
	if m.URI, err = r.field(prefixURI); err != nil || !absoluteURI(m.URI) {
		return Message{}, malformed("URI")
	}
	if m.Version, err = r.field(prefixVersion); err != nil || m.Version != Version {
		return Message{}, malformed("version")
	}
	chain, err := r.field(prefixChainID)
	if err != nil {
		return Message{}, malformed("chain id")
	}
	if m.ChainID, err = parseChainID(chain); err != nil {
		return Message{}, malformed("chain id")
	}
	if m.Nonce, err = r.field(prefixNonce); err != nil || !validNonce(m.Nonce) {
		return Message{}, malformed("nonce")
	}
	issued, err := r.field(prefixIssuedAt)
	if err != nil {
		return Message{}, malformed("issued at")
	}
	if m.IssuedAt, err = time.Parse(time.RFC3339Nano, issued); err != nil {
		return Message{}, malformed("issued at")
	}
	if m.ExpirationTime, err = r.optionalTime(prefixExpiration); err != nil {
		return Message{}, malformed("expiration time")
	}
	if m.NotBefore, err = r.optionalTime(prefixNotBefore); err != nil {
		return Message{}, malformed("not before")
	}
	if v, ok := r.optional(prefixRequestID); ok {
		m.RequestID = v
	}
	if r.peek() == lineResources {
		r.next()
		for strings.HasPrefix(r.peek(), prefixResource) {
			line, _ := r.next()
			res := strings.TrimPrefix(line, prefixResource)
			if !absoluteURI(res) {
				return Message{}, malformed("resource")
			}
			m.Resources = append(m.Resources, res)
		}
		if len(m.Resources) == 0 {
			return Message{}, malformed("resources")
		}
	}
	if !r.done() {
		return Message{}, malformed("text after the last field")
	}
	return m, nil
}

// String writes the message in ERC-4361 form: the exact text a wallet signs.
// ParseMessage(m.String()) returns m for any message ParseMessage accepted.
func (m Message) String() string {
	var b strings.Builder
	if m.Scheme != "" {
		b.WriteString(m.Scheme + schemeSeparator)
	}
	b.WriteString(m.Domain + headerSuffix + lineBreak)
	b.WriteString(m.Address + lineBreak + lineBreak)
	if m.Statement != "" {
		b.WriteString(m.Statement + lineBreak)
	}
	b.WriteString(lineBreak)
	b.WriteString(prefixURI + m.URI + lineBreak)
	b.WriteString(prefixVersion + m.Version + lineBreak)
	b.WriteString(prefixChainID + strconv.FormatInt(m.ChainID, 10) + lineBreak)
	b.WriteString(prefixNonce + m.Nonce + lineBreak)
	b.WriteString(prefixIssuedAt + m.IssuedAt.UTC().Format(time.RFC3339Nano))
	if m.ExpirationTime != nil {
		b.WriteString(lineBreak + prefixExpiration + m.ExpirationTime.UTC().Format(time.RFC3339Nano))
	}
	if m.NotBefore != nil {
		b.WriteString(lineBreak + prefixNotBefore + m.NotBefore.UTC().Format(time.RFC3339Nano))
	}
	if m.RequestID != "" {
		b.WriteString(lineBreak + prefixRequestID + m.RequestID)
	}
	if len(m.Resources) > 0 {
		b.WriteString(lineBreak + lineResources)
		for _, r := range m.Resources {
			b.WriteString(lineBreak + prefixResource + r)
		}
	}
	return b.String()
}

func malformed(part string) error { return errors.Join(ErrMessageMalformed, errors.New("siwe: "+part)) }

// lineReader walks the message's lines in order.
type lineReader struct {
	lines []string
	pos   int
}

func (r *lineReader) next() (string, bool) {
	if r.pos >= len(r.lines) {
		return "", false
	}
	r.pos++
	return r.lines[r.pos-1], true
}

func (r *lineReader) peek() string {
	if r.pos >= len(r.lines) {
		return ""
	}
	return r.lines[r.pos]
}

func (r *lineReader) done() bool { return r.pos >= len(r.lines) }

// field reads the next line, which must start with prefix, and returns the
// rest.
func (r *lineReader) field(prefix string) (string, error) {
	line, ok := r.next()
	if !ok || !strings.HasPrefix(line, prefix) {
		return "", ErrMessageMalformed
	}
	return strings.TrimPrefix(line, prefix), nil
}

// optional reads the next line when it starts with prefix.
func (r *lineReader) optional(prefix string) (string, bool) {
	if !strings.HasPrefix(r.peek(), prefix) {
		return "", false
	}
	line, _ := r.next()
	return strings.TrimPrefix(line, prefix), true
}

func (r *lineReader) optionalTime(prefix string) (*time.Time, error) {
	v, ok := r.optional(prefix)
	if !ok {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// parseChainID reads a positive decimal chain id without a sign or leading
// zero, so one chain has one spelling.
func parseChainID(s string) (int64, error) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 || strconv.FormatInt(n, 10) != s {
		return 0, ErrMessageMalformed
	}
	return n, nil
}

// validNonce is ERC-4361's nonce rule: at least MinNonceLength ASCII letters
// and digits.
func validNonce(s string) bool {
	if len(s) < MinNonceLength {
		return false
	}
	for _, c := range s {
		if !isAlnum(c) {
			return false
		}
	}
	return true
}

func isAlnum(c rune) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// validScheme is RFC 3986's scheme: a letter, then letters, digits, "+", "-"
// or ".".
func validScheme(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		letter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if i == 0 && !letter {
			return false
		}
		if !letter && !(c >= '0' && c <= '9') && c != '+' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

// validAuthority accepts a host with an optional port and nothing else (no
// user info, no path), the domain ERC-4361 binds the sign-in to.
func validAuthority(s string) bool {
	if s == "" || strings.ContainsAny(s, "/?#@ \t") {
		return false
	}
	u, err := url.Parse("https://" + s)
	return err == nil && u.Host == s && u.Hostname() != ""
}

// absoluteURI reports whether s parses as an absolute URI.
func absoluteURI(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme != "" && !strings.ContainsAny(s, " \t")
}
