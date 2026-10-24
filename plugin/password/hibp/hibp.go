// Package hibp checks passwords against the Have I Been Pwned range API, for
// password.CheckBreached.
//
// Only the first five hex characters of the password's SHA-1 leave the
// process (k-anonymity): the service answers with every suffix it knows under
// that prefix, and the match happens here. Responses are padded, so the size
// of the answer does not hint at the prefix either.
package hibp

import (
	"bufio"
	"context"
	"crypto/sha1" // the range API is keyed by SHA-1; it is an index, not a password hash
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultBaseURL is the public range API.
const DefaultBaseURL = "https://api.pwnedpasswords.com/range/"

// DefaultTimeout bounds one lookup. The check runs inside a sign-up request,
// so a slow service must fail it in seconds, not hang it.
const DefaultTimeout = 5 * time.Second

// prefixLen is how many hex characters of the hash are sent: five is the
// range API's fixed prefix length.
const prefixLen = 5

// maxBody bounds a response: a padded range answer is about 30 KB.
const maxBody = 1 << 20

// paddingHeader asks the range API to pad its answer with count-0 rows, so the
// response size does not reveal how many suffixes share the prefix.
const (
	paddingHeader = "Add-Padding"
	paddingOn     = "true"
)

// paddingCount is the count a padding row carries; it is not a breach.
const paddingCount = "0"

// Checker implements password.BreachChecker against the range API. It is
// safe for concurrent use; build one with New and share it.
type Checker struct {
	baseURL string
	hc      *http.Client
	// failOpen decides the answer when the service is unreachable.
	failOpen bool
	// message words the refusal; empty keeps password.ErrBreached's.
	message string
}

// Option configures the checker; pass options to New.
type Option func(*Checker)

// WithBaseURL points the checker at another server, such as a self-hosted
// mirror or a test server.
func WithBaseURL(u string) Option { return func(c *Checker) { c.baseURL = u } }

// WithHTTPClient replaces the client, such as to add a proxy or tracing. The
// replacement's own timeout applies instead of DefaultTimeout.
func WithHTTPClient(hc *http.Client) Option { return func(c *Checker) { c.hc = hc } }

// FailOpen accepts the password when the service cannot be reached, instead
// of failing the sign-up. The default is to return the error, because a
// silent pass is a check that never runs; an app that prefers availability
// names that choice here.
func FailOpen() Option { return func(c *Checker) { c.failOpen = true } }

// WithMessage words the refusal of a breached password. The password plugin
// answers password.breached with this message instead of the declared one;
// the code and the status stay, and a WithMessages catalogue entry for the
// code still wins in its locale. See password.BreachMessenger.
//
//ds:def id=hibp-withmessage-3nq8xw5k owner=@khanakia stability=stable
func WithMessage(msg string) Option { return func(c *Checker) { c.message = msg } }

// BreachedMessage is the WithMessage text, or "" for the default; it makes
// the checker a password.BreachMessenger.
func (c *Checker) BreachedMessage() string { return c.message }

// New builds a checker for the public API.
func New(opts ...Option) *Checker {
	c := &Checker{baseURL: DefaultBaseURL, hc: &http.Client{Timeout: DefaultTimeout}}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Breached reports whether password appears in a known breach. Padding rows
// never count as a match. When the service cannot answer it returns the error,
// or false with FailOpen.
func (c *Checker) Breached(ctx context.Context, password string) (bool, error) {
	sum := sha1.Sum([]byte(password))
	full := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := full[:prefixLen], full[prefixLen:]
	found, err := c.lookup(ctx, prefix, suffix)
	if err != nil {
		if c.failOpen {
			return false, nil
		}
		return false, fmt.Errorf("hibp: %w", err)
	}
	return found, nil
}

func (c *Checker) lookup(ctx context.Context, prefix, suffix string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+prefix, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set(paddingHeader, paddingOn)
	res, err := c.hc.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, res.Body)
		return false, fmt.Errorf("range API answered %d", res.StatusCode)
	}
	found := false
	sc := bufio.NewScanner(io.LimitReader(res.Body, maxBody))
	for sc.Scan() {
		line := sc.Text()
		s, count, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		// Padding rows carry a count of 0 and are not breaches. Every row is
		// compared, so the time taken does not depend on where a match is.
		if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(s)), []byte(suffix)) == 1 && strings.TrimSpace(count) != paddingCount {
			found = true
		}
	}
	return found, sc.Err()
}
