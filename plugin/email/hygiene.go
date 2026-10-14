package email

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ubgo/auth"
)

// AddressCheck decides whether a new address may be stored: at sign-up, when
// an address is added, and when one is changed (before the confirm mail goes
// out, and again when the row is written). It never runs at sign-in, so an
// account created before a check was switched on keeps working. Return
// ErrAddressRejected (or any auth.Error) to refuse the address; any other
// error is a failure of the check itself and fails the request.
//
// A check runs inside the writing transaction, so it must be quick: the
// built-in RequireMX bounds its lookup with a timeout.
type AddressCheck func(ctx context.Context, address string) error

// ErrAddressRejected refuses an address an AddressCheck turned down. Its
// message names no reason, so the answer is the same whether the domain is
// blocked or has no mail server.
var ErrAddressRejected = auth.NewError("email.address_rejected", http.StatusBadRequest, "This email address cannot be used. Use another one.")

// CheckAddresses runs every check, in order, on each new address; the first
// refusal wins. It is the hook better-auth-harmony and Sentinel's email
// validation fill: BlockDomains for a disposable-domain list, RequireMX for a
// domain that can receive mail, or the app's own function.
func CheckAddresses(checks ...AddressCheck) Option {
	return func(p *Plugin) {
		if auth.RefuseNilEach(&p.optErrs, "email.CheckAddresses", checks) {
			return
		}
		p.checks = append(p.checks, checks...)
	}
}

// checkAddress runs the configured checks on a stored-form address.
func (p *Plugin) checkAddress(ctx context.Context, address string) error {
	for _, check := range p.checks {
		if err := check(ctx, address); err != nil {
			return err
		}
	}
	return nil
}

// domainOf is the part after the last "@", folded to lower case: a domain is
// case-insensitive whatever normalizer stored the address.
func domainOf(address string) string {
	return strings.ToLower(address[strings.LastIndexByte(address, '@')+1:])
}

// BlockDomains refuses an address whose domain is one of domains or a
// subdomain of one ("mailinator.com" also blocks "x.mailinator.com").
// Domains are compared in lower case with any trailing dot removed. The
// library ships no list, because a list goes stale and its choice is the
// app's: load one with ParseDomainList, for example the disposable-email-domains
// project's blocklist that better-auth-harmony's own list is built from.
func BlockDomains(domains ...string) AddressCheck {
	set := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		if d = canonDomain(d); d != "" {
			set[d] = struct{}{}
		}
	}
	return func(_ context.Context, address string) error {
		for d := domainOf(address); d != ""; {
			if _, ok := set[d]; ok {
				return ErrAddressRejected
			}
			dot := strings.IndexByte(d, '.')
			if dot < 0 {
				break
			}
			d = d[dot+1:]
		}
		return nil
	}
}

// subdomainWildcard opens an AllowDomains entry to every subdomain:
// "*.acme.edu" allows "cs.acme.edu" and "a.b.acme.edu", never "acme.edu".
const subdomainWildcard = "*."

// ErrBadDomainList is AllowDomains given no domain, or an entry that names
// none ("", "*.", "*", or one holding "@" or another "*"). auth.New refuses
// the plugin with it, naming the option and the entry: a list that allows
// nobody is a configuration mistake to stop at start-up, because at the
// first sign-up it would refuse everyone.
var ErrBadDomainList = errors.New("email: AllowDomains needs at least one domain, and every entry must name one")

// AllowDomains refuses every new address whose domain the list does not
// name: the allow-list counterpart of BlockDomains, for an app open only to
// one company's or one university's people. It is an option rather than an
// AddressCheck so a bad list fails auth.New (ErrBadDomainList) instead of
// panicking or refusing every sign-up. Its check joins the ones
// CheckAddresses adds and runs where it stands among the options, so give it
// before CheckAddresses(RequireMX(…)) to refuse an outside address without a
// DNS lookup. Like every address check it runs on sign-up, on an added
// address and on a changed one, never at sign-in, so an account made before
// the list existed keeps working. Giving it twice requires both lists.
//
// An entry matches exactly: "acme.com" allows "pat@acme.com" and nothing
// else, neither "pat@eu.acme.com" nor "pat@notacme.com". A subdomain is
// allowed only when asked for, with a leading "*.": "*.acme.com" allows
// "pat@eu.acme.com" and "pat@a.b.acme.com" but not "pat@acme.com", so list
// both to allow both. Exact by default because an allow-list grants access:
// a subdomain is often run by someone else (a student society, a customer's
// tenant on a shared host), and nobody should be let in by a rule they did
// not write. Entries and addresses are compared in lower case with any
// trailing dot removed; a name in Unicode must be listed in the form the
// email plugin stores it (punycode unless WithNormalizer changes that).
//
// A refused address gets ErrAddressRejected, the same answer as a blocked
// domain or a domain with no mail server, and no row is read, so the answer
// tells nothing about which accounts exist. Load a long list with
// ParseDomainList.
func AllowDomains(domains ...string) Option {
	return func(p *Plugin) {
		check, err := allowList(domains)
		if err != nil {
			p.optErrs.JoinOptionErr(err)
			return
		}
		p.checks = append(p.checks, check)
	}
}

// allowList builds AllowDomains' check, or ErrBadDomainList naming the
// option and the entry that names no domain.
func allowList(domains []string) (AddressCheck, error) {
	exact := make(map[string]struct{}, len(domains))
	under := make(map[string]struct{}, len(domains))
	for _, raw := range domains {
		d := canonDomain(raw)
		set := exact
		if rest, ok := strings.CutPrefix(d, subdomainWildcard); ok {
			d, set = rest, under
		}
		if d == "" || strings.ContainsAny(d, "@*") {
			return nil, fmt.Errorf("%w: email.AllowDomains entry %q names no domain", ErrBadDomainList, raw)
		}
		set[d] = struct{}{}
	}
	if len(exact)+len(under) == 0 {
		return nil, fmt.Errorf("%w: email.AllowDomains() lists no domain", ErrBadDomainList)
	}
	return func(_ context.Context, address string) error {
		d := canonDomain(domainOf(address))
		if _, ok := exact[d]; ok {
			return nil
		}
		// Every proper parent of d: "a.b.acme.com" tries "b.acme.com",
		// "acme.com", "com"; d itself is never tried against under.
		for dot := strings.IndexByte(d, '.'); dot >= 0; dot = strings.IndexByte(d, '.') {
			d = d[dot+1:]
			if _, ok := under[d]; ok {
				return nil
			}
		}
		return ErrAddressRejected
	}, nil
}

// canonDomain is a list entry in the form BlockDomains compares.
func canonDomain(d string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
}

// ParseDomainList reads one domain per line, skipping blank lines and lines
// starting with "#", the format of the common disposable-domain lists.
func ParseDomainList(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

// MXResolver is the part of *net.Resolver RequireMX uses, so a test or an
// app with its own DNS client can supply one.
type MXResolver interface {
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// DefaultMXTimeout bounds RequireMX's lookups. The check runs inside the
// writing transaction, so a slow resolver must not hold it open.
//
//ds:def id=email-defaultmxtimeout-p3q7mx2v owner=@khanakia stability=stable
const DefaultMXTimeout = 3 * time.Second

// RequireMX refuses an address whose domain cannot receive mail: the domain
// does not exist, it publishes the null MX record (RFC 7505), or it has no MX
// record and no address record to fall back to (RFC 5321 §5.1). r nil is
// net.DefaultResolver; timeout 0 is DefaultMXTimeout.
//
// A lookup that fails for any other reason (a timeout, a resolver that is
// down) lets the address through: the verify mail is the real test of an
// address, and an outage of the app's DNS must not stop every sign-up.
func RequireMX(r MXResolver, timeout time.Duration) AddressCheck {
	if r == nil {
		r = net.DefaultResolver
	}
	if timeout <= 0 {
		timeout = DefaultMXTimeout
	}
	return func(ctx context.Context, address string) error {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		domain := domainOf(address)
		mxs, err := r.LookupMX(ctx, domain)
		switch {
		case err == nil && len(mxs) > 0:
			if len(mxs) == 1 && (mxs[0].Host == "." || mxs[0].Host == "") {
				return ErrAddressRejected // null MX: the domain accepts no mail
			}
			return nil
		case err != nil && !notFound(err):
			return nil
		}
		// No MX record: mail goes to the domain's own address, if it has one.
		_, err = r.LookupHost(ctx, domain)
		switch {
		case err == nil:
			return nil
		case notFound(err):
			return ErrAddressRejected
		}
		return nil
	}
}

// notFound reports a DNS answer that the name has no such record, as opposed
// to a lookup that could not be made.
func notFound(err error) bool {
	var dns *net.DNSError
	return errors.As(err, &dns) && dns.IsNotFound
}
