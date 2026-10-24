package authgate

import (
	"fmt"
	"strings"
)

// Allow adds an access rule. A profile gets in when any rule returns true,
// so AllowEmailDomain("example.com") and Allow(isContractor) together let in
// the company and the contractor. Rules run at sign-in and again on every
// request that carries a cookie, so removing someone from a rule and
// deploying shuts them out at once, without waiting for their cookie to
// expire. A rule must therefore be cheap and must not call the network; it
// sees only what the cookie holds (the Profile, with Tokens under
// KeepTokens). Without any rule New fails with ErrNoRule.
func Allow(rule func(Profile) bool) Option {
	return func(g *Gate) {
		if g.optErrs.RefuseNil("authgate.Allow", rule) {
			return
		}
		g.rules = append(g.rules, rule)
	}
}

// AllowEmailDomain lets in a profile whose email the provider verified and
// whose domain is one of domains, compared without regard to case. The match
// is exact: "example.com" does not admit "eu.example.com" (list it too), so a
// subdomain someone else controls is never let in by accident. An unverified
// address never matches: anyone can type any address into an account at a
// provider that does not check it.
func AllowEmailDomain(domains ...string) Option {
	return func(g *Gate) {
		set, err := lowerSet("AllowEmailDomain", domains)
		if err != nil {
			g.fail(err)
			return
		}
		g.rules = append(g.rules, func(p Profile) bool {
			at := strings.LastIndexByte(p.Email, '@')
			return p.EmailVerified && at > 0 && set[strings.ToLower(p.Email[at+1:])]
		})
	}
}

// AllowEmails lets in a profile whose email the provider verified and is one
// of addrs, compared without regard to case.
func AllowEmails(addrs ...string) Option {
	return func(g *Gate) {
		set, err := lowerSet("AllowEmails", addrs)
		if err != nil {
			g.fail(err)
			return
		}
		g.rules = append(g.rules, func(p Profile) bool {
			return p.EmailVerified && set[strings.ToLower(p.Email)]
		})
	}
}

// AllowAnyone lets in every account the providers sign in: the explicit
// choice for a tool that acts on the person's own account and guards nothing
// of the operator's. Any other rule is then redundant.
func AllowAnyone() Option {
	return func(g *Gate) { g.allowAnyone = true }
}

// allowed reports whether any rule accepts p.
func (g *Gate) allowed(p Profile) bool {
	if g.allowAnyone {
		return true
	}
	for _, rule := range g.rules {
		if rule(p) {
			return true
		}
	}
	return false
}

// lowerSet lower-cases values into a set, refusing an empty list or value:
// AllowEmailDomain() with nothing in it is a typo that must not silently
// admit nobody, or, worse, read as "no restriction".
func lowerSet(option string, values []string) (map[string]bool, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("%w: %s with no value", ErrBadOption, option)
	}
	set := make(map[string]bool, len(values))
	for _, v := range values {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" {
			return nil, fmt.Errorf("%w: %s with an empty value", ErrBadOption, option)
		}
		set[v] = true
	}
	return set, nil
}
