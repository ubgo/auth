package oauthprovider

import (
	"time"

	"github.com/ubgo/auth"
)

// rateWindow is the window of every default limit, 60 s.
const rateWindow = time.Minute

// DefaultRateLimits are the per-endpoint limits, per client IP
// per minute: token 20, authorize 30, introspect 100, revoke 30, register
// 5, userinfo 60. RateLimit replaces one; NoDefaultRateLimits drops them all
// so only the app's own rules apply.
//
//ds:def id=oauthprovider-defaultratelimits-q7v3mx2k owner=@khanakia stability=stable
var DefaultRateLimits = map[auth.EndpointID]int{
	EndpointToken:      20,
	EndpointAuthorize:  30,
	EndpointIntrospect: 100,
	EndpointRevoke:     30,
	EndpointRegister:   5,
	EndpointUserInfo:   60,
}

// RateLimit sets the per-IP limit of one endpoint to limit calls per
// window, replacing its default. limit 0 removes the endpoint's default.
func RateLimit(endpoint auth.EndpointID, limit int, window time.Duration) Option {
	return func(p *Plugin) {
		if p.limits == nil {
			p.limits = map[auth.EndpointID]rateSpec{}
		}
		p.limits[endpoint] = rateSpec{limit: limit, window: window}
	}
}

// NoDefaultRateLimits drops every DefaultRateLimits rule.
func NoDefaultRateLimits() Option { return func(p *Plugin) { p.noDefaultLimits = true } }

type rateSpec struct {
	limit  int
	window time.Duration
}

var _ auth.RateLimiter = (*Plugin)(nil)

// RateLimits declares the per-IP rules: the defaults unless dropped, with
// every RateLimit override on top.
func (p *Plugin) RateLimits() []auth.RateRule {
	specs := map[auth.EndpointID]rateSpec{}
	if !p.noDefaultLimits {
		for id, n := range DefaultRateLimits {
			specs[id] = rateSpec{limit: n, window: rateWindow}
		}
	}
	for id, s := range p.limits {
		specs[id] = s
	}
	var rules []auth.RateRule
	// A fixed order, so the rule list is the same on every start.
	for _, id := range []auth.EndpointID{EndpointToken, EndpointAuthorize, EndpointIntrospect, EndpointRevoke, EndpointRegister, EndpointUserInfo, EndpointEndSession} {
		if s, ok := specs[id]; ok && s.limit > 0 {
			rules = append(rules, auth.RateRule{Match: id, Key: auth.ByIP, Limit: s.limit, Window: s.window})
		}
	}
	return rules
}
