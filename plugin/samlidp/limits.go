package samlidp

import (
	"time"

	"github.com/ubgo/auth"
)

// rateWindow is the window of every default limit.
const rateWindow = time.Minute

// DefaultRateLimits are the calls per client IP per minute each endpoint
// accepts unless RateLimit changes it. The single sign-on service writes a
// row per accepted request, so it is bounded even though every request must
// come from a registered SP; continue allows the extra hops of a login.
//
//ds:def id=samlidp-defaultratelimits-b6t2qn8m owner=@khanakia stability=stable
var DefaultRateLimits = map[auth.EndpointID]int{
	EndpointSSO:      30,
	EndpointContinue: 60,
	EndpointInitiate: 30,
}

// RateLimit replaces an endpoint's default limit per client IP; a limit of
// 0 removes it (for an app that limits in front of the library).
func RateLimit(endpoint auth.EndpointID, limit int, window time.Duration) Option {
	return func(p *Plugin) {
		if p.limits == nil {
			p.limits = map[auth.EndpointID]rateSpec{}
		}
		p.limits[endpoint] = rateSpec{limit: limit, window: window}
	}
}

// rateSpec is one endpoint's limit.
type rateSpec struct {
	limit  int
	window time.Duration
}

var _ auth.RateLimiter = (*Plugin)(nil)

// RateLimits declares the limits, in a fixed order so the rule list is the
// same on every start.
func (p *Plugin) RateLimits() []auth.RateRule {
	var rules []auth.RateRule
	for _, id := range []auth.EndpointID{EndpointSSO, EndpointContinue, EndpointInitiate} {
		s := rateSpec{limit: DefaultRateLimits[id], window: rateWindow}
		if o, ok := p.limits[id]; ok {
			s = o
		}
		if s.limit > 0 {
			rules = append(rules, auth.RateRule{Match: id, Key: auth.ByIP, Limit: s.limit, Window: s.window})
		}
	}
	return rules
}
