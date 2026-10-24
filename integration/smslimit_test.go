package integration

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/phone"
)

// TestPhone_RangeLimitAndAllowedPrefixes: a bot rotating numbers inside one
// range and IPs is stopped by the range counter, and a number outside the
// allowed countries is refused before any code is sent.
func TestPhone_RangeLimitAndAllowedPrefixes(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ph := e.phonePlugin(phone.Login(), phone.SignInWithCode(), phone.AllowPrefixes("+1"), phone.LimitRange(6, 3, time.Hour))
		a := e.newAuth(t, nil, ph)
		var last error
		for i := range 4 {
			ctx := a.WithRequest(anon(a), auth.Request{Transport: auth.TransportHTTP, Client: auth.Client{IP: fmt.Sprintf("198.51.100.%d", i)}})
			last = ph.SendCode(ctx, fmt.Sprintf("+1555010%04d", i))
		}
		if !errors.Is(last, auth.ErrRateLimited) {
			t.Fatalf("4th code to one range: %v, want ErrRateLimited", last)
		}
		if err := ph.SendCode(anon(a), "+1666010000"); err != nil {
			t.Fatalf("another range must still work: %v", err)
		}
		if err := ph.SendCode(anon(a), "+447700900123"); !errors.Is(err, auth.ErrIdentifierInvalid) {
			t.Fatalf("a number outside the allowed prefixes: %v", err)
		}
		if got := e.sms.Count(a, "+447700900123"); got != 0 {
			t.Fatalf("%d texts sent to a refused number", got)
		}
	})
}
