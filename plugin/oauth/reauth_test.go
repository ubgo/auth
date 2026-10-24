package oauth

import (
	"testing"

	"github.com/ubgo/auth"
)

// TestReauthLanding: the outcome joins the page's own query, the ticket only
// when the second factor is due, and a page that does not parse is answered
// as it is rather than mangled.
func TestReauthLanding(t *testing.T) {
	for _, c := range []struct {
		page string
		r    auth.Reauthentication
		want string
	}{
		{"/settings", auth.Reauthentication{Fresh: true}, "/settings?reauth=fresh"},
		{"/settings?tab=security#top", auth.Reauthentication{Fresh: true}, "/settings?reauth=fresh&tab=security#top"},
		{"/", auth.Reauthentication{SecondFactorRequired: true, Ticket: "t-1"}, "/?reauth=second_factor&reauthTicket=t-1"},
		{"%zz", auth.Reauthentication{Fresh: true}, "%zz"},
	} {
		if got := reauthLanding(c.page, c.r); got != c.want {
			t.Fatalf("reauthLanding(%q) = %q, want %q", c.page, got, c.want)
		}
	}
}
