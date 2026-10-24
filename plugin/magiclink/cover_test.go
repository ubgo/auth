package magiclink_test

import (
	"errors"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/magiclink"
)

// mute registers a sign-in, verifiable kind but cannot deliver a message. The
// core allows that (only recovery kinds must deliver), so it is the case the
// plugin has to refuse itself.
type mute struct{}

const kindMute auth.IdentifierKindName = "mute"

func (mute) Name() string { return "mute" }
func (mute) Identifiers() []auth.IdentifierKind {
	return []auth.IdentifierKind{{
		Name: kindMute, Unique: true, CanLogin: true, Verifiable: true,
		Normalize: func(raw string) (string, error) { return raw, nil },
	}}
}

// TestInit_RefusesAKindThatCannotDeliver pins a bug: a link to a kind whose
// plugin cannot deliver failed in Send with auth.ErrNoDeliverer, but only for
// an identifier that had an owner, which told a stranger which ones do.
func TestInit_RefusesAKindThatCannotDeliver(t *testing.T) {
	base := auth.WithBaseURL("https://app.example.com")
	if _, err := auth.New(base, auth.WithPlugins(mute{}, magiclink.New())); !errors.Is(err, magiclink.ErrNoKinds) {
		t.Fatalf("only a mute kind = %v, want ErrNoKinds", err)
	}
	if _, err := auth.New(base, auth.WithPlugins(mute{}, email.New(email.Login(), email.WithMailer(noMail)), magiclink.New(magiclink.Kinds(kindMute)))); !errors.Is(err, magiclink.ErrBadKinds) {
		t.Fatalf("an explicit mute kind = %v, want ErrBadKinds", err)
	}
	// Beside a kind that delivers, the mute one is left out, not fatal.
	if _, err := auth.New(base, auth.WithPlugins(mute{}, email.New(email.Login(), email.WithMailer(noMail)), magiclink.New())); err != nil {
		t.Fatalf("mute + email = %v", err)
	}
}

func TestValidate_ExplicitUsableKind(t *testing.T) {
	_, err := auth.New(auth.WithPlugins(email.New(email.Login(), email.WithMailer(noMail), email.Links(func(auth.Purpose, auth.Token) string { return "x" })),
		magiclink.New(magiclink.Kinds(email.KindEmail), magiclink.Links(func(auth.Token) string { return "https://x/l" }))))
	if err != nil {
		t.Fatalf("Kinds(email) with Links and no base URL = %v", err)
	}
}

// TestSendLimitOptions: WithSendLimit and WithIPLimit replace the two rules.
func TestSendLimitOptions(t *testing.T) {
	rules := magiclink.New(magiclink.WithSendLimit(5, time.Hour), magiclink.WithIPLimit(50, 2*time.Hour)).RateLimits()
	if len(rules) != 2 {
		t.Fatalf("%d rules", len(rules))
	}
	for _, r := range rules {
		switch r.Key {
		case auth.ByIdentifier:
			if r.Limit != 5 || r.Window != time.Hour {
				t.Fatalf("per identifier = %+v", r)
			}
		case auth.ByIP:
			if r.Limit != 50 || r.Window != 2*time.Hour {
				t.Fatalf("per IP = %+v", r)
			}
		}
	}
}
