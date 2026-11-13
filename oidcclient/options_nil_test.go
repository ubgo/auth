package oidcclient_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth/oidcclient"
)

// TestOptions_RefuseNil: every oidcclient option that takes a func, an
// interface or a pointer refuses nil with ErrNilOption naming the option,
// and New reports it at start-up instead of the first request panicking on
// the nil value. TestGuard_OptionsRefuseNil in the core module fails when
// an option that takes a func or an interface is missing from this table.
func TestOptions_RefuseNil(t *testing.T) {
	cfg := oidcclient.Config{
		Issuer: "https://login.example.com", ClientID: "oac_test", ClientSecret: "secret", AppURL: "https://app.example.com",
		SessionSecret: oidcclient.Secret(strings.Repeat("s", oidcclient.MinSecretSize)),
	}
	for name, opt := range map[string]oidcclient.Option{
		"oidcclient.WithSessionStore": oidcclient.WithSessionStore(nil),
		"oidcclient.WithSealer":       oidcclient.WithSealer(nil),
		"oidcclient.WithUserMapper":   oidcclient.WithUserMapper(nil),
		"oidcclient.WithAuthorizer":   oidcclient.WithAuthorizer(nil),
		"oidcclient.WithRechecker":    oidcclient.WithRechecker(nil),
		"oidcclient.WithResponder":    oidcclient.WithResponder(nil),
		"oidcclient.WithReturnPolicy": oidcclient.WithReturnPolicy(nil),
		"oidcclient.WithClientAuth":   oidcclient.WithClientAuth(nil),
		"oidcclient.WithHTTPClient":   oidcclient.WithHTTPClient(nil),
		"oidcclient.WithLogger":       oidcclient.WithLogger(nil),
		"oidcclient.WithClock":        oidcclient.WithClock(nil),
		"oidcclient.WithObserver":     oidcclient.WithObserver(nil),
	} {
		_, err := oidcclient.New(cfg, opt)
		if !errors.Is(err, oidcclient.ErrNilOption) || !strings.Contains(err.Error(), name+"(nil)") {
			t.Errorf("%s(nil): New = %v, want ErrNilOption naming it", name, err)
		}
	}
	// A typed nil inside the interface is refused too, not only a bare nil.
	var rf oidcclient.RecheckerFunc
	if _, err := oidcclient.New(cfg, oidcclient.WithRechecker(rf)); !errors.Is(err, oidcclient.ErrNilOption) {
		t.Errorf("WithRechecker(nil func): %v", err)
	}
}
