package auth_test

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// TestNew_RefusesNilOptions: every option that takes a func or an interface
// refuses nil at New, naming the option, instead of panicking at the first
// request that calls it (WithIDs(nil) did, on the first id).
func TestNew_RefusesNilOptions(t *testing.T) {
	for name, opt := range map[string]auth.Option{
		"auth.WithDialect":            auth.WithDialect(nil),
		"auth.WithClock":              auth.WithClock(nil),
		"auth.WithIDs":                auth.WithIDs(nil),
		"auth.WithLogger":             auth.WithLogger(nil),
		"auth.WithRateStore":          auth.WithRateStore(nil),
		"auth.WithSessionPolicy":      auth.WithSessionPolicy(nil),
		"auth.WithMessages":           auth.WithMessages(nil),
		"auth.WithObserver":           auth.WithObserver(nil),
		"auth.WithBackground":         auth.WithBackground(nil),
		"auth.WithSessionExtras":      auth.WithSessionExtras(nil),
		"auth.WithTrustedOriginFunc":  auth.WithTrustedOriginFunc(nil),
		"auth.WithRateExempt":         auth.WithRateExempt(nil),
		"auth.WithRateChallenger":     auth.WithRateChallenger(nil),
		"auth.WithDeviceRecognizer":   auth.WithDeviceRecognizer(nil),
		"auth.WithGeoLocator":         auth.WithGeoLocator(nil),
		"auth.WithTravelHistory":      auth.WithTravelHistory(nil),
		"auth.WithIPReputation":       auth.WithIPReputation(nil, auth.RiskPolicy{}),
		"auth.WithBotCheck":           auth.WithBotCheck(nil, auth.RiskPolicy{}),
		"auth.WithTrialAbuseCheck":    auth.WithTrialAbuseCheck(nil, auth.RiskPolicy{}),
		"auth.WithSecuritySink":       auth.WithSecuritySink(nil, auth.SecurityQueue{}),
		"auth.WithSessionCache":       auth.WithSessionCache(nil, time.Minute),
		"auth.WithSessionRevocations": auth.WithSessionRevocations(nil),
		"auth.WithSessionStore":       auth.WithSessionStore(nil),
		"auth.WithSecondaryStorage":   auth.WithSecondaryStorage(nil),
		"auth.WithTracer":             auth.WithTracer(nil),
		"auth.WithVerificationStore":  auth.WithVerificationStore(nil),
		"auth.WithSealer":             auth.WithSealer(nil),
		// A pointer, not a func or an interface, so the source guard does
		// not demand it; WithDBAuto(nil) panicked in DetectDialect until the
		// config edge test (integration/configedge_test.go) found it.
		"auth.WithDBAuto":  auth.WithDBAuto(nil),
		"auth.WithDB":      auth.WithDB(nil, nil),
		"auth.Options":     auth.Options(nil),
		"auth.WithPlugins": auth.WithPlugins(signIn{on: true}, nil),
	} {
		_, err := newAuth(auth.WithPlugins(signIn{on: true}), opt)
		if !errors.Is(err, auth.ErrNilOption) || !strings.Contains(err.Error(), name+"(nil)") {
			t.Errorf("%s(nil) = %v, want ErrNilOption naming it", name, err)
		}
	}
}

// TestNew_SessionConfigZeroFieldsKeepDefaults: a WithSession that sets one
// field keeps DefaultSessionConfig's others, so a partial config no longer
// gives every session a zero hard stop; a negative field is refused.
func TestNew_SessionConfigZeroFieldsKeepDefaults(t *testing.T) {
	a, err := newAuth(auth.WithPlugins(signIn{on: true}), auth.WithSession(auth.SessionConfig{IdleTimeout: time.Hour}))
	if err != nil {
		t.Fatal(err)
	}
	def := auth.DefaultSessionConfig
	want := auth.SessionConfig{IdleTimeout: time.Hour, MaxLifetime: def.MaxLifetime, RefreshAfter: def.RefreshAfter, TransientIdleTimeout: auth.DefaultTransientIdleTimeout}
	if got := a.Config().Session; got != want {
		t.Fatalf("Session = %+v, want %+v", got, want)
	}
	for _, c := range []auth.SessionConfig{{IdleTimeout: -time.Second}, {MaxLifetime: -1}, {RefreshAfter: -1}, {TransientIdleTimeout: -1}} {
		if _, err := newAuth(auth.WithPlugins(signIn{on: true}), auth.WithSession(c)); !errors.Is(err, auth.ErrBadSessionConfig) {
			t.Errorf("%+v = %v, want ErrBadSessionConfig", c, err)
		}
	}
}

// checkedPlugin is a sign-in plugin whose options recorded err.
type checkedPlugin struct {
	signIn
	err error
}

func (p checkedPlugin) OptionErr() error { return p.err }

// checkedStorage is a secondary storage whose options recorded err.
type checkedStorage struct {
	auth.SecondaryStorage
	err error
}

func (s checkedStorage) OptionErr() error { return s.err }

// checkedRates is a rate store whose options recorded err.
type checkedRates struct {
	auth.RateStore
	err error
}

func (r checkedRates) OptionErr() error { return r.err }

// TestNew_RefusesComponentOptionErrors: New checks OptionErr on every plugin
// and every component given through an option, a wrapped secondary storage
// included, so a plugin or contrib store built with a nil option fails
// start-up; a component whose OptionErr is nil starts.
func TestNew_RefusesComponentOptionErrors(t *testing.T) {
	bad := fmt.Errorf("%w: test.WithThing(nil)", auth.ErrNilOption)
	mem := auth.NewMemoryStorage(time.Now)
	for name, opts := range map[string][]auth.Option{
		"plugin":       {auth.WithPlugins(checkedPlugin{signIn{on: true}, bad})},
		"rate store":   {auth.WithPlugins(signIn{on: true}), auth.WithRateStore(checkedRates{auth.NewMemoryRateStore(time.Now), bad})},
		"storage":      {auth.WithPlugins(signIn{on: true}), auth.WithSecondaryStorage(checkedStorage{mem, bad})},
		"verification": {auth.WithPlugins(signIn{on: true}), auth.WithVerificationStore(auth.NewStorageVerificationStore(checkedGetAndDeleter{mem.(auth.GetAndDeleter), bad}))},
	} {
		if _, err := newAuth(opts...); !errors.Is(err, auth.ErrNilOption) || !strings.Contains(err.Error(), "test.WithThing(nil)") {
			t.Errorf("%s: New = %v, want its OptionErr", name, err)
		}
	}
	if _, err := newAuth(auth.WithPlugins(checkedPlugin{signIn{on: true}, nil}), auth.WithSecondaryStorage(checkedStorage{mem, nil})); err != nil {
		t.Fatalf("nil OptionErr: New = %v", err)
	}
}

// checkedGetAndDeleter is a verification storage whose options recorded err.
type checkedGetAndDeleter struct {
	auth.GetAndDeleter
	err error
}

func (s checkedGetAndDeleter) OptionErr() error { return s.err }

// TestOptionErrors_RefuseNil pins what counts as nil: a nil interface, a nil
// func and a nil pointer (typed, inside an interface) are refused, each
// naming the option; a value, a zero struct and an empty slice are not.
func TestOptionErrors_RefuseNil(t *testing.T) {
	var nilFunc func()
	var nilPtr *slog.Logger
	var nilIface auth.Observer
	for name, v := range map[string]any{"iface": nilIface, "func": nilFunc, "ptr": nilPtr, "untyped": nil} {
		var o auth.OptionErrors
		if !o.RefuseNil("x.With"+name, v) || !errors.Is(o.OptionErr(), auth.ErrNilOption) || !strings.Contains(o.OptionErr().Error(), "x.With"+name+"(nil)") {
			t.Errorf("%s: RefuseNil did not refuse: %v", name, o.OptionErr())
		}
	}
	var o auth.OptionErrors
	for name, v := range map[string]any{"func": func() {}, "ptr": slog.Default(), "struct": auth.SessionConfig{}, "slice": []string(nil), "string": ""} {
		if o.RefuseNil(name, v) {
			t.Errorf("%s: RefuseNil refused a value", name)
		}
	}
	if o.OptionErr() != nil {
		t.Fatalf("OptionErr = %v, want nil", o.OptionErr())
	}
	if auth.RefuseNilEach(&o, "x.Each", []func(){func() {}}) || !auth.RefuseNilEach(&o, "x.Each", []func(){func() {}, nil}) {
		t.Fatal("RefuseNilEach: a nil element must be refused and only then")
	}
	o.JoinOptionErr(nil)
	if !strings.Contains(o.OptionErr().Error(), "x.Each(nil)") {
		t.Fatalf("OptionErr = %v", o.OptionErr())
	}
}
