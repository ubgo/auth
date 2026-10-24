package username_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/username"
)

// TestPlugin_UserJoinIsThePackageJoin: the method exists so a plugin list can
// be asked for its joins; it must not drift from the package-level form.
func TestPlugin_UserJoinIsThePackageJoin(t *testing.T) {
	m, f := username.New().UserJoin(), username.UserJoin()
	if m.Type != f.Type || m.Table != f.Table || len(m.On) != len(f.On) {
		t.Fatalf("method join %+v differs from package join %+v", m, f)
	}
}

// TestOf_NeedsThePluginWired: Of answers through the wired plugin, so an Auth
// without it is an error rather than a query over a kind nobody registered.
func TestOf_NeedsThePluginWired(t *testing.T) {
	a, err := auth.New(auth.WithPlugins(signIn{}))
	if err != nil {
		t.Fatal(err)
	}
	var d username.Data
	if _, err := username.Of(a, "u1", &d); !errors.Is(err, auth.ErrPluginNotRegistered) {
		t.Fatalf("Of without the plugin = %v, want auth.ErrPluginNotRegistered", err)
	}
	if _, err := username.Of(wire(t, username.New()), "u1", &d); err != nil {
		t.Fatalf("Of with the plugin: %v", err)
	}
}

// TestReserved_FoldsLikeTheNormalizer: a reserved name given with stray
// spaces or capitals still blocks the handle a user would type.
func TestReserved_FoldsLikeTheNormalizer(t *testing.T) {
	p := username.New(username.Reserved(" Staff "))
	if !p.IsReserved("staff") || !p.IsReserved("  STAFF") {
		t.Fatal("a reserved name must be stored in the normal form")
	}
}

// TestLengthAndValidatorOptions: Length replaces the bounds and WithValidator
// the character rule; each leaves the other in place.
func TestLengthAndValidatorOptions(t *testing.T) {
	k := username.New(username.Length(5, 8)).Identifiers()[0]
	if err := k.Validate("ada"); err == nil {
		t.Fatal("3 characters accepted under Length(5, 8)")
	}
	if err := k.Validate("adalovelace"); err == nil {
		t.Fatal("11 characters accepted under Length(5, 8)")
	}
	if err := k.Validate("ada_l"); err != nil {
		t.Fatalf("5 characters refused: %v", err)
	}
	errDots := errors.New("no dots")
	k = username.New(username.WithValidator(func(v string) error {
		if strings.Contains(v, ".") {
			return errDots
		}
		return nil
	})).Identifiers()[0]
	if err := k.Validate("ada.l"); !errors.Is(err, errDots) {
		t.Fatalf("custom rule = %v", err)
	}
	if err := k.Validate("ADA"); err != nil {
		t.Fatalf("a custom rule replaces the default characters, got %v", err)
	}
	if err := k.Validate("a"); err == nil {
		t.Fatal("the length bounds must still apply with a custom rule")
	}
	if err := username.ValidateChars("Ada"); err == nil {
		t.Fatal("ValidateChars must keep the lowercase rule")
	}
}

// TestWithNormalizer: the custom normal form is what the core stores and
// compares; the reserved list still matches the folded form.
func TestWithNormalizer(t *testing.T) {
	p := username.New(username.WithNormalizer(func(raw string) (string, error) {
		return strings.ReplaceAll(strings.ToLower(raw), "0", "o"), nil
	}))
	if v, _ := p.Identifiers()[0].Normalize("R00T"); v != "root" {
		t.Fatalf("normalize = %q", v)
	}
	if !p.IsReserved("root") {
		t.Fatal("reserved list lost")
	}
}

// TestNew_RefusesBadLength: bounds nobody could satisfy fail auth.New.
func TestNew_RefusesBadLength(t *testing.T) {
	for _, c := range [][2]int{{0, 5}, {5, 4}} {
		_, err := auth.New(auth.WithPlugins(signIn{}, username.New(username.Length(c[0], c[1]))))
		if !errors.Is(err, username.ErrBadLength) {
			t.Fatalf("Length(%d, %d) = %v", c[0], c[1], err)
		}
	}
}

// TestWithoutAvailability: the route is simply not registered.
func TestWithoutAvailability(t *testing.T) {
	a := wire(t, username.New(username.WithoutAvailability()))
	if _, ok := a.Operation(username.EndpointAvailable); ok {
		t.Fatal("available registered under WithoutAvailability")
	}
	if _, ok := a.Operation(username.EndpointSet); !ok {
		t.Fatal("set missing")
	}
	if _, ok := wire(t, username.New()).Operation(username.EndpointAvailable); !ok {
		t.Fatal("available missing by default")
	}
}

// TestDisplayForm_DefaultsAndTheHandleRule: with no display the handle as
// typed is shown; a display form is kept as sent when it normalizes to the
// handle, and refused when it names another handle.
func TestDisplayForm_DefaultsAndTheHandleRule(t *testing.T) {
	p := username.New()
	if got, err := p.DisplayForm("Ada_L", ""); err != nil || got != "Ada_L" {
		t.Fatalf("empty display = %q, %v", got, err)
	}
	if got, err := p.DisplayForm("ada_l", "ADA_L"); err != nil || got != "ADA_L" {
		t.Fatalf("matching display = %q, %v", got, err)
	}
	if _, err := p.DisplayForm("joe", "admin"); !errors.Is(err, username.ErrDisplayInvalid) {
		t.Fatalf("a display naming another handle = %v", err)
	}
}

// TestDisplayForm_ValidatorAndNormalizer: DisplayNormalizer rewrites what is
// stored; DisplayValidator sees the form as sent, or the rewritten form
// under ValidateDisplayAfterNormalization; the handle rule still holds after
// the rewrite.
func TestDisplayForm_ValidatorAndNormalizer(t *testing.T) {
	noUnderscore := func(d string) error {
		if strings.Contains(d, "_") {
			return errors.New("no underscores")
		}
		return nil
	}
	dashes := func(d string) string { return strings.ReplaceAll(d, "_", "-") }

	pre := username.New(username.DisplayValidator(noUnderscore), username.DisplayNormalizer(dashes))
	if _, err := pre.DisplayForm("ada-l", "Ada_L"); !errors.Is(err, username.ErrDisplayInvalid) {
		t.Fatalf("pre-normalization validation saw the rewritten form: %v", err)
	}
	if got, err := pre.DisplayForm("ada-l", "Ada-L"); err != nil || got != "Ada-L" {
		t.Fatalf("valid display = %q, %v", got, err)
	}

	post := username.New(username.DisplayValidator(noUnderscore), username.DisplayNormalizer(dashes), username.ValidateDisplayAfterNormalization())
	if got, err := post.DisplayForm("ada-l", "Ada_L"); err != nil || got != "Ada-L" {
		t.Fatalf("post-normalization = %q, %v", got, err)
	}

	toOther := username.New(username.DisplayNormalizer(func(string) string { return "root" }))
	if _, err := toOther.DisplayForm("ada", "Ada"); !errors.Is(err, username.ErrDisplayInvalid) {
		t.Fatalf("a normalizer that leaves the handle must be refused, got %v", err)
	}
}

// TestDisplayForm_NormalizerErrors: a handle the kind's normalizer refuses
// is refused with that error; a display form it refuses is ErrDisplayInvalid.
func TestDisplayForm_NormalizerErrors(t *testing.T) {
	errNo := errors.New("no")
	p := username.New(username.WithNormalizer(func(raw string) (string, error) {
		if strings.Contains(raw, "!") {
			return "", errNo
		}
		return strings.ToLower(raw), nil
	}))
	if _, err := p.DisplayForm("ada!", "Ada!"); !errors.Is(err, errNo) {
		t.Fatalf("handle refused by the normalizer = %v", err)
	}
	if _, err := p.DisplayForm("ada", "Ada!"); !errors.Is(err, username.ErrDisplayInvalid) {
		t.Fatalf("display refused by the normalizer = %v", err)
	}
}

// TestAvailableLimit: the available route has its own ByIP rule, by default
// DefaultAvailableLimit per DefaultAvailableWindow, replaced by
// WithAvailableLimit; no rule when the route is left out, and auth.New
// refuses a limit that could not count.
func TestAvailableLimit(t *testing.T) {
	want := auth.RateRule{Match: username.EndpointAvailable, Key: auth.ByIP, Limit: username.DefaultAvailableLimit, Window: username.DefaultAvailableWindow}
	if got := username.New().RateLimits(); len(got) != 1 || got[0].Match != want.Match || got[0].Key != want.Key || got[0].Limit != want.Limit || got[0].Window != want.Window {
		t.Fatalf("default rules = %+v", got)
	}
	got := username.New(username.WithAvailableLimit(5, time.Hour)).RateLimits()
	if len(got) != 1 || got[0].Limit != 5 || got[0].Window != time.Hour {
		t.Fatalf("WithAvailableLimit rules = %+v", got)
	}
	if got := username.New(username.WithoutAvailability()).RateLimits(); len(got) != 0 {
		t.Fatalf("WithoutAvailability rules = %+v", got)
	}
	wire(t, username.New(username.WithoutAvailability()))
	for _, c := range []struct {
		n int
		w time.Duration
	}{{0, time.Minute}, {5, 0}} {
		_, err := auth.New(auth.WithPlugins(signIn{}, username.New(username.WithAvailableLimit(c.n, c.w))))
		if !errors.Is(err, username.ErrBadAvailableLimit) {
			t.Fatalf("WithAvailableLimit(%d, %v) = %v", c.n, c.w, err)
		}
	}
}
