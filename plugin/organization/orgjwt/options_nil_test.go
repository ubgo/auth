package orgjwt_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/organization/orgjwt"
)

// TestOptions_RefuseNil: every orgjwt option that takes a func refuses nil
// at construction with auth.ErrNilOption naming the option and returns no
// claims func, so the app stops at start and a token is never minted with
// the role-derived permissions the app meant to replace.
// TestGuard_OptionsRefuseNil in the core module fails when such an option
// is missing from this table.
func TestOptions_RefuseNil(t *testing.T) {
	for name, opt := range map[string]orgjwt.Option{
		"orgjwt.Permissions": orgjwt.Permissions(nil),
	} {
		fn, err := orgjwt.Claims(fakeSource{active: "org_1", role: "admin"}, opt)
		if !errors.Is(err, auth.ErrNilOption) || !strings.Contains(err.Error(), name+"(nil)") {
			t.Errorf("%s(nil): Claims error = %v, want auth.ErrNilOption naming it", name, err)
		}
		if fn == nil {
			t.Fatalf("%s(nil): Claims returned a nil func, which a jwt.Template would read as no claims", name)
		}
		if _, ferr := fn(context.Background(), auth.User{ID: "usr_1"}, auth.Session{ID: "ses_1"}); !errors.Is(ferr, auth.ErrNilOption) {
			t.Errorf("%s(nil): the returned func = %v, want it to fail with auth.ErrNilOption", name, ferr)
		}
	}
}

// TestClaims_NilSourceRefused: a nil Source is refused at construction too.
func TestClaims_NilSourceRefused(t *testing.T) {
	if fn, err := orgjwt.Claims(nil); !errors.Is(err, auth.ErrNilOption) || fn == nil {
		t.Errorf("Claims(nil) = %v, %v; want a failing func and auth.ErrNilOption", fn != nil, err)
	}
}
