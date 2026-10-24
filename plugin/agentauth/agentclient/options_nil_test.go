package agentclient

import (
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
)

// TestOptions_RefuseNil: every agentclient option that takes a func or an
// interface refuses nil with auth.ErrNilOption naming the option; the client
// has no start-up check, so OptionErr reports it and every call that signs a
// token returns it instead of calling the nil clock. TestGuard_OptionsRefuseNil
// in the core module fails when such an option is missing from this table.
func TestOptions_RefuseNil(t *testing.T) {
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	for name, opt := range map[string]Option{
		"agentclient.WithClock": WithClock(nil),
	} {
		c := New(key, opt)
		for what, err := range map[string]error{
			"OptionErr": c.OptionErr(),
			"hostJWT":   second(c.hostJWT("aud", nil)),
			"agentJWT":  second(c.agentJWT(Agent{}, "aud", "", "", nil)),
		} {
			if !errors.Is(err, auth.ErrNilOption) || !strings.Contains(err.Error(), name+"(nil)") {
				t.Errorf("%s(nil): %s = %v, want auth.ErrNilOption naming it", name, what, err)
			}
		}
	}
}

// second is the error of a (value, error) pair.
func second(_ string, err error) error { return err }
