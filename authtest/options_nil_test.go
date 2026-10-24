package authtest

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/ubgo/auth"
)

// fatalTB records the first Fatalf and stops the goroutine, as testing.T
// does, so a test can assert that New fails the test.
type fatalTB struct {
	testing.TB
	msg string
}

func (f *fatalTB) Helper() {}

func (f *fatalTB) Fatalf(format string, args ...any) {
	f.msg = fmt.Sprintf(format, args...)
	runtime.Goexit()
}

// TestOptions_RefuseNil: every authtest option that takes a func or an
// interface refuses nil with auth.ErrNilOption naming the option, and New
// fails the test with it before opening a database. TestGuard_OptionsRefuseNil
// in the core module fails when such an option is missing from this table.
func TestOptions_RefuseNil(t *testing.T) {
	for name, opt := range map[string]Option{
		"authtest.WithDB":      WithDB(nil, nil),
		"authtest.WithOptions": WithOptions(nil),
		"authtest.WithPlugins": WithPlugins(nil),
	} {
		var s settings
		opt(&s)
		if err := s.optErrs.OptionErr(); !errors.Is(err, auth.ErrNilOption) || !strings.Contains(err.Error(), name+"(nil)") {
			t.Errorf("%s(nil): %v, want auth.ErrNilOption naming it", name, err)
		}
		tb := &fatalTB{}
		done := make(chan struct{})
		go func() {
			defer close(done)
			New(tb, opt)
		}()
		<-done
		if !strings.Contains(tb.msg, name+"(nil)") {
			t.Errorf("%s(nil): New failed with %q, want the option named", name, tb.msg)
		}
	}
}
