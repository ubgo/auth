package authcli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

// A random source that fails is ExitFailed with the reason, never a weak
// secret.
func TestSecret_RandomFailure(t *testing.T) {
	var out, errb bytes.Buffer
	if code := secret(nil, failingReader{}, &out, &errb); code != ExitFailed || out.Len() != 0 || !strings.Contains(errb.String(), "no entropy") {
		t.Fatalf("%d %q %q", code, out.String(), errb.String())
	}
}
