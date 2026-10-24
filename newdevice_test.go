package auth_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
)

// TestDeviceKey_IgnoresVersionsAndSpacing pins what makes a device the same
// across a browser update, and what keeps two different devices apart.
func TestDeviceKey_IgnoresVersionsAndSpacing(t *testing.T) {
	a := auth.DeviceKey("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/129.0.0.0 Safari/537.36")
	b := auth.DeviceKey("Mozilla/5.0  (Macintosh; Intel Mac OS X 10_15_7)  Chrome/130.0.6723.0 Safari/605.1")
	c := auth.DeviceKey("Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0")
	if a != b {
		t.Errorf("a browser update is a new device: %q vs %q", a, b)
	}
	if a == c {
		t.Errorf("a different system and browser share the key %q", a)
	}
	if auth.DeviceKey("") != "" {
		t.Errorf("empty user agent key = %q", auth.DeviceKey(""))
	}
}

// TestUnknownDevice_NewRefusesWhatCannotWork: a recognizer with the
// notification off changes nothing, so it is refused; the default rule
// reads sessions, which stateless mode does not keep, so it needs a
// recognizer of its own.
func TestUnknownDevice_NewRefusesWhatCannotWork(t *testing.T) {
	known := auth.DeviceRecognizerFunc(func(context.Context, auth.DeviceSignIn) (bool, error) { return true, nil })
	_, err := newAuth(auth.WithPlugins(basic("s")), auth.WithDeviceRecognizer(known))
	if !errors.Is(err, auth.ErrBadOperation) || !strings.Contains(err.Error(), "auth.WithDeviceRecognizer") {
		t.Errorf("recognizer without the notification = %v", err)
	}
	_, err = newAuth(auth.WithPlugins(basic("s")), auth.WithSecret([]byte(strings.Repeat("k", auth.MinSecretSize))), auth.WithStatelessSessions(), auth.WithUnknownDeviceNotification())
	if !errors.Is(err, auth.ErrBadOperation) || !strings.Contains(err.Error(), "auth.WithUnknownDeviceNotification") {
		t.Errorf("stateless without a recognizer = %v", err)
	}
	if _, err = newAuth(auth.WithPlugins(basic("s")), auth.WithSecret([]byte(strings.Repeat("k", auth.MinSecretSize))), auth.WithStatelessSessions(), auth.WithUnknownDeviceNotification(), auth.WithDeviceRecognizer(known)); err != nil {
		t.Errorf("stateless with a recognizer: %v", err)
	}
}
