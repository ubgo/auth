package auth

import (
	"errors"
	"strings"
	"testing"
)

// TestSessionHookError_WrapsTheHookFailure: the retry in endAlways finds the
// hook's failure with errors.As, and a caller that does see it can still
// match the hook's own error through Unwrap and read it in the message.
func TestSessionHookError_WrapsTheHookFailure(t *testing.T) {
	boom := errors.New("boom")
	var err error = &sessionHookError{err: boom}
	if !errors.Is(err, boom) {
		t.Fatal("Unwrap does not reach the hook's error")
	}
	if !strings.Contains(err.Error(), "session ended hook") || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("message %q lacks the hook and its error", err)
	}
}
