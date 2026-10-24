package webhook_test

import (
	"context"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/webhook"
)

// TestSessionEnded_APIKeySessionsAreNotReported: an API-key session is not a
// sign-in (session.created skips it too), so ending one enqueues nothing and
// does not touch the database, which this call has none of: a report would
// fail on the missing transaction.
func TestSessionEnded_APIKeySessionsAreNotReported(t *testing.T) {
	hook := webhook.New().DataHooks().SessionEnded
	if hook == nil {
		t.Fatal("the plugin does not listen for session ends")
	}
	e := auth.SessionEnd{Session: auth.Session{ID: "s1", UserID: "u1", APIKeyID: "key_1"}, Reason: auth.SessionEndRevoked}
	if err := hook(context.Background(), nil, e); err != nil {
		t.Fatalf("hook for an API-key session = %v, want nil", err)
	}
}
