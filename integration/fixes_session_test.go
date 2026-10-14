package integration

import (
	"context"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authtest"
)

// TestSession_PartialConfigKeepsSessionsAlive: with WithSession setting the
// idle timeout alone, a session still works a minute after sign-in. Before
// the zero fields took their defaults, MaxLifetime stayed zero and the first
// request after sign-in signed the user out.
func TestSession_PartialConfigKeepsSessionsAlive(t *testing.T) {
	e := authtest.New(t, authtest.WithPlugins(harnessPlugins), authtest.WithOptions(auth.WithSession(auth.SessionConfig{IdleTimeout: time.Hour})))
	u := e.CreateUser("Ada")
	s := e.SignIn(u.ID)
	e.Clock.Advance(time.Minute)
	if res, err := e.Auth.Session(s.Context(context.Background())); err != nil || res.User.ID != u.ID {
		t.Fatalf("a minute after sign-in: %+v %v", res, err)
	}
	e.Clock.Advance(2 * time.Hour)
	if _, err := e.Auth.Session(s.Context(context.Background())); err == nil {
		t.Fatal("the idle timeout set by WithSession did not end the session")
	}
}
