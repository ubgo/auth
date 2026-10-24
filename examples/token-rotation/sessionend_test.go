package main

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/sqlb"
)

// endRecorder is a plugin that only listens for session ends.
type endRecorder struct {
	mu  sync.Mutex
	got []auth.SessionEnd
}

func (*endRecorder) Name() string { return "endrecorder" }

func (r *endRecorder) DataHooks() auth.DataHooks {
	return auth.DataHooks{SessionEnded: func(_ context.Context, _ sqlb.DBTX, e auth.SessionEnd) error {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.got = append(r.got, e)
		return nil
	}}
}

// TestReuse_ReportsTheRevokedSessionAsTokenReuse: the theft revocation reaches
// the session-ended hook with reason token_reuse, once, so a plugin sees the
// same end the security event announces.
func TestReuse_ReportsTheRevokedSessionAsTokenReuse(t *testing.T) {
	rec := &endRecorder{}
	app := newTestApp(t, true, auth.WithPlugins(rec))
	first := app.call(t, http.MethodPost, "/auth/password/sign-up", "", credentials(), http.StatusOK).Header.Get(authhttp.SetTokenHeader)
	app.advance(refreshAfter + time.Second)
	app.call(t, http.MethodGet, "/me", first, nil, http.StatusOK)
	app.advance(rotationGrace + time.Second)
	app.call(t, http.MethodGet, "/me", first, nil, http.StatusUnauthorized)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.got) != 1 || rec.got[0].Reason != auth.SessionEndTokenReuse || rec.got[0].Session.ID == "" || rec.got[0].Session.UserID == "" {
		t.Fatalf("session ends = %+v, want one token_reuse", rec.got)
	}
}
