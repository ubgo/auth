package samlidp_test

import (
	"context"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/samlidp"
)

// alwaysSecondFactor makes every new session wait for a second factor.
type alwaysSecondFactor struct{ on bool }

func (alwaysSecondFactor) Name() string { return "testsecondfactor" }

func (f alwaysSecondFactor) SecondFactorRequired(context.Context, string) (bool, error) {
	return f.on, nil
}

// taskTest is the task alwaysTask requires.
const taskTest auth.SessionTaskID = "testtask.accept"

// alwaysTask gives every new session a task to complete.
type alwaysTask struct{ on bool }

func (alwaysTask) Name() string { return "testtask" }

func (alwaysTask) SessionTasks() []auth.SessionTask { return []auth.SessionTask{{ID: taskTest}} }

func (t alwaysTask) SessionTasksFor(context.Context, auth.SignInAttempt) ([]auth.SessionTaskID, error) {
	if !t.on {
		return nil, nil
	}
	return []auth.SessionTaskID{taskTest}, nil
}

// A session that has not finished signing in (second factor pending, or a
// session task pending) is signed out to the IdP: the browser goes back to
// the login page and no SAMLResponse is ever posted.
func TestUnfinishedSessions_NeverAsserted(t *testing.T) {
	for name, extra := range map[string]auth.Plugin{
		"second factor pending": alwaysSecondFactor{on: true},
		"session task pending":  alwaysTask{on: true},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t, setup{extra: []auth.Plugin{extra}})
			u, _ := w.authnRedirect(false, nil)
			// The login page signs in (creating the unfinished session) and
			// returns; the IdP sends the browser back to log in until the
			// client gives up on the redirect loop.
			res, err := w.browser.Get(u)
			if err == nil {
				defer res.Body.Close()
				if res.StatusCode == 200 {
					t.Fatalf("an unfinished session got an answer at %s", res.Request.URL)
				}
			}
			if w.logins < 2 {
				t.Fatalf("logins = %d: the unfinished session was not sent back to log in", w.logins)
			}
			for _, s := range w.seen {
				if !strings.Contains(s, "/saml/") && !strings.Contains(s, loginPath) {
					t.Fatalf("the browser left the IdP: %s", s)
				}
			}
			// From Go: Continue with the unfinished session answers the
			// login redirect, never a form.
			v, _ := w.authnPOST(false, nil)
			start, err := w.idp.SSO(w.env.Anonymous(context.Background()), samlidp.SSORequest{Binding: samlidp.BindingPOST, SAMLRequest: v})
			if err != nil {
				t.Fatal(err)
			}
			handle := start.RedirectTo[strings.Index(start.RedirectTo, "request=")+len("request="):]
			got, err := w.idp.Continue(w.env.SignIn(w.user.ID).Context(context.Background()), samlidp.ContinueRequest{Request: handle})
			if err != nil || got.Form != nil || !strings.HasPrefix(got.RedirectTo, loginPath+"?") {
				t.Fatalf("Continue for an unfinished session: %+v %v", got, err)
			}
		})
	}
}
