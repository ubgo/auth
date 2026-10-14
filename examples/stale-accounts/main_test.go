package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authcli"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/stale"
)

const (
	adaMail = "ada@example.com"
	adaPass = "correct horse battery staple"
	// testSecret is a 32-byte AUTH_SECRET for the tests only.
	testSecret = "test-secret-0123456789abcdefghij"
	// warnSubject and deletedSubject are words of the plugin's default English
	// subjects ("Your account has been inactive", "Your account was deleted"),
	// enough to tell the two mails apart from the sign-up's verification mail.
	warnSubject    = "inactive"
	deletedSubject = "deleted"
	// deletionNotice is the sentence the warning carries when deletion is on.
	deletionNotice = "will be deleted"
)

// The counters auth.Maintain reports for the plugin, "<plugin>.<counter>".
var (
	keyWarned  = stale.PluginName + "." + stale.CounterWarned
	keyDeleted = stale.PluginName + "." + stale.CounterDeleted
)

// world is the app with ada signed up and her address verified, so the
// warning has a recovery channel to go to. It returns her user id.
func world(t *testing.T) (*authtest.Env, *authtest.Browser, string) {
	t.Helper()
	// Post-commit work (the outbox's send after each message's transaction)
	// runs inline: a run queues messages one transaction at a time, and SQLite
	// answers SQLITE_BUSY when a transaction tries to write right after another
	// connection did in the background. Production SQLite apps use
	// _txlock=immediate; the test keeps the order fixed instead.
	inline := auth.WithBackground(func(ctx context.Context, task func(context.Context)) { task(ctx) })
	e := authtest.New(t,
		authtest.WithOptions(append(options([]byte(testSecret)), inline)...),
		authtest.WithPlugins(func(e *authtest.Env) []auth.Plugin { return plugins(e.Mail) }))
	b := e.Browser(newHandler(e.Auth))
	var up struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	b.Post("/auth/password/sign-up", map[string]string{"identifier": adaMail, "password": adaPass, "name": "Ada"}).Expect(http.StatusOK).Decode(&up)
	b.Post("/auth/email/verify", map[string]string{"token": e.Mail.LastToken(adaMail).Reveal()}).Expect(http.StatusOK)
	return e, b, up.User.ID
}

// maintain is one auth.Maintain run, requiring no error.
func maintain(t *testing.T, e *authtest.Env, dry bool) auth.SweepResult {
	t.Helper()
	res, err := e.Auth.Maintain(context.Background(), auth.MaintainOptions{DryRun: dry})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// idle reports whether a run did nothing: every counter is zero.
func idle(res auth.SweepResult) bool {
	for _, n := range res {
		if n != 0 {
			return false
		}
	}
	return true
}

// mails returns the mail to ada whose subject contains word.
func mails(e *authtest.Env, word string) []string {
	var out []string
	for _, m := range e.Mail.To(adaMail) {
		if strings.Contains(m.Subject, word) {
			out = append(out, m.Text)
		}
	}
	return out
}

// exists reports whether the user is still there.
func exists(t *testing.T, e *authtest.Env, id string) bool {
	t.Helper()
	_, err := e.Auth.User(context.Background(), id)
	if errors.Is(err, auth.ErrUserNotFound) {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	return true
}

// TestStale_WarnsOnceAfterTheInactivePeriod: nobody is warned before the
// period; after it ada gets one warning that says when the account will be
// deleted, and a second run straight after mails nothing.
func TestStale_WarnsOnceAfterTheInactivePeriod(t *testing.T) {
	e, _, _ := world(t)
	e.Clock.Advance(inactiveAfter - day)
	if res := maintain(t, e, false); !idle(res) || len(mails(e, warnSubject)) != 0 {
		t.Fatalf("before the period: %v, %d warnings", res, len(mails(e, warnSubject)))
	}
	e.Clock.Advance(2 * day)
	if res := maintain(t, e, false); res[keyWarned] != 1 {
		t.Fatalf("after the period: %v, want one warned", res)
	}
	warnings := mails(e, warnSubject)
	if len(warnings) != 1 || !strings.Contains(warnings[0], deletionNotice) {
		t.Fatalf("warnings = %q, want one that names the deletion", warnings)
	}
	if res := maintain(t, e, false); !idle(res) || len(mails(e, warnSubject)) != 1 {
		t.Fatalf("second run: %v, %d warnings, want nothing new", res, len(mails(e, warnSubject)))
	}
}

// TestStale_ASignInClearsTheWarning: ada signs in after the warning, so the
// grace period passing deletes nothing and warns nobody.
func TestStale_ASignInClearsTheWarning(t *testing.T) {
	e, b, ada := world(t)
	e.Clock.Advance(inactiveAfter + day)
	maintain(t, e, false)
	b.Post("/auth/password/sign-in", map[string]string{"identifier": adaMail, "password": adaPass}).Expect(http.StatusOK)
	e.Clock.Advance(deletionGrace + day)
	if res := maintain(t, e, false); !idle(res) || !exists(t, e, ada) {
		t.Fatalf("signed in after the warning: %v, exists %v", res, exists(t, e, ada))
	}
}

// TestStale_DeletesAfterTheGraceWithAFinalMail: the account survives the
// grace period, is deleted after it with one final mail, and a second run
// deletes and mails nothing.
//
//ds:def id=staleaccounts-example-test-delete-5nq8wk3v
func TestStale_DeletesAfterTheGraceWithAFinalMail(t *testing.T) {
	e, _, ada := world(t)
	e.Clock.Advance(inactiveAfter + day)
	maintain(t, e, false)
	e.Clock.Advance(deletionGrace - day)
	if res := maintain(t, e, false); !idle(res) || !exists(t, e, ada) {
		t.Fatalf("inside the grace: %v, exists %v", res, exists(t, e, ada))
	}
	e.Clock.Advance(2 * day)
	if res := maintain(t, e, false); res[keyDeleted] != 1 || exists(t, e, ada) {
		t.Fatalf("after the grace: %v, exists %v", res, exists(t, e, ada))
	}
	if n := len(mails(e, deletedSubject)); n != 1 {
		t.Fatalf("%d final mails, want 1", n)
	}
	if res := maintain(t, e, false); !idle(res) || len(mails(e, deletedSubject)) != 1 {
		t.Fatalf("second run after the deletion: %v, want nothing", res)
	}
}

// TestStale_DryRunChangesNothing: a dry run reports the counters a real run
// then matches, without a mail, a mark or a deletion.
func TestStale_DryRunChangesNothing(t *testing.T) {
	e, _, ada := world(t)
	e.Clock.Advance(inactiveAfter + day)
	dry := maintain(t, e, true)
	if dry[keyWarned] != 1 || len(mails(e, warnSubject)) != 0 {
		t.Fatalf("dry warning run: %v, %d warnings", dry, len(mails(e, warnSubject)))
	}
	if real := maintain(t, e, false); real[keyWarned] != dry[keyWarned] || len(mails(e, warnSubject)) != 1 {
		t.Fatalf("real run %v after dry run %v", real, dry)
	}
	e.Clock.Advance(deletionGrace + day)
	dry = maintain(t, e, true)
	if dry[keyDeleted] != 1 || !exists(t, e, ada) || len(mails(e, deletedSubject)) != 0 {
		t.Fatalf("dry deletion run: %v, exists %v", dry, exists(t, e, ada))
	}
}

// TestStale_MaintainCommandPrintsTheCounters: "auth maintain --dry-run"
// prints the counters and sends nothing; "auth maintain" does the work; any
// other command line is left to the server.
func TestStale_MaintainCommandPrintsTheCounters(t *testing.T) {
	e, _, _ := world(t)
	ctx := context.Background()
	if _, handled := command(ctx, e.Auth, nil, &bytes.Buffer{}, &bytes.Buffer{}); handled {
		t.Fatal("no arguments must start the server, not the command line")
	}
	e.Clock.Advance(inactiveAfter + day)
	want := keyWarned + "\t1\n"
	for _, args := range [][]string{{authCommand, authcli.CmdMaintain, "--dry-run"}, {authCommand, authcli.CmdMaintain}} {
		var out, errOut bytes.Buffer
		code, handled := command(ctx, e.Auth, args, &out, &errOut)
		if !handled || code != authcli.ExitOK || !strings.Contains(out.String(), want) || errOut.Len() != 0 {
			t.Fatalf("%v: code %d handled %v\nstdout:\n%s\nstderr:\n%s", args, code, handled, &out, &errOut)
		}
	}
	if n := len(mails(e, warnSubject)); n != 1 {
		t.Fatalf("%d warnings after a dry run and a real run, want 1", n)
	}
}
