package integration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/password"
)

func TestAdmin_BanFindAndLastAdmin(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, ad := e.emailPlugin(), e.passwordPlugin(), admin.New()
		a := e.newAuth(t, nil, em, pw, ad)
		boss := signUpVerified(t, e, a, pw, em)
		if err := ad.Grant(context.Background(), boss.User.ID); err != nil {
			t.Fatal(err)
		}
		bob := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: "bob@example.com", Password: secret, Name: "Bob"}))
		bossCtx := func() context.Context { return request(a, boss.Token) }

		// A non-admin is refused.
		if _, err := ad.Users(request(a, bob.Token), admin.UsersRequest{}); !errors.Is(err, admin.ErrForbidden) {
			t.Fatalf("non-admin listing: %v", err)
		}
		page := must[admin.UsersResult](t)(ad.Users(bossCtx(), admin.UsersRequest{Limit: 1}))
		if page.Total != 2 || len(page.Users) != 1 {
			t.Fatalf("page = %+v", page)
		}
		found := must[admin.UsersResult](t)(ad.Users(bossCtx(), admin.UsersRequest{Query: " BOB@example.com"}))
		if len(found.Users) != 1 || found.Users[0].ID != bob.User.ID {
			t.Fatalf("search by address = %+v", found)
		}
		if part := must[admin.UsersResult](t)(ad.Users(bossCtx(), admin.UsersRequest{Query: "bob"})); part.Total != 0 {
			t.Fatalf("a fragment must match nothing: %+v", part)
		}

		// A ban ends bob's sessions and refuses new ones.
		if err := ad.Ban(bossCtx(), bob.User.ID, "spam "+strings.Repeat("é", 400)); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := a.ResolveSession(context.Background(), bob.Token); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("banned user's session: %v", err)
		}
		// Signing in again is refused outright, with the ban's code, since
		// the password was right; the session predicate still guards any
		// session that existed before.
		if _, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: "bob@example.com", Password: secret}); !errors.Is(err, admin.ErrBanned) {
			t.Fatalf("a banned user signing in again: %v", err)
		}
		d := must[admin.UserDetail](t)(ad.User(bossCtx(), bob.User.ID))
		// The reason is cut to whole characters that fit the column on every
		// engine; strict MySQL would refuse 405 characters in VARCHAR(320).
		if !d.User.Banned || !strings.HasPrefix(d.BanReason, "spam é") || utf8.RuneCountInString(d.BanReason) != 300 || !utf8.ValidString(d.BanReason) || len(d.Identities) != 1 {
			t.Fatalf("detail = %+v", d)
		}
		if err := ad.Unban(bossCtx(), bob.User.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: "bob@example.com", Password: secret}); err != nil {
			t.Fatalf("after unban: %v", err)
		}

		// Admins cannot be banned, and the last one stays.
		if err := ad.Ban(bossCtx(), boss.User.ID, ""); !errors.Is(err, admin.ErrAdminTarget) {
			t.Fatalf("banning an admin: %v", err)
		}
		if err := ad.SetAdmin(bossCtx(), boss.User.ID, false); !errors.Is(err, admin.ErrLastAdmin) {
			t.Fatalf("removing the last admin: %v", err)
		}
		if err := ad.SetAdmin(bossCtx(), bob.User.ID, true); err != nil {
			t.Fatal(err)
		}
		if err := ad.SetAdmin(bossCtx(), boss.User.ID, false); err != nil {
			t.Fatalf("with a second admin: %v", err)
		}
	})
}

func TestAdmin_ImpersonationIsVisibleLimitedAndStoppable(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, ad := e.emailPlugin(), e.passwordPlugin(), admin.New()
		a := e.newAuth(t, nil, em, pw, ad)
		boss := signUpVerified(t, e, a, pw, em)
		if err := ad.Grant(context.Background(), boss.User.ID); err != nil {
			t.Fatal(err)
		}
		bob := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: "bob@example.com", Password: secret, Name: "Bob"}))

		if _, err := ad.Impersonate(request(a, bob.Token), admin.ImpersonateRequest{UserID: boss.User.ID}); !errors.Is(err, admin.ErrForbidden) {
			t.Fatalf("a non-admin impersonating: %v", err)
		}
		if _, err := ad.Impersonate(request(a, boss.Token), admin.ImpersonateRequest{UserID: boss.User.ID}); !errors.Is(err, admin.ErrAdminTarget) {
			t.Fatalf("impersonating an admin: %v", err)
		}
		as := must[admin.ImpersonateResult](t)(ad.Impersonate(request(a, boss.Token), admin.ImpersonateRequest{UserID: bob.User.ID, Minutes: 600}))
		if got := as.ExpiresAt.Sub(e.clock.Now()); got > auth.MaxImpersonationTTL {
			t.Fatalf("impersonation lasts %v, want at most %v", got, auth.MaxImpersonationTTL)
		}
		ctx := request(a, as.Token)
		if err := a.Resolve(ctx); err != nil {
			t.Fatal(err)
		}
		if u, ok := auth.CurrentUser(ctx); !ok || u.ID != bob.User.ID {
			t.Fatalf("acting as = %+v %v", u, ok)
		}
		// Looking is allowed; changing the password is not.
		if err := pw.Change(request(a, as.Token), password.ChangeRequest{Current: secret, New: "hijacked passphrase"}); !errors.Is(err, auth.ErrImpersonationRefused) {
			t.Fatalf("password change while impersonating: %v", err)
		}
		// Bob sees the impersonation in his own session list.
		op, _ := a.Operation(auth.EndpointSessions)
		out, err := op.Invoke(request(a, bob.Token), func(any) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		seen := false
		for _, s := range out.(auth.SessionsResult).Sessions {
			seen = seen || s.Impersonated
		}
		if !seen {
			t.Fatal("the impersonation must appear in the user's session list")
		}
		if _, err := ad.StopImpersonating(request(a, as.Token)); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := a.ResolveSession(context.Background(), as.Token); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("after stop: %v", err)
		}
		if _, err := ad.StopImpersonating(request(a, bob.Token)); !errors.Is(err, admin.ErrNotImpersonating) {
			t.Fatalf("stop on an ordinary session: %v", err)
		}
	})
}
