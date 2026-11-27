package integration

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/access"
	"github.com/ubgo/auth/plugin/access/accessadmin"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/audit"
	"github.com/ubgo/auth/plugin/password"
)

// The operator methods of the admin plugin (IsAdmin, BanOf, UnbanFor,
// RevokeAdmin, AdminUserIDs): Go only, for trusted code with no signed-in
// admin, on every engine.

// operatorRoleSuper is a role the operator tests define beside the built-in
// ones, to store a role that only a later configuration makes an admin role.
const operatorRoleSuper = "super"

// operatorAuthorizer defines the built-in roles plus operatorRoleSuper, so a
// plugin may store it whether or not AdminRoles names it.
func operatorAuthorizer() admin.Authorizer {
	ac := accessadmin.DefaultAccessControl
	super := ac.MustRole(access.Permissions(admin.DefaultStatements.Clone()))
	return accessadmin.MustNew(ac, map[string]access.Role{operatorRoleSuper: super})
}

// operatorAdmins is an admin world whose configuration was later changed:
// dave stored operatorRoleSuper while it was an ordinary role, and the second
// plugin (ad) names it in AdminRoles and lists carol and an id with no user
// yet in AdminIDs. Boss holds the staff flag; bob is nobody.
type operatorAdmins struct {
	*adminWorld
	ad          *admin.Plugin
	carol, dave auth.User
	ghost       string
}

func newOperatorAdmins(t *testing.T, e *env) *operatorAdmins {
	t.Helper()
	ctx := context.Background()
	w := newAdminWorld(t, e, []admin.Option{admin.WithAuthorizer(operatorAuthorizer())})
	o := &operatorAdmins{adminWorld: w, ghost: "usr_not_yet"}
	o.carol = must[auth.User](t)(w.a.CreateUser(ctx, auth.NewUser{Name: "Carol"}))
	o.dave = must[auth.User](t)(w.a.CreateUser(ctx, auth.NewUser{Name: "Dave"}))
	if err := w.ad.SetRoleFor(ctx, o.dave.ID, operatorRoleSuper); err != nil {
		t.Fatal(err)
	}
	o.ad = admin.New(admin.WithAuthorizer(operatorAuthorizer()), admin.AdminRoles(admin.RoleAdmin, operatorRoleSuper), admin.AdminIDs(o.carol.ID, o.ghost))
	e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), o.ad)
	return o
}

// TestAdminOperator_IsAdmin: the staff flag, AdminIDs and an admin role each
// make an admin, by the same rule the plugin protects admins with; an
// ordinary user is not one and an unknown user is ErrUserNotFound.
func TestAdminOperator_IsAdmin(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOperatorAdmins(t, e)
		ctx := context.Background()
		for _, c := range []struct {
			name, id string
			want     bool
		}{
			{"staff flag", o.boss.User.ID, true},
			{"AdminIDs", o.carol.ID, true},
			{"admin role, no flag", o.dave.ID, true},
			{"ordinary user", o.bob.User.ID, false},
		} {
			if got := must[bool](t)(o.ad.IsAdmin(ctx, c.id)); got != c.want {
				t.Errorf("%s: IsAdmin = %v, want %v", c.name, got, c.want)
			}
		}
		// The plugin agrees: a user IsAdmin answers true for cannot be banned.
		if err := o.ad.BanFor(ctx, o.dave.ID, "", time.Time{}); !errors.Is(err, admin.ErrAdminTarget) {
			t.Fatalf("banning an admin by role: %v", err)
		}
		// Under the first configuration super is no admin role.
		if must[bool](t)(o.adminWorld.ad.IsAdmin(ctx, o.dave.ID)) {
			t.Fatal("super is not an admin role of the first plugin")
		}
		for _, id := range []string{"usr_nobody", o.ghost} {
			if _, err := o.ad.IsAdmin(ctx, id); !errors.Is(err, auth.ErrUserNotFound) {
				t.Fatalf("IsAdmin(%s): %v, want ErrUserNotFound", id, err)
			}
		}
	})
}

// TestAdminOperator_AdminUserIDs: the list is exactly the users IsAdmin says
// yes to plus the AdminIDs entries, sorted; it is an empty slice, not nil,
// when there are none; a revoked admin leaves it.
func TestAdminOperator_AdminUserIDs(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		empty := admin.New()
		e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), empty)
		if got := must[[]string](t)(empty.AdminUserIDs(ctx)); got == nil || len(got) != 0 {
			t.Fatalf("no admins = %#v, want an empty slice", got)
		}
		o := newOperatorAdmins(t, e)
		want := []string{o.boss.User.ID, o.carol.ID, o.dave.ID, o.ghost}
		slices.Sort(want)
		got := must[[]string](t)(o.ad.AdminUserIDs(ctx))
		if !slices.Equal(got, want) {
			t.Fatalf("AdminUserIDs = %v, want %v", got, want)
		}
		for _, id := range got {
			if id == o.ghost {
				continue
			}
			if !must[bool](t)(o.ad.IsAdmin(ctx, id)) {
				t.Fatalf("%s is listed but IsAdmin says no", id)
			}
		}
		if first := must[[]string](t)(o.adminWorld.ad.AdminUserIDs(ctx)); !slices.Equal(first, []string{o.boss.User.ID}) {
			t.Fatalf("first plugin's admins = %v", first)
		}
		if err := o.ad.RevokeAdmin(ctx, o.dave.ID); err != nil {
			t.Fatal(err)
		}
		want = slices.DeleteFunc(want, func(id string) bool { return id == o.dave.ID })
		if got := must[[]string](t)(o.ad.AdminUserIDs(ctx)); !slices.Equal(got, want) {
			t.Fatalf("after revoking dave = %v, want %v", got, want)
		}
	})
}

// TestAdminOperator_BanOf: no ban, a permanent ban, a temporary ban in force
// up to (not at) its expiry, and none after UnbanFor; the ban returned is the
// stored one. Unknown users are ErrUserNotFound.
func TestAdminOperator_BanOf(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newAdminWorld(t, e, nil)
		ctx, bob := context.Background(), w.bob.User.ID
		none := func(when string) {
			t.Helper()
			b, ok, err := w.ad.BanOf(ctx, bob)
			if err != nil || ok || b != (admin.Ban{}) {
				t.Fatalf("%s: BanOf = %+v, %v, %v, want none", when, b, ok, err)
			}
		}
		inForce := func(when, reason string, expires *time.Time) {
			t.Helper()
			b, ok, err := w.ad.BanOf(ctx, bob)
			if err != nil || !ok || b.UserID != bob || b.Reason != reason || b.BannedAt.IsZero() {
				t.Fatalf("%s: BanOf = %+v, %v, %v", when, b, ok, err)
			}
			if (expires == nil) != (b.ExpiresAt == nil) || (expires != nil && !b.ExpiresAt.Equal(*expires)) {
				t.Fatalf("%s: ExpiresAt = %v, want %v", when, b.ExpiresAt, expires)
			}
		}
		if _, _, err := w.ad.BanOf(ctx, "usr_nobody"); !errors.Is(err, auth.ErrUserNotFound) {
			t.Fatalf("unknown user: %v", err)
		}
		none("never banned")
		if err := w.ad.BanFor(ctx, bob, "spam", time.Time{}); err != nil {
			t.Fatal(err)
		}
		inForce("permanent", "spam", nil)
		e.clock.Advance(1000 * time.Hour)
		inForce("permanent, much later", "spam", nil)
		if err := w.ad.UnbanFor(ctx, bob); err != nil {
			t.Fatal(err)
		}
		none("after UnbanFor")
		until := e.clock.Now().Add(time.Hour)
		if err := w.ad.BanFor(ctx, bob, "cool off", until); err != nil {
			t.Fatal(err)
		}
		inForce("temporary", "cool off", &until)
		e.clock.Advance(time.Hour - time.Second)
		inForce("a second before expiry", "cool off", &until)
		e.clock.Advance(time.Second)
		none("at expiry")
		// The session check uses the same rule: bob signs in again.
		if _, err := w.pw.SignIn(anon(w.a), password.SignInRequest{Identifier: "bob@example.com", Password: secret}); err != nil {
			t.Fatalf("sign-in after expiry: %v", err)
		}
	})
}

// TestAdminOperator_UnbanFor: the ban lifts and sign-in works again, the
// reason is cleared; a user who is not banned is no error; an unknown user is
// ErrUserNotFound; the audit plugin records it with no actor.
func TestAdminOperator_UnbanFor(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newAuditWorld(t, e)
		ctx, bob := context.Background(), w.bob.User.ID
		signIn := func() error {
			_, err := w.pw.SignIn(anon(w.a), password.SignInRequest{Identifier: "bob@example.com", Password: secret})
			return err
		}
		if err := w.ad.UnbanFor(ctx, "usr_nobody"); !errors.Is(err, auth.ErrUserNotFound) {
			t.Fatalf("unknown user: %v", err)
		}
		if err := w.ad.BanFor(ctx, bob, "fraud", time.Time{}); err != nil {
			t.Fatal(err)
		}
		if err := signIn(); !errors.Is(err, admin.ErrBanned) {
			t.Fatalf("sign-in while banned: %v", err)
		}
		if err := w.ad.UnbanFor(ctx, bob); err != nil {
			t.Fatal(err)
		}
		if err := signIn(); err != nil {
			t.Fatalf("sign-in after UnbanFor: %v", err)
		}
		if d := must[admin.UserDetail](t)(w.ad.User(w.bossCtx(), bob)); d.BanReason != "" || d.User.Banned {
			t.Fatalf("after UnbanFor: %+v", d)
		}
		pg := must[audit.Page](t)(w.au.Events(ctx, audit.Query{Op: admin.EndpointUnban, UserID: bob}))
		if pg.Total != 1 || pg.Events[0].ActorID != "" || pg.Events[0].SubjectID != bob || !pg.Events[0].OK || pg.Events[0].Transport != auth.TransportGo {
			t.Fatalf("audit = %+v", pg.Events)
		}
		if err := w.ad.UnbanFor(ctx, bob); err != nil {
			t.Fatalf("unbanning a user who is not banned: %v", err)
		}
	})
}

// TestAdminOperator_UnbanForLogs: an app's own audit log (EventRecorder) gets
// the unban. Without any log the unban works too: TestAdminOperator_BanOf
// and the UnbanFor fault sweep run it on a plugin with no recorder.
func TestAdminOperator_UnbanForLogs(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		log := &recordOnlyLog{}
		w := adminWithLog(t, e, log)
		ctx := context.Background()
		if err := w.ad.BanFor(ctx, w.bob.User.ID, "", time.Time{}); err != nil {
			t.Fatal(err)
		}
		if err := w.ad.UnbanFor(ctx, w.bob.User.ID); err != nil {
			t.Fatal(err)
		}
		if len(log.recorded) != 2 || log.recorded[1].Op != admin.EndpointUnban || log.recorded[1].SubjectID != w.bob.User.ID || log.recorded[1].ActorID != "" {
			t.Fatalf("recorded %+v", log.recorded)
		}
	})
}

// TestAdminOperator_RevokeAdmin: the flag and the admin roles go, the user
// keeps their other roles or DefaultRole; the last admin is refused; a user
// who is not an admin is a no-op and records nothing; an unknown user is
// ErrUserNotFound; each change is recorded with no actor.
func TestAdminOperator_RevokeAdmin(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newAuditWorld(t, e)
		ctx := context.Background()
		boss, bob := w.boss.User.ID, w.bob.User.ID
		roles := func(id string) []string { t.Helper(); return must[[]string](t)(w.ad.RolesOf(ctx, id)) }
		isAdmin := func(id string) bool { t.Helper(); return must[bool](t)(w.ad.IsAdmin(ctx, id)) }
		revoked := func() int64 {
			t.Helper()
			return must[audit.Page](t)(w.au.Events(ctx, audit.Query{Op: admin.EndpointSetAdmin})).Total
		}
		if err := w.ad.RevokeAdmin(ctx, "usr_nobody"); !errors.Is(err, auth.ErrUserNotFound) {
			t.Fatalf("unknown user: %v", err)
		}
		if err := w.ad.RevokeAdmin(ctx, boss); !errors.Is(err, admin.ErrLastAdmin) {
			t.Fatalf("the last admin: %v, want ErrLastAdmin", err)
		}
		if !isAdmin(boss) {
			t.Fatal("a refused revoke changed the last admin")
		}
		if err := w.ad.RevokeAdmin(ctx, bob); err != nil {
			t.Fatalf("not an admin: %v", err)
		}
		if n := revoked(); n != 0 {
			t.Fatalf("a no-op revoke was recorded (%d events)", n)
		}
		// Bob holds the flag only (Grant): he is left with DefaultRole.
		if err := w.ad.Grant(ctx, bob); err != nil {
			t.Fatal(err)
		}
		if err := w.ad.RevokeAdmin(ctx, bob); err != nil {
			t.Fatal(err)
		}
		if isAdmin(bob) || !slices.Equal(roles(bob), []string{admin.RoleUser}) {
			t.Fatalf("bob after revoke: admin %v, roles %v", isAdmin(bob), roles(bob))
		}
		// Carol holds the admin role beside another one: only the admin role goes.
		carol := must[auth.User](t)(w.a.CreateUser(ctx, auth.NewUser{Name: "Carol"}))
		if err := w.ad.SetRoleFor(ctx, carol.ID, admin.RoleAdmin, admin.RoleUser); err != nil {
			t.Fatal(err)
		}
		if err := w.ad.RevokeAdmin(ctx, carol.ID); err != nil {
			t.Fatal(err)
		}
		if isAdmin(carol.ID) || !slices.Equal(roles(carol.ID), []string{admin.RoleUser}) {
			t.Fatalf("carol after revoke: admin %v, roles %v", isAdmin(carol.ID), roles(carol.ID))
		}
		if got := must[[]string](t)(w.ad.AdminUserIDs(ctx)); !slices.Equal(got, []string{boss}) {
			t.Fatalf("admins = %v", got)
		}
		pg := must[audit.Page](t)(w.au.Events(ctx, audit.Query{Op: admin.EndpointSetAdmin}))
		if pg.Total != 2 {
			t.Fatalf("audit = %+v, want the two revokes", pg.Events)
		}
		for _, ev := range pg.Events {
			if ev.ActorID != "" || !ev.OK || ev.Transport != auth.TransportGo || (ev.SubjectID != bob && ev.SubjectID != carol.ID) {
				t.Fatalf("audit event = %+v", ev)
			}
		}
		// Boss is the last admin again.
		if err := w.ad.RevokeAdmin(ctx, boss); !errors.Is(err, admin.ErrLastAdmin) {
			t.Fatalf("the last admin again: %v", err)
		}
	})
}

// TestAdminOperator_RevokeAdminKeepsAdminIDs: AdminIDs is configuration, so a
// listed user stays an admin after RevokeAdmin, with or without the flag, and
// the app's own log gets only the change.
func TestAdminOperator_RevokeAdminKeepsAdminIDs(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newAdminWorld(t, e, nil)
		ctx, bob := context.Background(), w.bob.User.ID
		if err := w.ad.Grant(ctx, bob); err != nil {
			t.Fatal(err)
		}
		log := &recordOnlyLog{}
		ad := admin.New(admin.AdminIDs(bob))
		e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), ad, log)
		if err := ad.RevokeAdmin(ctx, bob); err != nil {
			t.Fatal(err)
		}
		if !must[bool](t)(ad.IsAdmin(ctx, bob)) {
			t.Fatal("an AdminIDs user lost admin rights")
		}
		// The flag is gone: the first plugin, without the list, sees no admin.
		if must[bool](t)(w.ad.IsAdmin(ctx, bob)) {
			t.Fatal("the flag was not cleared")
		}
		if err := ad.RevokeAdmin(ctx, bob); err != nil || !must[bool](t)(ad.IsAdmin(ctx, bob)) {
			t.Fatalf("revoking a listed user with no flag: %v", err)
		}
		if len(log.recorded) != 1 || log.recorded[0].Op != admin.EndpointSetAdmin || log.recorded[0].SubjectID != bob || log.recorded[0].ActorID != "" {
			t.Fatalf("recorded %+v", log.recorded)
		}
	})
}

// TestAdminOperator_Faults: every database failure of each operator method
// reaches the caller, with and without an audit log recording in the same
// transaction.
func TestAdminOperator_Faults(t *testing.T) {
	banned := func(t *testing.T, e *faultEnv, w *adminWorld) {
		t.Helper()
		if err := w.ad.BanFor(context.Background(), w.bob.User.ID, "x", e.clock.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	// secondAdmin grants bob, so revoking him passes the last-admin count.
	secondAdmin := func(t *testing.T, w *adminWorld) {
		t.Helper()
		if err := w.ad.Grant(context.Background(), w.bob.User.ID); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("UnbanFor", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			w := newAdminWorld(t, e.env, nil)
			banned(t, e, w)
			return func(ctx context.Context) error { return w.ad.UnbanFor(ctx, w.bob.User.ID) }
		})
	})
	t.Run("UnbanForAudited", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			w := newAuditWorld(t, e.env)
			banned(t, e, w.adminWorld)
			return func(ctx context.Context) error { return w.ad.UnbanFor(ctx, w.bob.User.ID) }
		})
	})
	t.Run("RevokeAdmin", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			w := newAdminWorld(t, e.env, nil)
			secondAdmin(t, w)
			return func(ctx context.Context) error { return w.ad.RevokeAdmin(ctx, w.bob.User.ID) }
		})
	})
	t.Run("RevokeAdminAudited", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			w := newAuditWorld(t, e.env)
			secondAdmin(t, w.adminWorld)
			return func(ctx context.Context) error { return w.ad.RevokeAdmin(ctx, w.bob.User.ID) }
		})
	})
	t.Run("IsAdmin", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			w := newAdminWorld(t, e.env, nil)
			return func(ctx context.Context) error { _, err := w.ad.IsAdmin(ctx, w.boss.User.ID); return err }
		})
	})
	t.Run("BanOf", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			w := newAdminWorld(t, e.env, nil)
			banned(t, e, w)
			return func(ctx context.Context) error { _, _, err := w.ad.BanOf(ctx, w.bob.User.ID); return err }
		})
	})
	t.Run("AdminUserIDs", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			w := newAdminWorld(t, e.env, nil)
			return func(ctx context.Context) error { _, err := w.ad.AdminUserIDs(ctx); return err }
		})
	})
}
