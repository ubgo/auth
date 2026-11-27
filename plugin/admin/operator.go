package admin

import (
	"context"
	"database/sql"
	"slices"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/audit"
	"github.com/ubgo/sqlb"
)

// Operator methods: plain Go methods for trusted code with no signed-in admin
// (an operator's command line, an import, a job), beside Grant, BanFor and
// ResetTwoFactorFor. They are never operations and never mounted on a route,
// so nothing reaches them over HTTP; the app that calls them decides who may.
// The reads (IsAdmin, BanOf, AdminUserIDs) let an app's own admin-only routes
// and its own credentials (an OAuth provider's tokens, which live outside
// auth_session) agree with the plugin about who is an admin and who is banned.

// IsAdmin reports whether userID is an admin by the plugin's own rule: the
// staff flag (admin_granted_at), AdminIDs, or one of AdminRoles. It is the
// check an app's own admin-only route makes, so the route and the plugin never
// disagree about who an admin is. An unknown user is auth.ErrUserNotFound.
//
//ds:def id=plugin-isadmin-r4m8vq2k owner=@khanakia stability=stable
func (p *Plugin) IsAdmin(ctx context.Context, userID string) (bool, error) {
	r, err := p.load(ctx, userID)
	if err != nil {
		return false, err
	}
	return p.isAdmin(userID, r.cols), nil
}

// BanOf returns the ban in force on userID, and false when there is none:
// never banned, unbanned, or a temporary ban whose expiry has passed (the
// rule the session check applies). The ban already refuses sessions; BanOf is
// for credentials the plugin does not see, such as the access and refresh
// tokens an OAuth provider issues, so the app can refuse a banned user there
// too. An unknown user is auth.ErrUserNotFound.
//
//ds:def id=plugin-banof-h7w3nk5p owner=@khanakia stability=stable
func (p *Plugin) BanOf(ctx context.Context, userID string) (Ban, bool, error) {
	r, err := p.load(ctx, userID)
	if err != nil {
		return Ban{}, false, err
	}
	if !isBanned(r.cols, p.core.Now()) {
		return Ban{}, false, nil
	}
	return Ban{UserID: userID, Reason: r.cols.BanReason, BannedAt: *r.cols.BannedAt, ExpiresAt: r.cols.BanExpiresAt}, true, nil
}

// UnbanFor lifts userID's ban from Go only, the counterpart of BanFor for
// trusted code with no signed-in admin: it clears the ban, its expiry and its
// reason as unban does. Sessions the ban ended stay ended. A user who is not
// banned is no error; an unknown user is auth.ErrUserNotFound. When an audit
// log is registered (EventRecorder) it is recorded under EndpointUnban with no
// actor and the user as subject, in the same transaction. It runs in one
// transaction, or joins the one in ctx.
//
//ds:def id=plugin-unbanfor-k2p9wd4x owner=@khanakia stability=stable
func (p *Plugin) UnbanFor(ctx context.Context, userID string) error {
	return p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		if err := p.clearBan(ctx, userID); err != nil {
			return err
		}
		if p.recorder == nil {
			return nil
		}
		return p.recorder.Record(ctx, audit.Event{Op: EndpointUnban, Plugin: PluginName, OK: true, SubjectID: userID})
	})
}

// RevokeAdmin removes userID's admin rights from Go only, the counterpart of
// Grant: an operator's command line takes them back with no signed-in admin.
// It is set-admin with admin false: the flag is cleared and every admin role
// dropped (the user keeps DefaultRole when no role is left), and the last
// admin keeps their rights (ErrLastAdmin), so the app is never left with
// nobody who can grant them back. A user who is not an admin is no error. A
// user listed by AdminIDs stays an admin: the option is configuration, not
// data. When an audit log is registered (EventRecorder) a change is recorded
// under EndpointSetAdmin with no actor and the user as subject, in the same
// transaction. It runs in one transaction, or joins the one in ctx; an
// unknown user is auth.ErrUserNotFound.
//
//ds:def id=plugin-revokeadmin-q5t8mz3c owner=@khanakia stability=stable
func (p *Plugin) RevokeAdmin(ctx context.Context, userID string) error {
	return p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		changed, err := p.applyAdmin(ctx, userID, false)
		if err != nil || !changed || p.recorder == nil {
			return err
		}
		return p.recorder.Record(ctx, audit.Event{Op: EndpointSetAdmin, Plugin: PluginName, OK: true, SubjectID: userID})
	})
}

// AdminUserIDs lists the ids of every admin, sorted: the users whose staff
// flag is set (set-admin, set-role and Grant keep it in step with the admin
// roles) and the ids AdminIDs lists. For an operator's "who are the admins"
// command; an AdminIDs entry is listed even when no such user exists yet,
// because the option makes that id an admin the moment it does.
//
//ds:def id=plugin-adminuserids-w6c2xn8j owner=@khanakia stability=stable
func (p *Plugin) AdminUserIDs(ctx context.Context) ([]string, error) {
	var id string
	var out []string
	q := p.core.Select().Columns(sqlb.Bind(auth.UserID, &id)).From(auth.TableUser).Where(sqlb.IsNotNull(GrantedAt))
	if err := p.core.Each(ctx, q, func() error {
		out = append(out, id)
		return nil
	}); err != nil {
		return nil, err
	}
	for listed := range p.adminIDs {
		if !slices.Contains(out, listed) {
			out = append(out, listed)
		}
	}
	slices.Sort(out)
	if out == nil {
		out = []string{}
	}
	return out, nil
}
