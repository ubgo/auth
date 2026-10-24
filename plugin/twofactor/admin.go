package twofactor

import (
	"context"
	"database/sql"
	"errors"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// Reset turns userID's second factor off for them: the support desk's answer
// to a user who lost their phone and their recovery codes. It deletes the
// factor (confirmed or still being set up), every further factor and
// security key, every recovery code and every trusted device, and clears two_factor_enabled, in one transaction, so the
// next sign-in asks for the first factor only and the user can enrol again.
//
// It asks for no code and no password, so it is a server-side call for the
// app to put behind its own staff check; the plugin serves no route for it,
// because who may reset whom is the app's rule. Sessions are left alone: the
// user's own were created with the factor, and an app that suspects the
// account was taken calls auth's DeleteUserSessions as well. A user with no
// factor is ErrNotEnrolled, after the same cleanup, so a mistyped id is seen.
//
//ds:def id=twofactor-reset-8kq3wv5n owner=@khanakia stability=stable
func (p *Plugin) Reset(ctx context.Context, userID string) error {
	if p.core == nil {
		return auth.ErrOperationNotWired
	}
	var removed bool
	err := p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		had, err := p.resetAll(ctx, userID)
		if err != nil {
			return err
		}
		removed = had
		if _, err := p.core.Exec(ctx, sqlb.NewDelete(p.core.Dialect()).From(TableRecovery).Where(sqlb.Eq(RecoveryUser, userID))); err != nil {
			return err
		}
		return auth.SetUserColumn(ctx, p.core, PluginName, userID, Enabled, false)
	})
	if err != nil {
		return err
	}
	if !removed {
		return ErrNotEnrolled
	}
	return nil
}

// Unlock lifts userID's lockout before it expires and clears the count of
// wrong codes, for a support desk that has confirmed who is asking. The
// factor, its secret and the recovery codes are untouched. Like Reset it is a
// server-side call the app authorizes; a user with no factor is
// ErrNotEnrolled.
//
//ds:def id=twofactor-unlock-4tn8xm2q owner=@khanakia stability=stable
func (p *Plugin) Unlock(ctx context.Context, userID string) error {
	if p.core == nil {
		return auth.ErrOperationNotWired
	}
	upd := sqlb.NewUpdate(p.core.Dialect()).Table(TableFactor).
		Set(sqlb.Set(FactorLockedUntil, nil), sqlb.Set(FactorFailures, 0)).
		Where(sqlb.Eq(FactorUserID, userID))
	n, err := p.core.Exec(ctx, upd)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotEnrolled
	}
	return nil
}

// FactorOf reports userID's second factor for a support screen: the method
// of the confirmed factor ("" when there is none, which includes an
// enrolment still waiting for its first code) and whether sign-in asks for
// it (two_factor_enabled). A confirmed factor with enabled false is one
// DisableFor paused. It is the read side of the admin plugin's two-factor
// routes, which find this plugin by method set (admin.TwoFactorManager), so
// it returns plain values and the admin plugin imports nothing from here.
// Like Reset it checks nobody: the caller authorizes.
func (p *Plugin) FactorOf(ctx context.Context, userID string) (method string, enabled bool, err error) {
	if p.core == nil {
		return "", false, auth.ErrOperationNotWired
	}
	row, err := p.load(ctx, userID)
	switch {
	case errors.Is(err, ErrNotEnrolled):
		return "", false, nil
	case err != nil:
		return "", false, err
	case row.confirmedAt == nil:
		return "", false, nil
	}
	on, err := p.enabledFor(ctx, userID)
	return row.method, on, err
}

// DisableFor pauses userID's second factor: sign-in stops asking for it,
// and the factor, its recovery codes and trusted devices stay, so EnableFor
// can switch it back on without the user enrolling again. It is the support
// desk's answer to "my phone is in for repair": Reset is the answer to "my
// phone is gone". While paused the user sees two-factor as off in status
// and may enrol afresh, which replaces the paused factor. Sessions are left
// alone, as with Reset. No confirmed factor is ErrNotEnrolled; pausing a
// paused factor changes nothing.
//
//ds:def id=twofactor-disablefor-r5m2qk8w owner=@khanakia stability=stable
func (p *Plugin) DisableFor(ctx context.Context, userID string) error {
	if err := p.requireConfirmed(ctx, userID); err != nil {
		return err
	}
	return auth.SetUserColumn(ctx, p.core, PluginName, userID, Enabled, false)
}

// EnableFor switches a paused factor back on: the next sign-in asks for it
// again. Every session of the user ends when it does, for the reason
// confirm gives: they were created without the factor. A factor that is
// already on is left as it is and its sessions are kept; no confirmed factor
// is ErrNotEnrolled, because there is nothing to ask for.
//
//ds:def id=twofactor-enablefor-h7w3nd6p owner=@khanakia stability=stable
func (p *Plugin) EnableFor(ctx context.Context, userID string) error {
	if err := p.requireConfirmed(ctx, userID); err != nil {
		return err
	}
	return p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		on, err := p.enabledFor(ctx, userID)
		if err != nil || on {
			return err
		}
		if err := auth.SetUserColumn(ctx, p.core, PluginName, userID, Enabled, true); err != nil {
			return err
		}
		return p.core.EndUserSessions(ctx, userID, "", auth.SessionEndCredentialChanged)
	})
}

// requireConfirmed is nil when userID has a confirmed factor, ErrNotEnrolled
// when they have none or only an unconfirmed enrolment.
func (p *Plugin) requireConfirmed(ctx context.Context, userID string) error {
	if p.core == nil {
		return auth.ErrOperationNotWired
	}
	row, err := p.load(ctx, userID)
	if err != nil {
		return err
	}
	if row.confirmedAt == nil {
		return ErrNotEnrolled
	}
	return nil
}

// enabledFor reads two_factor_enabled: whether sign-in asks for the factor.
// It and a confirmed factor row agree except while DisableFor has paused it.
func (p *Plugin) enabledFor(ctx context.Context, userID string) (bool, error) {
	var c TwoFactorColumns
	err := p.core.LoadUserColumns(ctx, userID, Bindings(&c)...)
	return c.TwoFactorEnabled, err
}
