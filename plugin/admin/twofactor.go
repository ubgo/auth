package admin

import (
	"context"
	"database/sql"
	"net/http"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/audit"
)

// Admin control of another user's second factor: see whether it is on,
// pause it, switch it back on, or reset it so the user enrols again. The
// plugin owns no factor and imports no second-factor package: it finds one
// at Init by method set (TwoFactorManager), as it finds the password, email
// and audit plugins, so plugin/twofactor or any other implementation of the
// four methods serves these routes, and an app without one gets
// ErrNoTwoFactorPlugin from them.
//
// Every route asks the Authorizer for a ResourceTwoFactor permission first,
// before the target is looked up, so a refusal never reveals whether a user
// exists. Pausing and resetting refuse an admin target (ErrAdminTarget), for
// the reason set-password does: lowering an admin's protection is how a
// stolen admin session takes over the other admins. Sessions follow the
// second-factor plugin's own rules: a pause or a reset leaves them alone
// (the user's sessions were made with the factor, and revoke-sessions is the
// separate act for a suspected takeover); switching back on ends them,
// because sessions made during the pause never passed the factor.

// Operation ids of the two-factor routes.
const (
	EndpointTwoFactor        auth.EndpointID = "admin.two-factor"
	EndpointDisableTwoFactor auth.EndpointID = "admin.disable-two-factor"
	EndpointEnableTwoFactor  auth.EndpointID = "admin.enable-two-factor"
	EndpointResetTwoFactor   auth.EndpointID = "admin.reset-two-factor"
)

// ErrNoTwoFactorPlugin refuses the two-factor routes when no registered
// plugin manages second factors (TwoFactorManager). It is answered after the
// permission check, so it tells a caller without the permission nothing.
var ErrNoTwoFactorPlugin = auth.NewError("admin.no_two_factor_plugin", http.StatusConflict, "No two-factor plugin is registered.")

// TwoFactorManager is what the admin plugin needs from a second-factor
// plugin to manage another user's factor: the methods `*twofactor.Plugin`
// already has. Found through auth.PluginOf at Init, so the admin plugin
// imports no second-factor package, and any implementation with these four
// methods is used. The methods check nobody; the admin plugin authorizes
// before it calls them.
//
//ds:def id=admin-twofactormanager-c8v4nq2x owner=@khanakia stability=api
type TwoFactorManager interface {
	auth.Plugin
	// FactorOf is userID's confirmed factor's method ("" for none, which
	// includes an enrolment still waiting for its first code) and whether
	// sign-in asks for it.
	FactorOf(ctx context.Context, userID string) (method string, enabled bool, err error)
	// DisableFor pauses the factor: sign-in stops asking, the factor and
	// its recovery codes stay.
	DisableFor(ctx context.Context, userID string) error
	// EnableFor switches a paused factor back on.
	EnableFor(ctx context.Context, userID string) error
	// Reset removes the factor, its recovery codes and its trusted devices,
	// so the user enrols again.
	Reset(ctx context.Context, userID string) error
}

// TwoFactorResult is the output of two-factor: what a support screen shows
// before it pauses or resets anything.
type TwoFactorResult struct {
	// Enrolled is true when the user has a confirmed factor, on or paused.
	Enrolled bool `json:"enrolled"`
	// Enabled is true when sign-in asks for it; Enrolled and not Enabled is
	// a paused factor.
	Enabled bool `json:"enabled"`
	// Method is the factor's method as the second-factor plugin names it
	// (plugin/twofactor: "totp" or "delivered"); "" when not enrolled.
	Method string `json:"method"`
}

// TwoFactor shows a user's second factor, as the signed-in admin with
// two-factor:get.
func (p *Plugin) TwoFactor(ctx context.Context, userID string) (TwoFactorResult, error) {
	return p.twoFactorOf.Call(ctx, UserRequest{UserID: userID})
}

// DisableTwoFactor pauses a user's second factor, as the signed-in admin
// with a fresh sign-in and two-factor:disable.
func (p *Plugin) DisableTwoFactor(ctx context.Context, userID string) error {
	_, err := p.disableTwoFactor.Call(ctx, UserRequest{UserID: userID})
	return err
}

// EnableTwoFactor switches a paused second factor back on, as the signed-in
// admin with a fresh sign-in and two-factor:enable.
func (p *Plugin) EnableTwoFactor(ctx context.Context, userID string) error {
	_, err := p.enableTwoFactor.Call(ctx, UserRequest{UserID: userID})
	return err
}

// ResetTwoFactor removes a user's second factor and recovery codes so they
// enrol again, as the signed-in admin with a fresh sign-in and
// two-factor:reset.
func (p *Plugin) ResetTwoFactor(ctx context.Context, userID string) error {
	_, err := p.resetTwoFactor.Call(ctx, UserRequest{UserID: userID})
	return err
}

// ResetTwoFactorFor resets userID's second factor from Go only, like BanFor
// from trusted code with no signed-in admin: a recovery command run by an
// operator. Unlike the route it accepts an admin target, because it is the
// way back for an admin who lost their phone when no other admin may reset
// them over HTTP. When an audit log is registered (EventRecorder) the reset
// is recorded under EndpointResetTwoFactor with no actor and the user as
// subject, in the same transaction, so a reset that cannot be recorded does
// not happen. An unknown user is auth.ErrUserNotFound, a user with no factor
// the second-factor plugin's error (plugin/twofactor: ErrNotEnrolled).
//
//ds:def id=admin-resettwofactorfor-w2k9pt4m owner=@khanakia stability=stable
func (p *Plugin) ResetTwoFactorFor(ctx context.Context, userID string) error {
	if p.twoFactor == nil {
		return ErrNoTwoFactorPlugin
	}
	return p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		if _, err := p.core.User(ctx, userID); err != nil {
			return err
		}
		if err := p.twoFactor.Reset(ctx, userID); err != nil {
			return err
		}
		if p.recorder == nil {
			return nil
		}
		return p.recorder.Record(ctx, audit.Event{Op: EndpointResetTwoFactor, Plugin: PluginName, OK: true, SubjectID: userID})
	})
}

// twoFactorTarget is every two-factor route's preamble: the permission
// first (so a refusal says nothing about the target), then the plugin, then
// the user, then, for an operation that lowers protection, the refusal of an
// admin target.
func (p *Plugin) twoFactorTarget(ctx context.Context, c *auth.Call, action, userID string, refuseAdmin bool) error {
	if err := p.require(ctx, c, ResourceTwoFactor, action); err != nil {
		return err
	}
	if p.twoFactor == nil {
		return ErrNoTwoFactorPlugin
	}
	r, err := p.load(ctx, userID)
	if err != nil {
		return err
	}
	if refuseAdmin && p.isAdmin(userID, r.cols) {
		return ErrAdminTarget
	}
	return nil
}

func (p *Plugin) doTwoFactor(ctx context.Context, c *auth.Call, in UserRequest) (TwoFactorResult, error) {
	if err := p.twoFactorTarget(ctx, c, ActionGet, in.UserID, false); err != nil {
		return TwoFactorResult{}, err
	}
	method, enabled, err := p.twoFactor.FactorOf(ctx, in.UserID)
	if err != nil {
		return TwoFactorResult{}, err
	}
	return TwoFactorResult{Enrolled: method != "", Enabled: enabled, Method: method}, nil
}

func (p *Plugin) doDisableTwoFactor(ctx context.Context, c *auth.Call, in UserRequest) (auth.Done, error) {
	if err := p.twoFactorTarget(ctx, c, ActionDisable, in.UserID, true); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, p.twoFactor.DisableFor(ctx, in.UserID)
}

// doEnableTwoFactor accepts an admin target: switching a factor back on
// raises protection, which no stolen session gains anything from.
func (p *Plugin) doEnableTwoFactor(ctx context.Context, c *auth.Call, in UserRequest) (auth.Done, error) {
	if err := p.twoFactorTarget(ctx, c, ActionEnable, in.UserID, false); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, p.twoFactor.EnableFor(ctx, in.UserID)
}

func (p *Plugin) doResetTwoFactor(ctx context.Context, c *auth.Call, in UserRequest) (auth.Done, error) {
	if err := p.twoFactorTarget(ctx, c, ActionReset, in.UserID, true); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, p.twoFactor.Reset(ctx, in.UserID)
}
