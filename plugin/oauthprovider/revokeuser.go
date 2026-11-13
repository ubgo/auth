package oauthprovider

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authcli"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/sqlb"
)

// The operator's revoke: end everything one user holds at one client at
// once, from the operator's side, with no signed-in user. It is what an
// access list change needs to take effect now rather than at the client's
// next refresh: ClientAccess already refuses that refresh, but an access
// token the client holds stays good until it expires, and a client that
// re-checks only on refresh keeps the user in until then.
//
// It is a plain Go method, like DeleteClient, SetClientDisabled and
// PatchClient, not an auth.Define operation: operations are routes run for a
// caller the pipeline authenticates (Public, SignedIn, FreshSignIn), and the
// core has no operator requirement. The self-service counterpart,
// RevokeConsent, is an operation because it acts for the signed-in user.

// SubClientRevokeUser is the `auth oauth-client revoke-user` subcommand,
// beside the SubClient* constants of cli.go.
const SubClientRevokeUser = "revoke-user"

// RevokeUserRequest names the user and the client whose grant
// RevokeUserForClient ends. Both are ids: the command line resolves a client
// name or an email address before it calls, so the Go API never guesses
// which account an address means.
type RevokeUserRequest struct {
	// ClientID is the client; it must exist (a trusted client counts: the
	// revoke ends the user's tokens, it changes nothing about the client).
	ClientID string
	// UserID is the user; it must exist, so a mistyped id is an error
	// rather than a silent "nothing to revoke".
	UserID string
}

// RevokeUserResult is what RevokeUserForClient ended, for the operator's
// output and an app's audit log. A second call for the same pair returns
// all zero: the revoke is idempotent, so a script re-running an access list
// change is safe.
type RevokeUserResult struct {
	// Tokens is the number of token rows revoked. One row is one issuance:
	// an access token and, with offline_access, its refresh token; every
	// refresh family of the user at the client is covered.
	Tokens int64 `json:"tokens"`
	// Codes is the number of authorization codes issued to the client for
	// the user and not yet redeemed, deleted so none turns into a token
	// after the revoke.
	Codes int64 `json:"codes"`
	// Consent reports whether a stored consent was deleted: the user's next
	// authorization asks again, unless the client skips consent.
	Consent bool `json:"consent"`
	// LogoutNotices is the number of back-channel logout tokens scheduled
	// for the client, delivered after the commit (0 when the client has no
	// backchannel_logout_uri or is disabled).
	LogoutNotices int `json:"logout_notices"`
}

// RevokeUserForClient revokes every access token, refresh token, unredeemed
// code and the consent that one user holds at one client, in one
// transaction, from Go. Named for what it ends (one user, one client), so it
// reads apart from Revoke (RFC 7009, one token presented by its client) and
// RevokeConsent (the signed-in user withdrawing their own consent).
//
// What stays true after it returns nil:
//   - introspection, userinfo and VerifyAccessToken answer inactive for
//     every token it revoked, and the token endpoint refuses each refresh
//     token as invalid_grant, inside RefreshReuseInterval too (a revoked
//     family is never inside the window);
//   - when the client has a backchannel_logout_uri, it is sent one logout
//     token per session of the user's revoked tokens (sub and sid), and one
//     with sub alone for tokens issued on no session, unless the client set
//     backchannel_logout_session_required; delivery is after the commit,
//     not retried, and its failure is logged, never returned, as for a
//     sign-out (SessionEnded).
//
// What it does not do: it does not stop the user from authorizing again.
// The user's session at this server is untouched, so a client that sends
// the user back to authorize gets a new code unless ClientAccess now
// refuses the user; change the access rule first, then revoke. A JWT access
// token (one issued for a resource) that a resource server verifies by
// signature alone stays valid there until its exp; only servers that
// introspect see the revoke at once.
//
// An unknown client is ErrClientNotFound and an unknown user
// auth.ErrUserNotFound; any database error rolls the whole revoke back.
func (p *Plugin) RevokeUserForClient(ctx context.Context, in RevokeUserRequest) (RevokeUserResult, error) {
	var res RevokeUserResult
	err := p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		c, err := p.loadClient(ctx, in.ClientID)
		if err != nil {
			return err
		}
		if in.UserID == "" {
			return auth.ErrUserNotFound
		}
		if _, err := p.core.User(ctx, in.UserID); err != nil {
			return err
		}
		// The notices are worked out from the rows about to be revoked, before
		// the UPDATE: afterwards nothing tells them from rows revoked earlier,
		// and a second run must notify nobody.
		targets, err := p.revokeUserTargets(ctx, c, in.UserID)
		if err != nil {
			return err
		}
		d, now := p.core.Dialect(), p.core.Now()
		if res.Tokens, err = p.core.Exec(ctx, sqlb.NewUpdate(d).Table(TableToken).Set(sqlb.Set(TokenRevoked, &now)).
			Where(sqlb.Eq(TokenUser, &in.UserID), sqlb.Eq(TokenClient, in.ClientID), sqlb.IsNull(TokenRevoked))); err != nil {
			return err
		}
		// A redeemed code stays: it is the root of its (now revoked) family,
		// and presenting it again must still read as a replay.
		if res.Codes, err = p.core.Exec(ctx, sqlb.NewDelete(d).From(TableCode).
			Where(sqlb.Eq(CodeUser, in.UserID), sqlb.Eq(CodeClient, in.ClientID), sqlb.IsNull(CodeConsumed))); err != nil {
			return err
		}
		n, err := p.core.Exec(ctx, sqlb.NewDelete(d).From(TableConsent).Where(sqlb.Eq(ConsentUser, in.UserID), sqlb.Eq(ConsentClient, in.ClientID)))
		if err != nil {
			return err
		}
		res.Consent = n > 0
		res.LogoutNotices = len(targets)
		if len(targets) > 0 {
			p.core.AfterCommit(ctx, func(ctx context.Context) {
				p.core.RunInBackground(ctx, func(ctx context.Context) { p.deliverLogoutTokens(ctx, targets) })
			})
		}
		return nil
	})
	if err != nil {
		return RevokeUserResult{}, err
	}
	return res, nil
}

// revokeUserTargets is the back-channel logout notices RevokeUserForClient
// sends c for userID: one per distinct session of the user's unrevoked
// tokens at c, and one without a session for tokens issued on none (a
// device or extension grant) unless c requires sid
// (backchannel_logout_session_required). None when c is disabled or has no
// backchannel_logout_uri, as for a sign-out (endSessions).
func (p *Plugin) revokeUserTargets(ctx context.Context, c clientRow, userID string) ([]logoutTarget, error) {
	if c.disabledAt != nil || deref(c.backchannel) == "" {
		return nil, nil
	}
	var session *string
	seen := map[string]bool{}
	var targets []logoutTarget
	q := p.core.Select().Columns(sqlb.Bind(TokenSession, &session)).From(TableToken).
		Where(sqlb.Eq(TokenUser, &userID), sqlb.Eq(TokenClient, c.c.ClientID), sqlb.IsNull(TokenRevoked))
	err := p.core.Each(ctx, q, func() error {
		sid := deref(session)
		if seen[sid] || (sid == "" && c.c.BackchannelLogoutSessionRequired) {
			return nil
		}
		seen[sid] = true
		targets = append(targets, logoutTarget{client: c, sessionID: sid, userID: userID})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return targets, nil
}

// revokeUserUsage is the revoke-user line of the oauth-client usage text.
const revokeUserUsage = `auth oauth-client revoke-user <id|name> <user-id|email> [--json]
                          revoke every token, code and the consent the user holds at the
                          client, and send the client a back-channel logout; the email must be
                          a verified address; nothing left to revoke is success (all zero)
`

// cliRevokeUser runs `auth oauth-client revoke-user <client> <user>`.
//
// The client is found as show, update and delete find it (findClient: id,
// then a name only one client has). The user is found by id with the core's
// User, then, when that is auth.ErrUserNotFound and the argument holds an
// "@", as the owner of that verified email address (the core's FindIdentity
// with email.KindEmail, verifiedOnly true): an unverified address could
// belong to someone who typed it at sign-up, and ClientAccess never sees one
// either. A user found neither way is ErrUserNotFound.
//
// Output: one line on stdout naming the client, the user and the counts
// ("revoked 3 tokens, 0 codes and the consent of user usr_1 (a@b.c) at
// client cl_1 (Admin); 1 logout notice scheduled"), or the RevokeUserResult
// as JSON with --json. Exit codes are cli.go's: ExitOK on success,
// including nothing to revoke, ExitUsage for missing or extra arguments,
// ExitFailed for an unknown client or user, an ambiguous name or a database
// error, with the error on stderr through cliResult.
func (p *Plugin) cliRevokeUser(ctx context.Context, fs *flag.FlagSet, args []string, asJSON *bool, std authcli.IO) int {
	if len(args) < 2 || strings.HasPrefix(args[0], "-") || strings.HasPrefix(args[1], "-") {
		fmt.Fprint(std.Stderr, clientUsage)
		return authcli.ExitUsage
	}
	if code, stop := authcli.ParseFlags(fs, args[2:]); stop {
		return code
	}
	if fs.NArg() > 0 {
		fmt.Fprint(std.Stderr, clientUsage)
		return authcli.ExitUsage
	}
	c, err := p.findClient(ctx, args[0])
	if err != nil {
		return cliResult(std.Stderr, SubClientRevokeUser, err)
	}
	u, err := p.findRevokeUser(ctx, args[1])
	if err != nil {
		return cliResult(std.Stderr, SubClientRevokeUser, err)
	}
	res, err := p.RevokeUserForClient(ctx, RevokeUserRequest{ClientID: c.ClientID, UserID: u.ID})
	if err != nil {
		return cliResult(std.Stderr, SubClientRevokeUser, err)
	}
	if *asJSON {
		return cliResult(std.Stderr, SubClientRevokeUser, printJSON(std.Stdout, res))
	}
	_, err = fmt.Fprintln(std.Stdout, revokeUserLine(c, u, args[1], res))
	return cliResult(std.Stderr, SubClientRevokeUser, err)
}

// emailMark is what tells an email address from a user id on the command
// line: no user id the core generates holds it.
const emailMark = "@"

// findRevokeUser resolves the revoke-user command's user argument: a user
// id first, then, for an argument holding emailMark, the owner of that
// address as a verified email (an unverified one could be anyone's who
// typed it). Neither is auth.ErrUserNotFound; a failed read is its own
// error.
func (p *Plugin) findRevokeUser(ctx context.Context, ref string) (auth.User, error) {
	u, err := p.core.User(ctx, ref)
	if err == nil || !errors.Is(err, auth.ErrUserNotFound) || !strings.Contains(ref, emailMark) {
		return u, err
	}
	idn, err := p.core.FindIdentity(ctx, email.KindEmail, ref, true)
	if errors.Is(err, auth.ErrIdentityNotFound) {
		return auth.User{}, auth.ErrUserNotFound
	}
	if err != nil {
		return auth.User{}, err
	}
	return p.core.User(ctx, idn.UserID)
}

// revokeUserLine is the revoke-user command's one line of output: what was
// ended, for whom, at which client, and how many logout notices went out.
// The user is shown as the operator named them when that was an address.
func revokeUserLine(c Client, u auth.User, ref string, res RevokeUserResult) string {
	who := u.ID
	if strings.Contains(ref, emailMark) && ref != u.ID {
		who += " (" + ref + ")"
	}
	consent := "no consent"
	if res.Consent {
		consent = "the consent"
	}
	return fmt.Sprintf("revoked %s, %s and %s of user %s at client %s (%s); %s scheduled",
		plural(res.Tokens, "token"), plural(res.Codes, "code"), consent, who, c.ClientID, c.Name, plural(int64(res.LogoutNotices), "logout notice"))
}

// plural is "1 token" or "3 tokens".
func plural(n int64, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
