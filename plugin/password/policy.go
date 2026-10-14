package password

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// History and expiry: two opt-in policies on top of the rules every new
// password passes. Neither is on by default, because NIST SP 800-63B advises
// against forced periodic changes; both exist because some products must have
// them (a compliance regime, a customer's security questionnaire).

// EndpointChangeExpired changes an expired password and signs in, the one way
// in once ExpireAfter has refused a sign-in. It exists only under ExpireAfter.
const EndpointChangeExpired auth.EndpointID = "password.change-expired"

// pathChangeExpired is EndpointChangeExpired's path under the auth mount.
const pathChangeExpired = "/change-expired"

// MaxHistory is the most passwords History may remember. Every remembered
// hash costs one hash check per change, so the cap bounds the work one change
// can ask of argon2; 24 is the largest history Active Directory allows.
//
//ds:def id=maxhistory-r25pwh01 owner=@khanakia stability=stable
const MaxHistory = 24

// The history table: one row per earlier password of a user, newest kept,
// created only under History. Rows hold hashes, never passwords, in whatever
// format the Hasher wrote them; a legacy format is still compared through
// AcceptLegacyHashes.
const (
	//ds:def id=tablenamepasswordhistory-r25pwh02 owner=@khanakia stability=stable
	TableNamePasswordHistory  = "auth_password_history"
	TableAliasPasswordHistory = "pwh"
	ColHistoryID              = "id"
	ColHistoryUserID          = "user_id"
	ColHistoryHash            = "hash"
	// ColHistorySeq orders a user's rows, 1 for the first replaced password
	// and one more for each after it. A counter rather than created_at,
	// because two changes in one clock tick (or one second, on a coarse
	// timestamp) would tie, and pruning must know which row is oldest.
	ColHistorySeq       = "seq"
	ColHistoryCreatedAt = "created_at"
)

// TablePasswordHistory and its typed columns, for an app that reads the table
// (reads are open; only the plugin writes it).
var (
	TablePasswordHistory = sqlb.Table{Name: TableNamePasswordHistory, Alias: TableAliasPasswordHistory}
	HistoryID            = sqlb.Col[string](TablePasswordHistory, ColHistoryID)
	HistoryUserID        = sqlb.Col[string](TablePasswordHistory, ColHistoryUserID)
	HistoryHash          = sqlb.Col[string](TablePasswordHistory, ColHistoryHash)
	HistorySeq           = sqlb.Col[int64](TablePasswordHistory, ColHistorySeq)
	HistoryCreatedAt     = sqlb.Col[time.Time](TablePasswordHistory, ColHistoryCreatedAt)
)

// historyIDPrefix prefixes the ids of history rows.
const historyIDPrefix = "pwh"

// historyIndexSuffix names the history table's user_id index after the
// table, so a renamed or prefixed table gets a matching index name.
const historyIndexSuffix = "_user_idx"

// migrationHistory is the history table's ledger name; it runs only once
// History is configured, so turning History on later creates the table then.
const migrationHistory = "0002_password_history"

var (
	// ErrReused refuses a new password that matches the current one or one
	// History remembers. It is reached only by someone who already proved the
	// account (a session with the current password, a reset link or code), so
	// it reveals nothing to a stranger.
	//
	//ds:def id=errreused-r25pwh03 owner=@khanakia stability=stable
	ErrReused = auth.NewError("password.reused", http.StatusBadRequest, "Choose a password you have not used recently.")
	// ErrExpired refuses a sign-in with the right password once it is older
	// than ExpireAfter. Only the right password learns it, as with
	// auth.ErrNotVerified; the client then calls change-expired.
	//
	//ds:def id=errexpired-r25pwh04 owner=@khanakia stability=stable
	ErrExpired = auth.NewError("password.expired", http.StatusForbidden, "Your password has expired. Choose a new one.")
	// ErrNotExpired refuses change-expired for a password that has not
	// expired: the route is the way past an expired password, not a second
	// change route without a session. Only the right password learns it.
	ErrNotExpired = auth.NewError("password.not_expired", http.StatusBadRequest, "This password has not expired. Sign in and change it from your account.")

	// ErrHistoryRange is a configuration mistake auth.New refuses: History
	// takes 1 to MaxHistory.
	ErrHistoryRange = fmt.Errorf("password: History takes 1 to %d passwords", MaxHistory)
	// ErrExpireRange is a configuration mistake auth.New refuses: ExpireAfter
	// takes a positive duration.
	ErrExpireRange = errors.New("password: ExpireAfter takes a positive duration")
)

// History refuses a new password that matches the current one or any of the
// n-1 before it, so n is how many passwords a user cannot go back to,
// counting the one in use. It applies to change, reset, change-expired and
// SetPassword; sign-up and ImportHash have no earlier password. Earlier
// passwords are kept as hashes in auth_password_history, which the plugin
// creates on the first migrate after History is set. Each change checks up to
// n hashes, so n is capped at MaxHistory. Turning History off later stops the
// writes and leaves the table and its rows; drop the table if you want the
// hashes gone, because DeleteUser only clears it while History is on.
//
//ds:def id=history-option-r25pwh05 owner=@khanakia stability=stable
func History(n int) Option { return func(p *Plugin) { p.history = n } }

// ExpireAfter makes a password expire d after it was set (sign-up, change,
// reset, SetPassword or ImportHash; the re-hash at sign-in does not reset the
// clock). A sign-in with the right, expired password is refused with
// ErrExpired, and the client sends the identifier, the old password and a new
// one to change-expired, which changes it and signs in. A wrong password is
// ErrInvalidCredentials as always, so the refusal reveals nothing to someone
// who does not know the password. Sessions that already exist are not ended
// when the password expires; expiry is checked at sign-in. A new password
// must differ from the expired one, and with History from the ones it
// remembers. NIST SP 800-63B advises against periodic expiry; set it only
// when a policy requires it.
//
//ds:def id=expireafter-option-r25pwh06 owner=@khanakia stability=stable
func ExpireAfter(d time.Duration) Option { return func(p *Plugin) { p.expireAfter = d } }

// ChangeExpiredRequest is the input of change-expired: the identifier, the
// expired password and the new one.
type ChangeExpiredRequest struct {
	Identifier string `json:"identifier"`
	Current    Secret `json:"current"`
	New        Secret `json:"new"`
	// Remember is the "remember me" box, as on SignInRequest.
	Remember *bool `json:"remember,omitempty"`
}

// RateIdentifier counts change-expired attempts per account, like sign-in:
// the route checks a password.
func (r ChangeExpiredRequest) RateIdentifier() string { return foldKey(r.Identifier) }

// ChangeExpired changes an expired password and starts a session, the way in
// after a sign-in answered ErrExpired. It runs every rule of a new password,
// refuses the expired one itself (ErrReused), and signs out every other
// session and spends every open reset link, as a reset does.
func (p *Plugin) ChangeExpired(ctx context.Context, in ChangeExpiredRequest) (SignInResult, error) {
	return p.changeExpired.Call(ctx, in)
}

// validatePolicies refuses a History or ExpireAfter value no deployment
// means: a negative history, one past MaxHistory, or a negative expiry.
func (p *Plugin) validatePolicies() error {
	if p.history < 0 || p.history > MaxHistory {
		return ErrHistoryRange
	}
	if p.expireAfter < 0 {
		return ErrExpireRange
	}
	return nil
}

// expired reports whether a password set at setAt has expired under
// ExpireAfter; never without it.
func (p *Plugin) expired(setAt time.Time) bool {
	return p.expireAfter > 0 && !p.core.Now().Before(setAt.Add(p.expireAfter))
}

// historyMigration creates auth_password_history for engine.
func (p *Plugin) historyMigration(engine string, t auth.SQLTypes) auth.Migration {
	table := p.core.TableName(TablePasswordHistory)
	index := table + historyIndexSuffix
	create := "CREATE TABLE IF NOT EXISTS " + table + " (" +
		ColHistoryID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
		ColHistoryUserID + " " + t.ID + " NOT NULL, " +
		ColHistoryHash + " " + t.Text + " NOT NULL, " +
		ColHistorySeq + " " + t.Int + " NOT NULL, " +
		ColHistoryCreatedAt + " " + t.Timestamp + " NOT NULL"
	var st []string
	if engine == auth.EngineMySQL {
		st = []string{create + ", INDEX " + index + " (" + ColHistoryUserID + "))" + t.TableSuffix}
	} else {
		st = []string{create + ")" + t.TableSuffix, "CREATE INDEX IF NOT EXISTS " + index + " ON " + table + " (" + ColHistoryUserID + ")"}
	}
	return auth.Migration{Owner: PluginName, Name: migrationHistory, Statements: st}
}

// replace sets userID's password to pw, whose new hash the caller made: it
// refuses a reused one under History, stores the hash, and moves the old one
// into the history. stored and has are the current hash and whether there is
// one, which every caller has already loaded. It is the one writer of a
// changed password, so change, reset, change-expired and SetPassword cannot
// disagree on the rule. The hash comes in made so a Hasher failure stops a
// caller before any row is read or written.
func (p *Plugin) replace(ctx context.Context, userID string, pw Secret, hash, stored string, has bool) error {
	if err := p.checkReuse(ctx, userID, pw, stored, has); err != nil {
		return err
	}
	if err := p.store(ctx, userID, hash, !has); err != nil {
		return err
	}
	if p.history == 0 || !has {
		return nil
	}
	return p.remember(ctx, userID, stored)
}

// checkReuse refuses pw when it matches the current hash or a remembered
// one. Without History it checks nothing. Every remembered hash is checked,
// even after a match, so the work does not depend on which one matched.
func (p *Plugin) checkReuse(ctx context.Context, userID string, pw Secret, stored string, has bool) error {
	if p.history == 0 {
		return nil
	}
	hashes, err := p.historyHashes(ctx, userID)
	if err != nil {
		return err
	}
	if has {
		hashes = append([]string{stored}, hashes...)
	}
	return p.matchAny(pw, hashes)
}

// matchAny is ErrReused when pw verifies against any of hashes. A hash in a
// format the configuration no longer verifies cannot match and is skipped,
// rather than failing every change of a user with an old row.
func (p *Plugin) matchAny(pw Secret, hashes []string) error {
	reused := false
	for _, h := range hashes {
		ok, _, err := p.checkPassword(pw, h)
		switch {
		case errors.Is(err, errBadHash):
		case err != nil:
			return err
		case ok:
			reused = true
		}
	}
	if reused {
		return ErrReused
	}
	return nil
}

// historyHashes returns the hashes History remembers for userID besides the
// current one, newest first, at most History-1 of them.
func (p *Plugin) historyHashes(ctx context.Context, userID string) ([]string, error) {
	rows, err := p.historyRows(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows[:min(len(rows), p.history-1)] {
		out = append(out, r.hash)
	}
	return out, nil
}

// historyRow is one auth_password_history row.
type historyRow struct {
	id, hash string
	seq      int64
}

// historyRows reads every history row of userID, newest (highest seq) first.
func (p *Plugin) historyRows(ctx context.Context, userID string) ([]historyRow, error) {
	var r historyRow
	var out []historyRow
	q := p.core.Select().Columns(sqlb.Bind(HistoryID, &r.id), sqlb.Bind(HistoryHash, &r.hash), sqlb.Bind(HistorySeq, &r.seq)).
		From(TablePasswordHistory).Where(sqlb.Eq(HistoryUserID, userID)).
		Order(sqlb.OrderBy(HistorySeq, sqlb.SortDesc), sqlb.OrderBy(HistoryID, sqlb.SortDesc))
	err := p.core.Each(ctx, q, func() error {
		out = append(out, r)
		return nil
	})
	return out, err
}

// remember stores the replaced hash as the newest history row and deletes
// the rows past History-1, so the table holds exactly what the next check
// needs and an old hash does not outlive the policy.
func (p *Plugin) remember(ctx context.Context, userID, old string) error {
	id, err := p.core.NewID(historyIDPrefix)
	if err != nil {
		return err
	}
	rows, err := p.historyRows(ctx, userID)
	if err != nil {
		return err
	}
	next := int64(1)
	if len(rows) > 0 {
		next = rows[0].seq + 1
	}
	d := p.core.Dialect()
	if _, err := p.core.Exec(ctx, sqlb.NewInsert(d).Into(TablePasswordHistory).Row(
		sqlb.Set(HistoryID, id), sqlb.Set(HistoryUserID, userID), sqlb.Set(HistoryHash, old),
		sqlb.Set(HistorySeq, next), sqlb.Set(HistoryCreatedAt, p.core.Now()))); err != nil {
		return err
	}
	rows = append([]historyRow{{id: id, hash: old, seq: next}}, rows...)
	if len(rows) <= p.history-1 {
		return nil
	}
	stale := make([]string, 0, len(rows))
	for _, r := range rows[p.history-1:] {
		stale = append(stale, r.id)
	}
	_, err = p.core.Exec(ctx, sqlb.NewDelete(d).From(TablePasswordHistory).Where(sqlb.In(HistoryID, stale...)))
	return err
}

// doChangeExpired is sign-in and change in one, for an expired password only.
// It is enumeration-safe like sign-in: an unknown identifier, an account
// without a password and a wrong password all cost one hash check and answer
// ErrInvalidCredentials; only the right password learns ErrNotVerified,
// ErrNotExpired or ErrReused.
func (p *Plugin) doChangeExpired(ctx context.Context, c *auth.Call, in ChangeExpiredRequest) (SignInResult, error) {
	if len(in.Current) > p.maxLen {
		return SignInResult{}, ErrInvalidCredentials
	}
	if err := p.checkNew(ctx, in.New); err != nil {
		return SignInResult{}, err
	}
	idn, kind, err := c.Auth.FindSignInIdentity(ctx, in.Identifier)
	if err != nil && !errors.Is(err, auth.ErrIdentityNotFound) && !errors.Is(err, auth.ErrIdentifierInvalid) {
		return SignInResult{}, err
	}
	stored, setAt, found := p.dummy, time.Time{}, false
	if err == nil {
		h, at, lerr := p.loadSet(ctx, idn.UserID)
		switch {
		case lerr == nil:
			stored, setAt, found = h, at, true
		case !errors.Is(lerr, sqlb.ErrNoRows):
			return SignInResult{}, lerr
		}
	}
	ok, _, err := p.checkPassword(in.Current, stored)
	if err != nil {
		return SignInResult{}, err
	}
	if !ok || !found {
		return SignInResult{}, ErrInvalidCredentials
	}
	if kind.RequireVerified && !idn.Verified() {
		return SignInResult{}, auth.ErrNotVerified
	}
	if !p.expired(setAt) {
		return SignInResult{}, ErrNotExpired
	}
	if p.history == 0 {
		// Without History the expired password itself is still refused:
		// typing it again would satisfy the policy in name only.
		if err := p.matchAny(in.New, []string{stored}); err != nil {
			return SignInResult{}, err
		}
	}
	hash, err := p.hasher.Hash(in.New)
	if err != nil {
		return SignInResult{}, err
	}
	if err := p.replace(ctx, idn.UserID, in.New, hash, stored, true); err != nil {
		return SignInResult{}, err
	}
	if err := c.Auth.ConsumeAllVerifications(ctx, PurposeResetToken, idn.UserID); err != nil {
		return SignInResult{}, err
	}
	if err := c.Auth.EndUserSessions(ctx, idn.UserID, "", auth.SessionEndPasswordReset); err != nil {
		return SignInResult{}, err
	}
	if err := c.Auth.CredentialChanged(ctx, idn.UserID); err != nil {
		return SignInResult{}, err
	}
	u, err := c.Auth.User(ctx, idn.UserID)
	if err != nil {
		return SignInResult{}, err
	}
	return p.startSession(ctx, c, u, auth.SessionOptions{Transient: in.Remember != nil && !*in.Remember})
}

// loadSet returns userID's stored hash and when the password was set, or
// sqlb.ErrNoRows when the user has no password.
func (p *Plugin) loadSet(ctx context.Context, userID string) (string, time.Time, error) {
	var h string
	var at time.Time
	err := p.core.One(ctx, p.core.Select().Columns(sqlb.Bind(Hash, &h), sqlb.Bind(UpdatedAt, &at)).From(TablePassword).Where(sqlb.Eq(UserID, userID)).Limit(1))
	return h, at, err
}
