// Package ldap signs users in with a username and password checked against
// an LDAP directory (OpenLDAP, Active Directory, FreeIPA, lldap, 389-DS).
//
// The directory is the source of truth for the password: the plugin stores
// none. It reaches the directory only through the Directory interface; the
// default, Client, uses github.com/go-ldap/ldap with TLS required. On a first
// sign-in the directory account is linked to a user: the user who already
// holds the entry's verified email address, or a new user created from the
// entry's attributes. Links live in auth_ldap_account, keyed by a stable id
// from the entry, so a renamed DN or a changed address still reaches the
// same user.
//
// An unknown username and a wrong password answer the same error, after the
// same work: the Directory contract requires it and Client keeps it with a
// decoy bind.
package ldap

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/sqlb"
)

// PluginName is the plugin's permanent identity: its route prefix and its
// owner name in the migration ledger.
const PluginName = "ldap"

// EndpointSignIn is the sign-in operation's id, a stable wire name.
const EndpointSignIn auth.EndpointID = "ldap.sign-in"

const pathSignIn = "/sign-in"

// Limits.
const (
	// MaxUsernameLength bounds the username before it reaches the
	// directory; real login names are far shorter, and a long one is only
	// work for the directory's filter parser.
	MaxUsernameLength = 256
	// MaxPasswordLength bounds the password sent in the bind. Directories
	// cap theirs lower; 1024 bytes stops a request from shipping megabytes
	// to the directory per attempt.
	MaxPasswordLength = 1024
	// signInIPLimit attempts per IP per signInIPWindow, the password
	// plugin's numbers.
	signInIPLimit  = 20
	signInIPWindow = time.Minute
	// signInUserLimit attempts per username per signInUserWindow. Lower
	// than an IP's because a directory locks accounts on its own count
	// (Active Directory's lockout threshold is often 5 to 10): a guesser
	// would otherwise lock real people out of every system that uses the
	// directory, not only this app.
	signInUserLimit  = 5
	signInUserWindow = 15 * time.Minute
)

// Default entry attributes the profile is read from.
const (
	// DefaultEmailAttribute holds the address in inetOrgPerson and AD.
	DefaultEmailAttribute = "mail"
	// DefaultNameAttribute is the common name, present on every person.
	DefaultNameAttribute = "cn"
)

// The plugin's table: one row per directory account, linked to one user.
const (
	TableNameAccount  = "auth_ldap_account"
	TableAliasAccount = "lda"
	ColID             = "id"
	ColUserID         = "user_id"
	// ColSubject is the entry's stable id (AttributeMap.Subject, the DN by
	// default), unique: one directory account belongs to one user.
	ColSubject   = "subject"
	ColDN        = "dn"
	ColCreatedAt = "created_at"
	ColLastUsed  = "last_used_at"
)

// Typed columns, for an app that reads the table (reads are open; only the
// plugin writes it).
var (
	TableAccount     = sqlb.Table{Name: TableNameAccount, Alias: TableAliasAccount}
	AccountID        = sqlb.Col[string](TableAccount, ColID)
	AccountUserID    = sqlb.Col[string](TableAccount, ColUserID)
	AccountSubject   = sqlb.Col[string](TableAccount, ColSubject)
	AccountDN        = sqlb.Col[string](TableAccount, ColDN)
	AccountCreatedAt = sqlb.Col[time.Time](TableAccount, ColCreatedAt)
	AccountLastUsed  = sqlb.Col[time.Time](TableAccount, ColLastUsed)
)

const (
	idPrefix         = "lda"
	migrationAccount = "0001_account"
	indexUserSuffix  = "_user_idx"
)

// Errors the sign-in answers.
var (
	// ErrCredentialsInvalid is an unknown username, a wrong password, a
	// locked account or an entry the filter leaves out, all alike.
	ErrCredentialsInvalid = auth.NewError("ldap.credentials_invalid", http.StatusUnauthorized, "The username or password is incorrect.")
	// ErrDirectoryUnavailable is a directory that could not decide: down,
	// unreachable, or refusing the service account. The cause is logged.
	ErrDirectoryUnavailable = auth.NewError("ldap.directory_unavailable", http.StatusServiceUnavailable, "Sign-in is unavailable right now. Please try again later.")
	// ErrAccountExists is a directory account whose email belongs to an
	// existing user when the directory's emails are not trusted
	// (UntrustedEmail): linking would hand that user to whoever controls the
	// directory entry.
	ErrAccountExists = auth.NewError("ldap.account_exists", http.StatusConflict, "An account with this email already exists. Sign in to it first.")
	// ErrSignUpDisabled is a first sign-in under NoSignUp with no user to
	// link to.
	ErrSignUpDisabled = auth.NewError("ldap.sign_up_disabled", http.StatusForbidden, "This directory account has no account here.")
	// ErrProfileRefused is an entry MapProfile refused, or one without the
	// stable id the link needs. The cause is logged.
	ErrProfileRefused = auth.NewError("ldap.profile_refused", http.StatusForbidden, "This account may not sign in here.")
	// ErrSignInConflict is two first sign-ins of one directory account at
	// once; the second is asked to try again, when the first has linked it.
	ErrSignInConflict = auth.NewError("ldap.sign_in_conflict", http.StatusConflict, "Another sign-in for this account is in progress. Please try again.")
)

// ErrNoDirectory is auth.New's error for a plugin built without
// WithDirectory: it could never check a password.
var ErrNoDirectory = errors.New("ldap: no directory; pass ldap.WithDirectory(ldap.NewClient(...))")

// Profile is what a sign-in takes from a directory entry.
type Profile struct {
	// Subject is the entry's stable id, which links it to a user. Required.
	Subject string
	// Email is the user's address; empty when the entry has none.
	Email string
	// Name and Image are a new user's profile.
	Name  string
	Image string
}

// AttributeMap names the attributes a Profile is read from. A field left
// empty keeps its default.
type AttributeMap struct {
	// Subject is the stable id: empty means the DN, which changes when an
	// entry is renamed or moved; set "entryUUID" (OpenLDAP, lldap),
	// "objectGUID" (Active Directory) or "ipaUniqueID" (FreeIPA) to survive
	// that. A binary value is hex-encoded.
	Subject string
	// Email is DefaultEmailAttribute by default.
	Email string
	// Name is DefaultNameAttribute by default; "displayName" is common too.
	Name string
	// Image has no default; "jpegPhoto" is binary and not a URL, so map it
	// with MapProfile if at all.
	Image string
}

// Plugin is the LDAP sign-in method. Build it with New.
type Plugin struct {
	// optErrs collects what the options found while they ran, such as a
	// nil Directory (auth.ErrNilOption); see OptionErr.
	optErrs        auth.OptionErrors
	dir            Directory
	attrs          AttributeMap
	mapProfile     func(Entry) (Profile, error)
	noSignUp       bool
	untrustedEmail bool
	core           *auth.Auth

	signIn *auth.Op[SignInRequest, SignInResult]
}

// OptionErr is every error the options recorded; auth.New refuses to start
// while it is not nil (auth.OptionChecker).
func (p *Plugin) OptionErr() error { return p.optErrs.OptionErr() }

// Option configures the plugin; New applies them in order.
type Option func(*Plugin)

// WithDirectory is the directory passwords are checked against: a Client
// from NewClient, or any Directory. Required.
func WithDirectory(d Directory) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("ldap.WithDirectory", d) {
			return
		}
		p.dir = d
	}
}

// MapAttributes replaces the attribute names a Profile is read from; empty
// fields keep their defaults.
func MapAttributes(m AttributeMap) Option {
	return func(p *Plugin) {
		if m.Subject != "" {
			p.attrs.Subject = m.Subject
		}
		if m.Email != "" {
			p.attrs.Email = m.Email
		}
		if m.Name != "" {
			p.attrs.Name = m.Name
		}
		if m.Image != "" {
			p.attrs.Image = m.Image
		}
	}
}

// MapProfile replaces the attribute mapping with a function: compute a
// subject, join a given name and a surname, refuse an entry by returning an
// error (ErrProfileRefused is answered, the error is logged; an *auth.Error
// is answered as it is). It runs after the password was proven.
func MapProfile(fn func(Entry) (Profile, error)) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("ldap.MapProfile", fn) {
			return
		}
		p.mapProfile = fn
	}
}

// NoSignUp creates no users: a directory account signs in only when it is
// linked already, or its email matches a user's verified one.
func NoSignUp() Option { return func(p *Plugin) { p.noSignUp = true } }

// UntrustedEmail treats the directory's email addresses as unverified: they
// never link to an existing user (ErrAccountExists instead), and a new
// user's address is stored unverified. By default the directory is the
// organization's own record and its addresses are trusted, which is what
// lets a person who signed up with a password and later signs in through
// the directory keep one account.
func UntrustedEmail() Option { return func(p *Plugin) { p.untrustedEmail = true } }

var (
	_ auth.SignInMethod      = (*Plugin)(nil)
	_ auth.OperationProvider = (*Plugin)(nil)
	_ auth.TypedMigrator     = (*Plugin)(nil)
	_ auth.TableOwner        = (*Plugin)(nil)
	_ auth.UserTableOwner    = (*Plugin)(nil)
	_ auth.CredentialCounter = (*Plugin)(nil)
	_ auth.Validator         = (*Plugin)(nil)
	_ auth.Initializer       = (*Plugin)(nil)
	_ auth.RateLimiter       = (*Plugin)(nil)
)

// New builds the plugin. WithDirectory is required.
func New(opts ...Option) *Plugin {
	p := &Plugin{attrs: AttributeMap{Email: DefaultEmailAttribute, Name: DefaultNameAttribute}}
	for _, o := range opts {
		o(p)
	}
	p.signIn = auth.Define(auth.OpInfo{ID: EndpointSignIn, Kind: auth.Mutation, Require: auth.Public, Path: pathSignIn, SignIn: true}, p.doSignIn)
	return p
}

// Name returns PluginName.
func (p *Plugin) Name() string { return PluginName }

// SignsIn reports that a directory account is a way in.
func (p *Plugin) SignsIn() bool { return true }

// Tables declares auth_ldap_account, so auth.New refuses another owner.
func (p *Plugin) Tables() []sqlb.Table { return []sqlb.Table{TableAccount} }

// UserTables declares that account rows belong to the user in user_id, so
// DeleteUser removes them.
func (p *Plugin) UserTables() []auth.UserTable {
	return []auth.UserTable{{Table: TableAccount, Column: ColUserID}}
}

// Operations lists the sign-in.
func (p *Plugin) Operations() []auth.Operation { return []auth.Operation{p.signIn} }

// RateLimits bounds sign-in per IP and, lower, per username, so a guesser
// cannot trip the directory's own lockout for a real person.
func (p *Plugin) RateLimits() []auth.RateRule {
	return []auth.RateRule{
		{Match: EndpointSignIn, Key: auth.ByIP, Limit: signInIPLimit, Window: signInIPWindow},
		{Match: EndpointSignIn, Key: auth.ByIdentifier, Limit: signInUserLimit, Window: signInUserWindow},
	}
}

// Validate refuses a plugin without a directory.
func (p *Plugin) Validate(*auth.Config) error {
	if p.dir == nil {
		return ErrNoDirectory
	}
	return nil
}

// Init keeps the core for the table name and the clock.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	return nil
}

// TypedMigrations creates auth_ldap_account: subject is unique, user_id
// indexed. MySQL declares the index inside CREATE TABLE, having no CREATE
// INDEX IF NOT EXISTS.
func (p *Plugin) TypedMigrations(engine string, t auth.SQLTypes) ([]auth.Migration, error) {
	if err := auth.CheckEngine(engine); err != nil {
		return nil, err
	}
	table := p.core.TableName(TableAccount)
	indexUser := table + indexUserSuffix
	create := "CREATE TABLE IF NOT EXISTS " + table + " (" +
		ColID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
		ColUserID + " " + t.ID + " NOT NULL, " +
		ColSubject + " " + t.Key + " NOT NULL UNIQUE, " +
		ColDN + " " + t.Long + " NOT NULL, " +
		ColCreatedAt + " " + t.Timestamp + " NOT NULL, " +
		ColLastUsed + " " + t.Timestamp + " NOT NULL"
	var st []string
	if engine == auth.EngineMySQL {
		st = []string{create + ", INDEX " + indexUser + " (" + ColUserID + "))" + t.TableSuffix}
	} else {
		st = []string{create + ")" + t.TableSuffix, "CREATE INDEX IF NOT EXISTS " + indexUser + " ON " + table + " (" + ColUserID + ")"}
	}
	return []auth.Migration{{Owner: PluginName, Name: migrationAccount, Statements: st}}, nil
}

// SignInRequest is the login form.
type SignInRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// RateIdentifier counts attempts per username, folded as most directories
// compare login names, so case changes do not reset the limit.
func (r SignInRequest) RateIdentifier() string {
	return strings.ToLower(strings.TrimSpace(r.Username))
}

// SignInResult is the output of sign-in. Token is for Go callers and bearer
// transports, never encoded into JSON.
type SignInResult struct {
	User auth.UserView `json:"user"`
	// Created is true when this sign-in created the user.
	Created bool `json:"created"`
	// Linked is true when this sign-in linked the directory account to an
	// existing user by email.
	Linked               bool       `json:"linked"`
	SecondFactorRequired bool       `json:"secondFactorRequired"`
	Token                auth.Token `json:"-"`
}

// SignIn checks a username and password against the directory and signs
// the user in, the typed form of POST /ldap/sign-in.
func (p *Plugin) SignIn(ctx context.Context, username, password string) (SignInResult, error) {
	return p.signIn.Call(ctx, SignInRequest{Username: username, Password: password})
}

// doSignIn proves the password with the directory, then links or creates
// the user and starts a session. A directory password is one factor, so a
// user with two-factor gets a pending session.
func (p *Plugin) doSignIn(ctx context.Context, c *auth.Call, in SignInRequest) (SignInResult, error) {
	username := strings.TrimSpace(in.Username)
	// Refused before the directory sees them: an empty password would be
	// an anonymous bind, which succeeds. The answer depends on the input
	// alone, so it says nothing about who exists.
	if username == "" || in.Password == "" || len(username) > MaxUsernameLength || len(in.Password) > MaxPasswordLength || strings.ContainsRune(username, 0) {
		return SignInResult{}, ErrCredentialsInvalid
	}
	entry, err := p.dir.Authenticate(ctx, username, in.Password)
	switch {
	case errors.Is(err, ErrInvalidCredentials):
		return SignInResult{}, ErrCredentialsInvalid
	case errors.Is(err, ErrAmbiguousUser):
		c.Auth.Logger().Warn("ldap: username matched several entries; answered as a wrong password", "error", err)
		return SignInResult{}, ErrCredentialsInvalid
	case err != nil:
		c.Auth.Logger().Error("ldap: directory failed", "error", err)
		return SignInResult{}, ErrDirectoryUnavailable
	}
	prof, err := p.profile(c, entry)
	if err != nil {
		return SignInResult{}, err
	}
	out, err := p.resolve(ctx, c, entry, prof)
	if err != nil {
		return SignInResult{}, err
	}
	sess, tok, err := c.Auth.CreateSession(ctx, out.User.ID, c.Client)
	if err != nil {
		return SignInResult{}, err
	}
	c.Effects.IssueSessionOf(sess, tok)
	out.Token, out.SecondFactorRequired = tok, sess.SecondFactorPending
	return out, nil
}

// profile reads the entry through MapProfile or the attribute map. A
// subject is required: without one the account could not be found again.
func (p *Plugin) profile(c *auth.Call, e Entry) (Profile, error) {
	var prof Profile
	if p.mapProfile != nil {
		var err error
		if prof, err = p.mapProfile(e); err != nil {
			var ae *auth.Error
			if errors.As(err, &ae) {
				return Profile{}, err
			}
			c.Auth.Logger().Info("ldap: profile refused", "dn", e.DN, "error", err)
			return Profile{}, ErrProfileRefused
		}
	} else {
		prof = Profile{Subject: e.DN, Email: e.Get(p.attrs.Email), Name: e.Get(p.attrs.Name)}
		if p.attrs.Subject != "" {
			prof.Subject = e.Get(p.attrs.Subject)
		}
		if p.attrs.Image != "" {
			prof.Image = e.Get(p.attrs.Image)
		}
	}
	if prof.Subject == "" {
		c.Auth.Logger().Error("ldap: entry has no subject; set MapAttributes Subject to an attribute every entry has", "dn", e.DN)
		return Profile{}, ErrProfileRefused
	}
	if !utf8.ValidString(prof.Subject) {
		prof.Subject = hex.EncodeToString([]byte(prof.Subject))
	}
	return prof, nil
}

// account is one auth_ldap_account row.
type account struct {
	id, userID string
}

// resolve finds the user of a proven directory account. In order:
//
//  1. a linked account is its user's;
//  2. an email that matches a verified identity links to that user, when the
//     directory's emails are trusted (the default); untrusted, it is
//     ErrAccountExists;
//  3. otherwise a user is created, unless NoSignUp.
func (p *Plugin) resolve(ctx context.Context, c *auth.Call, e Entry, prof Profile) (SignInResult, error) {
	acc, err := p.accountBySubject(ctx, prof.Subject)
	switch {
	case err == nil:
		if err := p.touch(ctx, acc.id, e.DN); err != nil {
			return SignInResult{}, err
		}
		u, err := c.Auth.User(ctx, acc.userID)
		return SignInResult{User: auth.ViewOf(u)}, err
	case !errors.Is(err, sqlb.ErrNoRows):
		return SignInResult{}, err
	}
	hasEmail := prof.Email != "" && c.Auth.Config().HasIdentifier(email.KindEmail)
	if hasEmail {
		owner, err := c.Auth.FindIdentity(ctx, email.KindEmail, prof.Email, true)
		switch {
		case err == nil:
			if p.untrustedEmail {
				return SignInResult{}, ErrAccountExists
			}
			if err := p.createAccount(ctx, owner.UserID, prof.Subject, e.DN); err != nil {
				return SignInResult{}, err
			}
			u, err := c.Auth.User(ctx, owner.UserID)
			return SignInResult{User: auth.ViewOf(u), Linked: true}, err
		case errors.Is(err, auth.ErrIdentifierInvalid):
			// The directory holds an address the email plugin would not
			// accept; the user is created without it rather than refused.
			hasEmail = false
		case !errors.Is(err, auth.ErrIdentityNotFound):
			return SignInResult{}, err
		}
	}
	if p.noSignUp {
		return SignInResult{}, ErrSignUpDisabled
	}
	u, err := c.Auth.CreateUser(ctx, auth.NewUser{Name: prof.Name, Image: prof.Image})
	if err != nil {
		return SignInResult{}, err
	}
	if hasEmail {
		verified := !p.untrustedEmail
		if _, err := c.Auth.CreateIdentity(ctx, auth.NewIdentity{UserID: u.ID, Kind: email.KindEmail, Raw: prof.Email, Verified: verified, Primary: verified}); err != nil {
			return SignInResult{}, err
		}
	}
	if err := p.createAccount(ctx, u.ID, prof.Subject, e.DN); err != nil {
		return SignInResult{}, err
	}
	return SignInResult{User: auth.ViewOf(u), Created: true}, nil
}

func (p *Plugin) accountBySubject(ctx context.Context, subject string) (account, error) {
	var a account
	err := p.core.One(ctx, p.core.Select().Columns(sqlb.Bind(AccountID, &a.id), sqlb.Bind(AccountUserID, &a.userID)).
		From(TableAccount).Where(sqlb.Eq(AccountSubject, subject)).Limit(1))
	return a, err
}

// createAccount links subject to userID. A unique violation is a concurrent
// first sign-in of the same account that committed first.
func (p *Plugin) createAccount(ctx context.Context, userID, subject, dn string) error {
	id, err := p.core.NewID(idPrefix)
	if err != nil {
		return err
	}
	now := p.core.Now()
	ins := sqlb.NewInsert(p.core.Dialect()).Into(TableAccount).Row(
		sqlb.Set(AccountID, id), sqlb.Set(AccountUserID, userID), sqlb.Set(AccountSubject, subject),
		sqlb.Set(AccountDN, dn), sqlb.Set(AccountCreatedAt, now), sqlb.Set(AccountLastUsed, now),
	)
	if _, err := p.core.Exec(ctx, ins); err != nil {
		if auth.IsUniqueViolation(err) {
			return ErrSignInConflict
		}
		return fmt.Errorf("ldap: link account: %w", err)
	}
	return nil
}

// touch records the sign-in time and the entry's current DN, which a rename
// or a move changes while the subject stays.
func (p *Plugin) touch(ctx context.Context, id, dn string) error {
	upd := sqlb.NewUpdate(p.core.Dialect()).Table(TableAccount).
		Set(sqlb.Set(AccountLastUsed, p.core.Now()), sqlb.Set(AccountDN, dn)).Where(sqlb.Eq(AccountID, id))
	_, err := p.core.Exec(ctx, upd)
	return err
}

// SignInCredentials counts userID's linked directory accounts, leaving out
// exceptID, for the core's last-sign-in-method check.
func (p *Plugin) SignInCredentials(ctx context.Context, userID, exceptID string) (int, error) {
	n := 0
	var id string
	err := p.core.Each(ctx, p.core.Select().Columns(sqlb.Bind(AccountID, &id)).From(TableAccount).Where(sqlb.Eq(AccountUserID, userID)), func() error {
		if id != exceptID {
			n++
		}
		return nil
	})
	return n, err
}
