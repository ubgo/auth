package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/phone"
	"github.com/ubgo/auth/plugin/twofactor"
	"github.com/ubgo/auth/plugin/username"
)

// record is one user as every export format is reduced to it. A reader's
// whole job is to turn its format into records; the importer then has one
// code path, so a rule such as "an unverified address is a claim, not a
// proof" is written once rather than once per source.
type record struct {
	// ID is the other system's id, kept as the user id so the app's own
	// rows (orders, posts) keep their foreign keys. Empty makes a new one.
	ID        string
	Name      string
	Image     string
	CreatedAt time.Time
	Emails    []identifier
	Phones    []identifier
	// Username is an optional handle; it is imported verified, since a
	// handle is not something a person proves.
	Username string
	// PasswordHash is the other system's hash string, unchanged. Empty
	// means the user had no password (a social-only account) or the source
	// does not export hashes; the guide for that source says what the user
	// does then.
	PasswordHash string
	// PasswordNote explains an empty PasswordHash when the export carried
	// one in a format the plugin cannot verify, so the summary says so.
	PasswordNote string
	Accounts     []account
	// TOTPSecret is a base32 authenticator secret the other system exported
	// in the clear; most sources do not.
	TOTPSecret string
	// Admin grants the admin plugin's flag.
	Admin bool
	// Banned imports the other system's ban; BannedUntil is when it lifts,
	// zero for a permanent one. The ban ends the user's sessions (there are
	// none yet) and refuses their sign-in until it lifts, as a ban made by an
	// admin here would.
	Banned      bool
	BannedUntil time.Time
	// BanReason is stored with the ban; empty takes the admin plugin's
	// default.
	BanReason string
	// Skip is why the record is not imported at all (an anonymous user with
	// nothing to come back to, a soft-deleted row); empty imports it.
	Skip string
}

// identifier is one email address or phone number of a record.
type identifier struct {
	Value    string
	Verified bool
	Primary  bool
}

// account is one social account the other system had linked.
type account struct {
	Provider  string
	AccountID string
	Email     string
}

// reader turns one export format into records. Each source file implements
// one; main picks it by the -source flag.
type reader func(in input) ([]record, error)

// input is the set of files a source may need. Most need one; Supabase and
// Auth.js export related tables separately.
type input struct {
	Main       io.Reader
	Identities io.Reader
	Factors    io.Reader
}

// deps are the plugins the importer writes credentials through. Each is
// optional: a nil plugin skips that kind of credential and the summary says
// so, because an import that silently drops every password is the one that
// locks a user base out on launch day.
type deps struct {
	Password  *password.Plugin
	OAuth     *oauth.Plugin
	TwoFactor *twofactor.Plugin
	Admin     *admin.Plugin
}

// outcome is what happened to one record.
type outcome struct {
	Record record
	UserID string
	// Err is why the user was not imported; nothing was written for it.
	Err error
	// Notes are things that landed differently from the export: a password
	// not imported, a provider not configured. The user exists.
	Notes []string
}

// summary is the importer's report.
type summary struct {
	Imported int
	Failed   int
	Skipped  int
	Outcomes []outcome
}

// errNoHasher means a record carried a password hash but no password plugin
// was wired, so it could not be stored.
var errNoHasher = errors.New("no password plugin wired")

// importRecords moves the records in. Each record is one transaction: the
// user, its identities and every credential land together or not at all, so
// a failed account link never leaves a user who cannot sign in with what the
// export said they had. A record's failure is reported in its outcome and
// the rest continue, as a.ImportUsers does for a single row.
func importRecords(ctx context.Context, a *auth.Auth, d deps, recs []record, dryRun bool) summary {
	var s summary
	for _, r := range recs {
		o := outcome{Record: r}
		if r.Skip != "" {
			s.Skipped++
			s.Outcomes = append(s.Outcomes, o)
			continue
		}
		if dryRun {
			o.Notes = planNotes(r, d)
			s.Imported++
			s.Outcomes = append(s.Outcomes, o)
			continue
		}
		o.Err = a.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
			id, notes, err := importOne(ctx, a, d, r)
			o.UserID, o.Notes = id, notes
			return err
		})
		if o.Err != nil {
			o.UserID = ""
			s.Failed++
		} else {
			s.Imported++
		}
		s.Outcomes = append(s.Outcomes, o)
	}
	return s
}

// importOne writes one record inside the caller's transaction and returns
// the user id and the notes.
func importOne(ctx context.Context, a *auth.Auth, d deps, r record) (string, []string, error) {
	res, err := a.ImportUsers(ctx, []auth.ImportUser{toImportUser(r)})
	if err != nil {
		return "", nil, res[0].Err
	}
	id := res[0].User.ID
	notes, err := importCredentials(ctx, d, id, r)
	if err != nil {
		return "", nil, err
	}
	// The admin flag and a ban are not credentials: they are set the way
	// trusted code sets them for any app, from Go. A user who was both an
	// admin and banned fails here (admin.admin_target), as the plugin refuses
	// to ban an admin; the source's contradiction is the summary's to show.
	switch {
	case (r.Admin || r.Banned) && d.Admin == nil:
		notes = append(notes, "admin flag or ban not imported: no admin plugin wired")
	default:
		if r.Admin {
			if err := d.Admin.Grant(ctx, id); err != nil {
				return "", nil, fmt.Errorf("admin: %w", err)
			}
		}
		if r.Banned {
			if err := d.Admin.BanFor(ctx, id, r.BanReason, r.BannedUntil); err != nil {
				return "", nil, fmt.Errorf("ban: %w", err)
			}
		}
	}
	return id, notes, nil
}

// importCredentials stores what the user signs in with (password hash,
// linked accounts, authenticator secret), each through its plugin's import
// method, in the transaction that created the user. A provider the app does
// not offer is a note, not a failure: nothing could ever match that row. A
// hash the plugin cannot verify is a failure, so a botched export stops here
// and not at the user's first sign-in.
//
//ds:def id=import-credentials-4r8wn2kt
func importCredentials(ctx context.Context, d deps, id string, r record) ([]string, error) {
	var notes []string
	switch {
	case r.PasswordHash != "" && d.Password == nil:
		return nil, errNoHasher
	case r.PasswordHash != "":
		if err := d.Password.ImportHash(ctx, id, r.PasswordHash); err != nil {
			return nil, fmt.Errorf("password: %w", err)
		}
	case r.PasswordNote != "":
		notes = append(notes, "password not imported: "+r.PasswordNote)
	}
	for _, acc := range r.Accounts {
		if d.OAuth == nil {
			notes = append(notes, "account "+acc.Provider+" not imported: no oauth plugin wired")
			continue
		}
		err := d.OAuth.ImportAccount(ctx, oauth.ImportAccount{UserID: id, Provider: acc.Provider, ProviderAccountID: acc.AccountID, Email: acc.Email})
		if errors.Is(err, oauth.ErrProviderUnknown) {
			notes = append(notes, "account "+acc.Provider+" not imported: provider not configured")
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("account %s: %w", acc.Provider, err)
		}
	}
	if r.TOTPSecret != "" {
		if d.TwoFactor == nil {
			notes = append(notes, "two-factor not imported: no twofactor plugin wired")
		} else if err := d.TwoFactor.ImportTOTP(ctx, id, r.TOTPSecret); err != nil {
			return nil, fmt.Errorf("two-factor: %w", err)
		}
	}
	return notes, nil
}

// planNotes is what a dry run says about a record: the same notes a real
// import would add, without touching the database.
func planNotes(r record, d deps) []string {
	var notes []string
	if r.PasswordHash == "" && r.PasswordNote != "" {
		notes = append(notes, "password not imported: "+r.PasswordNote)
	}
	if len(r.Accounts) > 0 && d.OAuth == nil {
		notes = append(notes, "accounts not imported: no oauth plugin wired")
	}
	if r.TOTPSecret != "" && d.TwoFactor == nil {
		notes = append(notes, "two-factor not imported: no twofactor plugin wired")
	}
	if (r.Admin || r.Banned) && d.Admin == nil {
		notes = append(notes, "admin flag or ban not imported: no admin plugin wired")
	}
	return notes
}

// toImportUser maps a record onto the core's import shape. Exactly one
// identity per kind is primary: the record's first marked one, else the
// first verified one, because a primary must be verified.
func toImportUser(r record) auth.ImportUser {
	u := auth.ImportUser{ID: r.ID, Name: r.Name, Image: r.Image, CreatedAt: r.CreatedAt}
	u.Identities = append(u.Identities, identities(email.KindEmail, r.Emails)...)
	u.Identities = append(u.Identities, identities(phone.KindPhone, r.Phones)...)
	if r.Username != "" {
		u.Identities = append(u.Identities, auth.ImportIdentity{Kind: username.KindUsername, Value: r.Username, Verified: true, Primary: true})
	}
	return u
}

// identities converts one kind's list, choosing its primary.
func identities(kind auth.IdentifierKindName, ids []identifier) []auth.ImportIdentity {
	primary := -1
	for i, id := range ids {
		if id.Primary && id.Verified {
			primary = i
			break
		}
	}
	if primary < 0 {
		for i, id := range ids {
			if id.Verified {
				primary = i
				break
			}
		}
	}
	out := make([]auth.ImportIdentity, 0, len(ids))
	for i, id := range ids {
		out = append(out, auth.ImportIdentity{Kind: kind, Value: id.Value, Verified: id.Verified, Primary: i == primary})
	}
	return out
}

// label names a record in the summary: its first address, else its id.
func (r record) label() string {
	if len(r.Emails) > 0 {
		return r.Emails[0].Value
	}
	if len(r.Phones) > 0 {
		return r.Phones[0].Value
	}
	return r.ID
}

// report writes the summary the way the program prints it: counts first,
// then every record that needs a human's eye, in a stable order.
func (s summary) report(w io.Writer, dryRun bool) {
	verb := "imported"
	if dryRun {
		verb = "would import"
	}
	fmt.Fprintf(w, "%s %d user(s), %d failed, %d skipped\n", verb, s.Imported, s.Failed, s.Skipped)
	for _, o := range s.Outcomes {
		switch {
		case o.Record.Skip != "":
			fmt.Fprintf(w, "  skip   %s: %s\n", o.Record.label(), o.Record.Skip)
		case o.Err != nil:
			fmt.Fprintf(w, "  FAILED %s: %v\n", o.Record.label(), o.Err)
		case len(o.Notes) > 0:
			fmt.Fprintf(w, "  note   %s: %s\n", o.Record.label(), strings.Join(o.Notes, "; "))
		}
	}
}
