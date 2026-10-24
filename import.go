package auth

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Bulk import: moving users and their identifiers in from another system,
// through the same core API every sign-up uses, so the uniqueness rules,
// the plugins' data hooks and the column extensions all apply, and nothing
// is written to a core table by hand.

// ImportIdentity is one identifier of an imported user.
type ImportIdentity struct {
	Kind IdentifierKindName
	// Value is what the other system held; it is normalized like typed
	// input.
	Value string
	// Verified imports the identity as proven. An import of addresses the
	// other system had verified sets it; an unverified identity is a claim
	// the user must still prove here.
	Verified bool
	// Primary makes it the primary identity of its kind; needs Verified.
	Primary bool
}

// ImportUser is one user to import.
//
//ds:def id=core-importuser-4hq7nx2m owner=@khanakia stability=stable
type ImportUser struct {
	// ID keeps the other system's id when it fits (opaque text, unique);
	// empty makes a new one. Keeping ids lets the app's own rows keep their
	// foreign keys.
	ID    string
	Name  string
	Image string
	// CreatedAt keeps the original sign-up time; zero means now.
	CreatedAt  time.Time
	Identities []ImportIdentity
}

// ImportResult is the outcome for one ImportUser, in input order.
type ImportResult struct {
	Index int
	// User is set when the row was imported.
	User User
	// Err is why it was not: ErrUserExists, ErrIdentityTaken,
	// ErrIdentifierInvalid, a hook's refusal, or a database error. The row
	// left nothing behind.
	Err error
}

// ErrUserExists refuses an import whose ID is already a user's.
var ErrUserExists = errors.New("auth: a user with this id exists")

// ErrImportFailed is returned by ImportUsers when at least one row failed;
// the results say which.
var ErrImportFailed = errors.New("auth: some users were not imported")

// ImportUsers creates the users and their identities, each user in a
// transaction of its own, so a row that fails leaves nothing behind and the
// rest still land. Every plugin's data hooks run, so the email plugin's
// primary-address column is filled as it would be at sign-up; no message is
// sent, since an import is not a sign-up (Quiet). It returns one result per
// input, in order, and ErrImportFailed when any row failed. Passwords and
// other credentials are imported through their plugin's own import, after
// this, with the user ids the results carry.
//
//ds:def id=core-importusers-9zk3wq6p owner=@khanakia stability=stable
func (a *Auth) ImportUsers(ctx context.Context, users []ImportUser) ([]ImportResult, error) {
	if a.db == nil {
		return nil, ErrNoDatabase
	}
	ctx = Quiet(ctx)
	out := make([]ImportResult, 0, len(users))
	failed := 0
	for i, in := range users {
		res := ImportResult{Index: i}
		res.Err = a.Tx(ctx, func(ctx context.Context, _ sqlbTx) error {
			u, err := a.CreateUser(ctx, NewUser{ID: in.ID, Name: in.Name, Image: in.Image, CreatedAt: in.CreatedAt})
			if err != nil {
				return err
			}
			for _, idn := range in.Identities {
				if _, err := a.CreateIdentity(ctx, NewIdentity{UserID: u.ID, Kind: idn.Kind, Raw: idn.Value, Verified: idn.Verified, Primary: idn.Primary}); err != nil {
					return fmt.Errorf("identity %s %q: %w", idn.Kind, idn.Value, err)
				}
			}
			res.User = u
			return nil
		})
		if res.Err != nil {
			failed++
		}
		out = append(out, res)
	}
	if failed > 0 {
		return out, fmt.Errorf("%w: %d of %d", ErrImportFailed, failed, len(users))
	}
	return out, nil
}

// quietKey marks a context whose deliveries are dropped.
type quietKey struct{}

// Quiet returns ctx with delivery switched off: Deliver records nothing and
// sends nothing for the rest of the request or transaction. It is for an
// import or a repair that creates identities without a person on the other
// end of the mail; a verify link sent during a migration of ten thousand
// accounts is ten thousand confused users.
//
//ds:def id=core-quiet-6tm4xr8k owner=@khanakia stability=stable
func Quiet(ctx context.Context) context.Context { return context.WithValue(ctx, quietKey{}, true) }

// isQuiet reports whether Quiet was applied to ctx.
func isQuiet(ctx context.Context) bool {
	q, _ := ctx.Value(quietKey{}).(bool)
	return q
}
