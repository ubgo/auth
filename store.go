package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ubgo/sqlb"
)

// NewUser is the input of CreateUser.
type NewUser struct {
	Name  string
	Image string
	// ID, when set, is the user's id instead of a generated one: an import
	// keeping another system's ids, or a plugin that must know the id before
	// the row exists. Opaque text; a taken id is ErrUserExists.
	ID string
	// CreatedAt, when set, is the user's creation time instead of now, for
	// an import keeping the original sign-up time.
	CreatedAt time.Time
}

// CreateUser inserts a user and runs the User create hooks, in the transaction
// of ctx if there is one.
func (a *Auth) CreateUser(ctx context.Context, in NewUser) (User, error) {
	id := in.ID
	if id == "" {
		var err error
		if id, err = a.ids(IDPrefixUser); err != nil {
			return User{}, err
		}
	}
	now := a.now()
	created := in.CreatedAt
	if created.IsZero() {
		created = now
	}
	u := User{ID: id, Name: in.Name, Image: in.Image, CreatedAt: created.UTC(), UpdatedAt: now}
	err := a.Tx(ctx, func(ctx context.Context, tx sqlbTx) error {
		if err := runHooks(ctx, a, tx, pickUser, stageBeforeCreate, nil, &u); err != nil {
			return err
		}
		q := sqlb.NewInsert(a.cfg.Dialect).Into(TableUser).Row(
			sqlb.Set(UserID, u.ID), sqlb.Set(UserName, u.Name), sqlb.Set(UserImage, u.Image),
			sqlb.Set(UserCreatedAt, u.CreatedAt), sqlb.Set(UserUpdatedAt, u.UpdatedAt),
		)
		if _, err := a.Exec(ctx, q); err != nil {
			if isUniqueViolation(err) {
				return ErrUserExists
			}
			return fmt.Errorf("auth: insert user: %w", err)
		}
		return runHooks(ctx, a, tx, pickUser, stageAfterCreate, nil, &u)
	})
	return u, err
}

// UserUpdate names the display fields to change; a nil field is kept.
type UserUpdate struct {
	Name  *string
	Image *string
}

// Profile limits. The name is shown back to other users, so it is bounded;
// the image is a URL the app will put in an <img>, so only https is taken.
const (
	MaxNameLength  = 100
	MaxImageLength = 2048
)

// ErrProfileInvalid refuses a name or image outside the limits.
var ErrProfileInvalid = NewError("auth.profile_invalid", http.StatusBadRequest, "Use a shorter name, and an image address that starts with https://.")

// UpdateUser changes a user's display fields and runs the User update hooks,
// in the transaction of ctx if there is one.
func (a *Auth) UpdateUser(ctx context.Context, id string, in UserUpdate) (User, error) {
	if in.Name != nil && utf8.RuneCountInString(*in.Name) > MaxNameLength {
		return User{}, ErrProfileInvalid
	}
	if in.Image != nil && *in.Image != "" && (len(*in.Image) > MaxImageLength || !strings.HasPrefix(*in.Image, "https://")) {
		return User{}, ErrProfileInvalid
	}
	var out User
	err := a.Tx(ctx, func(ctx context.Context, tx sqlbTx) error {
		old, err := a.User(ctx, id)
		if err != nil {
			return err
		}
		upd := old
		if in.Name != nil {
			upd.Name = strings.TrimSpace(*in.Name)
		}
		if in.Image != nil {
			upd.Image = *in.Image
		}
		upd.UpdatedAt = a.now()
		if err := runHooks(ctx, a, tx, pickUser, stageBeforeUpdate, &old, &upd); err != nil {
			return err
		}
		q := sqlb.NewUpdate(a.cfg.Dialect).Table(TableUser).
			Set(sqlb.Set(UserName, upd.Name), sqlb.Set(UserImage, upd.Image), sqlb.Set(UserUpdatedAt, upd.UpdatedAt)).
			Where(sqlb.Eq(UserID, id))
		if _, err := a.Exec(ctx, q); err != nil {
			return err
		}
		out = upd
		return runHooks(ctx, a, tx, pickUser, stageAfterUpdate, &old, &upd)
	})
	return out, err
}

// User returns the user with id, or ErrUserNotFound.
func (a *Auth) User(ctx context.Context, id string) (User, error) {
	var u User
	if err := a.loadUser(ctx, id, UserBindings(&u)); err != nil {
		return User{}, err
	}
	return u, nil
}

// DeleteUser removes a user and everything that belongs to it, in one
// transaction and in Go: there is no foreign key and no cascade (ADR-0002).
// The User BeforeDelete hooks run first, which is where an app removes its own
// rows that reference the user or refuses the deletion; then every registered
// user table (UserTables: the plugins' rows, the identities), the verification
// tokens and codes filed under the user or its identities, the sessions
// through the store and the SQL table, and last the user row. Stateless
// sessions end because the user row they load is gone. The user's
// SessionCache entries are evicted after the commit (EvictCachedSessions).
//
//ds:def id=core-deleteuser-6tq4nw8k owner=@khanakia stability=stable
func (a *Auth) DeleteUser(ctx context.Context, id string) error {
	return a.endAlways(ctx, func(ctx context.Context, m hookMode) error {
		return a.Tx(ctx, func(ctx context.Context, tx sqlbTx) error {
			u, err := a.User(ctx, id)
			if err != nil {
				return err
			}
			if err := runHooks(ctx, a, tx, pickUser, stageBeforeDelete, nil, &u); err != nil {
				return err
			}
			if err := a.fireUserSessionsEnded(ctx, tx, m, id, "", SessionEndUserDeleted); err != nil {
				return err
			}
			if err := a.deleteUserRows(ctx, id); err != nil {
				return err
			}
			a.EvictCachedSessions(ctx, id)
			q := sqlb.NewDelete(a.cfg.Dialect).From(TableUser).Where(sqlb.Eq(UserID, id))
			_, err = a.Exec(ctx, q)
			return err
		})
	})
}

// Normalize reduces raw to the stored form for kind, and validates it.
func (a *Auth) Normalize(kind IdentifierKindName, raw string) (string, error) {
	k, ok := a.cfg.Identifier(kind)
	if !ok {
		return "", fmt.Errorf("%w: kind %q is not registered", ErrIdentifierInvalid, kind)
	}
	v, err := k.Normalize(raw)
	if err != nil {
		return "", ErrIdentifierInvalid
	}
	if k.Validate != nil {
		if err := k.Validate(v); err != nil {
			return "", ErrIdentifierInvalid
		}
	}
	return v, nil
}

// DetectKind returns the first sign-in kind, in plugin order, whose normalizer
// and validator accept raw, with the normalized value. It is how one sign-in
// field takes an email address, a phone number or a handle. The built-in kinds
// do not overlap: a phone starts with "+", a handle has a letter and no "@".
func (a *Auth) DetectKind(raw string) (IdentifierKindName, string, error) {
	for _, k := range a.cfg.LoginKinds() {
		v, err := k.Normalize(raw)
		if err != nil {
			continue
		}
		if k.Validate != nil && k.Validate(v) != nil {
			continue
		}
		return k.Name, v, nil
	}
	return "", "", ErrIdentifierInvalid
}

// NewIdentity is the input of CreateIdentity.
//
//ds:def id=core-newidentity-bwmkquxj owner=@khanakia stability=stable
type NewIdentity struct {
	UserID string
	Kind   IdentifierKindName
	Raw    string
	// Verified creates the identity already verified, for a value a trusted
	// source vouched for, such as a provider that reports email_verified.
	Verified bool
	// Primary makes it the primary identity of its kind. Requires Verified,
	// or it is ignored until the identity is verified.
	Primary bool
	// ScopeID confines uniqueness to a tenant, for kinds ScopedByTenant.
	ScopeID *string
}

// CreateIdentity normalizes and stores an identity. A value the unique index
// refuses returns ErrIdentityTaken.
//
//ds:def id=core-createidentity-8pm7m3dt owner=@khanakia stability=stable
func (a *Auth) CreateIdentity(ctx context.Context, in NewIdentity) (Identity, error) {
	value, err := a.Normalize(in.Kind, in.Raw)
	if err != nil {
		return Identity{}, err
	}
	scope := in.ScopeID
	if scope == nil {
		if scope, err = a.scopeFor(ctx, in.Kind); err != nil {
			return Identity{}, err
		}
	}
	id, err := a.ids(IDPrefixIdentity)
	if err != nil {
		return Identity{}, err
	}
	now := a.now()
	idn := Identity{ID: id, UserID: in.UserID, Kind: in.Kind, Value: value, ValueRaw: in.Raw, ScopeID: scope, CreatedAt: now}
	if in.Verified {
		idn.VerifiedAt = &now
		idn.IsPrimary = in.Primary
	}
	if err := a.risk.checkSignUp(ctx, idn); err != nil {
		return Identity{}, err
	}
	err = a.Tx(ctx, func(ctx context.Context, tx sqlbTx) error {
		if err := runHooks(ctx, a, tx, pickIdentity, stageBeforeCreate, nil, &idn); err != nil {
			return err
		}
		if idn.IsPrimary {
			if err := a.clearPrimary(ctx, idn.UserID, idn.Kind); err != nil {
				return err
			}
		}
		q := sqlb.NewInsert(a.cfg.Dialect).Into(TableIdentity).Row(
			sqlb.Set(IdentityID, idn.ID), sqlb.Set(IdentityUserID, idn.UserID), sqlb.Set(IdentityKind, idn.Kind),
			sqlb.Set(IdentityValue, idn.Value), sqlb.Set(IdentityValueRaw, idn.ValueRaw),
			sqlb.Set(IdentityVerifiedAt, idn.VerifiedAt), sqlb.Set(IdentityIsPrimary, idn.IsPrimary),
			sqlb.Set(IdentityScopeID, idn.ScopeID), sqlb.Set(IdentityCreatedAt, idn.CreatedAt),
		)
		if _, err := a.Exec(ctx, q); err != nil {
			if isUniqueViolation(err) {
				return ErrIdentityTaken
			}
			return fmt.Errorf("auth: insert identity: %w", err)
		}
		return runHooks(ctx, a, tx, pickIdentity, stageAfterCreate, nil, &idn)
	})
	return idn, err
}

// FindIdentity returns the identity of kind with the value raw normalizes to,
// using the exact comparison the unique index serves.
//
// A verified row always wins. Without verifiedOnly, and only when no verified
// row exists, the oldest unverified row is returned. Why "verified first" is
// two queries and not an ORDER BY verified_at DESC: Postgres sorts NULL first
// in a descending order and MySQL and SQLite sort it last, so one ORDER BY
// would pick a different row on each engine — and the wrong one on Postgres
// is the squatter's.
//
//ds:def id=core-findidentity-xg5u92k6 owner=@khanakia stability=stable
func (a *Auth) FindIdentity(ctx context.Context, kind IdentifierKindName, raw string, verifiedOnly bool) (Identity, error) {
	value, err := a.Normalize(kind, raw)
	if err != nil {
		return Identity{}, err
	}
	where := []sqlb.Predicate{sqlb.Eq(IdentityKind, kind), sqlb.Eq(IdentityValue, value)}
	if p, ok, err := a.scopePredicate(ctx, kind); err != nil {
		return Identity{}, err
	} else if ok {
		where = append(where, p)
	}
	idn, err := a.oneIdentity(ctx, append(where, VerifiedIdentity())...)
	if err == nil || verifiedOnly || !errors.Is(err, ErrIdentityNotFound) {
		return idn, err
	}
	return a.oneIdentity(ctx, append(where, sqlb.IsNull(IdentityVerifiedAt))...)
}

// FindSignInIdentity resolves what a user typed into a sign-in field: it
// detects the kind among the sign-in kinds, then finds the identity as
// FindIdentity does. The kind is returned with it, so the caller can apply
// RequireVerified after checking the credential.
func (a *Auth) FindSignInIdentity(ctx context.Context, raw string) (Identity, IdentifierKind, error) {
	kind, _, err := a.DetectKind(raw)
	if err != nil {
		return Identity{}, IdentifierKind{}, err
	}
	k, _ := a.cfg.Identifier(kind)
	idn, err := a.FindIdentity(ctx, kind, raw, false)
	return idn, k, err
}

// IdentityByID returns the identity with id, or ErrIdentityNotFound. It does
// not check the owner; a caller acting for a user compares UserID itself.
func (a *Auth) IdentityByID(ctx context.Context, id string) (Identity, error) {
	return a.oneIdentity(ctx, sqlb.Eq(IdentityID, id))
}

func (a *Auth) oneIdentity(ctx context.Context, where ...sqlb.Predicate) (Identity, error) {
	var idn Identity
	q := a.Select().Columns(IdentityBindings(&idn)...).From(TableIdentity).
		Where(where...).Order(sqlb.OrderBy(IdentityCreatedAt, sqlb.SortAsc), sqlb.OrderBy(IdentityID, sqlb.SortAsc)).Limit(1)
	if err := a.One(ctx, q); err != nil {
		if errors.Is(err, sqlb.ErrNoRows) {
			return Identity{}, ErrIdentityNotFound
		}
		return Identity{}, err
	}
	return idn, nil
}

// Identities returns every identity of a user, verified or not, for a settings
// page that shows pending verifications to their own owner.
func (a *Auth) Identities(ctx context.Context, userID string) ([]Identity, error) {
	return a.listIdentities(ctx, sqlb.Eq(IdentityUserID, userID))
}

// VerifiedIdentities returns a user's verified identities of kind. It is the
// one way a plugin should match an identity to a person.
func (a *Auth) VerifiedIdentities(ctx context.Context, userID string, kind IdentifierKindName) ([]Identity, error) {
	return a.listIdentities(ctx, sqlb.Eq(IdentityUserID, userID), sqlb.Eq(IdentityKind, kind), VerifiedIdentity())
}

// listIdentities returns the matching identities oldest first, ties broken by
// id: MySQL returns rows with equal timestamps in no fixed order, and callers
// such as DeliverRecovery take the first one.
func (a *Auth) listIdentities(ctx context.Context, where ...sqlb.Predicate) ([]Identity, error) {
	var row Identity
	q := a.Select().Columns(IdentityBindings(&row)...).From(TableIdentity).
		Where(where...).Order(sqlb.OrderBy(IdentityCreatedAt, sqlb.SortAsc), sqlb.OrderBy(IdentityID, sqlb.SortAsc))
	var out []Identity
	err := a.Each(ctx, q, func() error { out = append(out, row); return nil })
	return out, err
}

// VerifyIdentity marks an identity verified. A value that another account has
// already verified returns ErrIdentityTaken and changes nothing.
func (a *Auth) VerifyIdentity(ctx context.Context, id string) (Identity, error) {
	var out Identity
	err := a.Tx(ctx, func(ctx context.Context, tx sqlbTx) error {
		old, err := a.IdentityByID(ctx, id)
		if err != nil {
			return err
		}
		if old.VerifiedAt != nil {
			out = old
			return nil
		}
		now := a.now()
		upd := old
		upd.VerifiedAt = &now
		if err := runHooks(ctx, a, tx, pickIdentity, stageBeforeUpdate, &old, &upd); err != nil {
			return err
		}
		q := sqlb.NewUpdate(a.cfg.Dialect).Table(TableIdentity).
			Set(sqlb.Set(IdentityVerifiedAt, upd.VerifiedAt)).Where(sqlb.Eq(IdentityID, id))
		if _, err := a.Exec(ctx, q); err != nil {
			if isUniqueViolation(err) {
				return ErrIdentityTaken
			}
			return fmt.Errorf("auth: verify identity: %w", err)
		}
		if err := runHooks(ctx, a, tx, pickIdentity, stageAfterUpdate, &old, &upd); err != nil {
			return err
		}
		out = upd
		return nil
	})
	return out, err
}

// SetPrimaryIdentity makes a verified identity the primary one of its kind.
func (a *Auth) SetPrimaryIdentity(ctx context.Context, userID, id string) (Identity, error) {
	var out Identity
	err := a.Tx(ctx, func(ctx context.Context, tx sqlbTx) error {
		// Only a missing row is ErrIdentityNotFound (IdentityByID's own
		// answer); a failed read is returned as it is.
		old, err := a.IdentityByID(ctx, id)
		if err != nil {
			return err
		}
		if old.UserID != userID {
			return ErrIdentityNotFound
		}
		if old.VerifiedAt == nil {
			return ErrNotVerified
		}
		if err := a.clearPrimary(ctx, userID, old.Kind); err != nil {
			return err
		}
		upd := old
		upd.IsPrimary = true
		if err := runHooks(ctx, a, tx, pickIdentity, stageBeforeUpdate, &old, &upd); err != nil {
			return err
		}
		q := sqlb.NewUpdate(a.cfg.Dialect).Table(TableIdentity).
			Set(sqlb.Set(IdentityIsPrimary, true)).Where(sqlb.Eq(IdentityID, id))
		if _, err := a.Exec(ctx, q); err != nil {
			return err
		}
		out = upd
		return runHooks(ctx, a, tx, pickIdentity, stageAfterUpdate, &old, &upd)
	})
	return out, err
}

func (a *Auth) clearPrimary(ctx context.Context, userID string, kind IdentifierKindName) error {
	q := sqlb.NewUpdate(a.cfg.Dialect).Table(TableIdentity).Set(sqlb.Set(IdentityIsPrimary, false)).
		Where(sqlb.Eq(IdentityUserID, userID), sqlb.Eq(IdentityKind, kind))
	_, err := a.Exec(ctx, q)
	return err
}

// DeleteIdentity removes one of a user's identities. It refuses to remove the
// last way into the account; see CheckRemovable.
func (a *Auth) DeleteIdentity(ctx context.Context, userID, id string) error {
	return a.Tx(ctx, func(ctx context.Context, tx sqlbTx) error {
		// IdentityByID answers ErrIdentityNotFound for no row; any other
		// failure is returned as it is, never read as "not found".
		row, err := a.IdentityByID(ctx, id)
		if err != nil {
			return err
		}
		if row.UserID != userID {
			return ErrIdentityNotFound
		}
		// Only a sign-in identity can be the last way in; removing a contact
		// address never strands anyone.
		if k, ok := a.cfg.Identifier(row.Kind); ok && k.CanLogin {
			if err := a.CheckRemovable(ctx, userID, id, ""); err != nil {
				return err
			}
		}
		if err := runHooks(ctx, a, tx, pickIdentity, stageBeforeDelete, nil, &row); err != nil {
			return err
		}
		q := sqlb.NewDelete(a.cfg.Dialect).From(TableIdentity).Where(sqlb.Eq(IdentityID, id))
		_, err = a.Exec(ctx, q)
		return err
	})
}

// IssueVerification stores a new single-use token for purpose and returns it.
// identifier names what the token is about; see Verification.Identifier.
//
//ds:def id=core-issueverification-ddz4te35 owner=@khanakia stability=stable
func (a *Auth) IssueVerification(ctx context.Context, purpose Purpose, identifier string, ttl time.Duration, meta string) (Token, error) {
	tok := NewToken()
	return tok, a.IssueVerificationToken(ctx, purpose, identifier, tok, ttl, meta)
}

// errEmptyToken refuses an empty token given to IssueVerificationToken.
var errEmptyToken = errors.New("auth: IssueVerificationToken needs a token")

// IssueVerificationToken stores tok, made by the caller, as a single-use
// token for purpose. The token is looked up by its hash alone, so it must be
// unguessable; the caller checks its strength (IssueVerification's are 256
// random bits). An empty token is refused; the SQL store also refuses a token
// equal to one already stored.
//
//ds:def id=core-issueverificationtoken-8kw3nq5d owner=@khanakia stability=stable
func (a *Auth) IssueVerificationToken(ctx context.Context, purpose Purpose, identifier string, tok Token, ttl time.Duration, meta string) error {
	if tok == "" {
		return errEmptyToken
	}
	id, err := a.ids(IDPrefixVerification)
	if err != nil {
		return err
	}
	now := a.now()
	v := Verification{ID: id, Identifier: identifier, Purpose: purpose, ExpiresAt: now.Add(ttl), Meta: meta, CreatedAt: now}
	return a.Tx(ctx, func(ctx context.Context, tx sqlbTx) error {
		if err := runHooks(ctx, a, tx, pickVerification, stageBeforeCreate, nil, &v); err != nil {
			return err
		}
		if err := a.verifications.Insert(ctx, v, HashToken(tok)); err != nil {
			return err
		}
		return runHooks(ctx, a, tx, pickVerification, stageAfterCreate, nil, &v)
	})
}

// ConsumeVerification spends a token of purpose and returns its row.
//
// Single use is the store's guarantee (see VerificationStore): the SQL store
// matches only a row whose consumed_at is null, a key-value store reads and
// deletes the record in one atomic step, so of two requests with one token
// exactly one continues.
//
// A wrong, used, expired or wrong-purpose token is ErrTokenInvalid, all alike.
//
//ds:def id=core-consumeverification-gp5t3mcx owner=@khanakia stability=stable
func (a *Auth) ConsumeVerification(ctx context.Context, purpose Purpose, tok Token) (Verification, error) {
	var out Verification
	err := a.Tx(ctx, func(ctx context.Context, _ sqlbTx) error {
		var err error
		out, err = a.verifications.Consume(ctx, purpose, HashToken(tok), a.now())
		return err
	})
	return out, err
}

// ConsumeAllVerifications spends every open token of purpose for identifier,
// such as every outstanding reset link once the password changed.
func (a *Auth) ConsumeAllVerifications(ctx context.Context, purpose Purpose, identifier string) error {
	return a.verifications.ConsumeAll(ctx, purpose, identifier, a.now())
}

// DeliveryTimeout bounds one message delivery. Delivery runs after the
// response, so without a bound a hung mail server would pile up goroutines.
//
//ds:def id=core-deliverytimeout-m93qwbsg owner=@khanakia stability=stable
const DeliveryTimeout = 30 * time.Second

// Deliver asks the plugin that owns the identity's kind to send m, after the
// transaction in ctx commits.
//
// The send runs in the background, detached from the request. Two reasons:
// a request that waited for a mail server would take visibly longer when an
// account exists, which is exactly the timing signal "forgot password" must
// not give; and a slow provider must not slow sign-up. A failure is logged —
// the data it refers to is committed, and the user can ask again. WaitDeliveries
// waits for every send in flight, for tests and for a clean shutdown. Under
// Quiet(ctx) nothing is sent and nil is returned: an import creates
// identities with nobody waiting for a mail. Under WithDeliveryOutbox the
// message is also written to the outbox in ctx's transaction, so a send the
// process never made is retried by SendOutbox; a failed write fails Deliver.
//
//ds:def id=core-deliver-nfr5jt99 owner=@khanakia stability=stable
func (a *Auth) Deliver(ctx context.Context, to Identity, m Message) error {
	d, ok := a.kindOwner[to.Kind].(Deliverer)
	if !ok {
		return fmt.Errorf("%w: kind %q", ErrNoDeliverer, to.Kind)
	}
	if isQuiet(ctx) {
		return nil
	}
	if m.Locale == "" {
		m.Locale = a.Locale(ctx)
	}
	outboxID := ""
	if a.outbox != nil {
		id, err := a.enqueue(ctx, to, m)
		if err != nil {
			return err
		}
		outboxID = id
	}
	a.AfterCommit(ctx, func(ctx context.Context) {
		a.deliveries.Add(1)
		a.background(context.WithoutCancel(ctx), func(ctx context.Context) {
			defer a.deliveries.Done()
			sendCtx, cancel := context.WithTimeout(ctx, DeliveryTimeout)
			err := d.Deliver(sendCtx, to, m)
			cancel()
			if err != nil {
				a.logger.Error("auth: delivery failed", "kind", string(to.Kind), "purpose", string(m.Purpose), "error", err)
			}
			if outboxID == "" {
				return
			}
			if err := a.outboxDone(ctx, outboxID, 1, err); err != nil {
				a.logger.Error("auth: delivery outbox", "id", outboxID, "error", err)
			}
		})
	})
	return nil
}

// VerificationSender is an identifier plugin that can send a fresh
// verification (a link or a code) for one of its unverified identities, on
// request from another plugin. The password plugin asks for one when a
// sign-in with the right password is refused because the address is not
// verified yet, so the person gets the mail they need instead of a dead end.
//
//ds:def id=core-verificationsender-5tq8mz3c owner=@khanakia stability=stable
type VerificationSender interface {
	SendVerification(ctx context.Context, to Identity) error
}

// SendVerification asks the plugin that owns to.Kind for a fresh verification
// of to. A kind whose plugin cannot is ErrNoVerificationSender; a plugin that
// chose not to (an option left off) returns nil and sends nothing, so the
// caller cannot tell the two apart by timing, which is the point: a refused
// sign-in must take the same time whether or not a mail went out.
//
//ds:def id=core-sendverification-8kd3rq7v owner=@khanakia stability=stable
func (a *Auth) SendVerification(ctx context.Context, to Identity) error {
	s, ok := a.kindOwner[to.Kind].(VerificationSender)
	if !ok {
		return fmt.Errorf("%w: kind %q", ErrNoVerificationSender, to.Kind)
	}
	return s.SendVerification(ctx, to)
}

// WaitDeliveries blocks until every message handed to Deliver has been sent or
// has failed.
func (a *Auth) WaitDeliveries() { a.deliveries.Wait() }

// CredentialCounter is a plugin that holds ways into an account that are not
// identities, such as linked social accounts. The core asks it before removing
// anything, so no plugin can strand a user.
type CredentialCounter interface {
	// SignInCredentials counts userID's credentials in this plugin, leaving
	// out the one named by exceptID when it is this plugin's.
	SignInCredentials(ctx context.Context, userID, exceptID string) (int, error)
}

// CheckRemovable returns ErrLastSignInMethod when removing the identity
// exceptIdentity (or the plugin credential exceptCredential) would leave userID
// with no way in: no other verified sign-in identity and no plugin credential.
// Either argument may be empty.
func (a *Auth) CheckRemovable(ctx context.Context, userID, exceptIdentity, exceptCredential string) error {
	n := 0
	for _, k := range a.cfg.LoginKinds() {
		ids, err := a.listIdentities(ctx, sqlb.Eq(IdentityUserID, userID), sqlb.Eq(IdentityKind, k.Name))
		if err != nil {
			return err
		}
		for _, idn := range ids {
			// An unverified identity counts only for a kind that signs in
			// without verification; a handle has no verification at all.
			if idn.ID != exceptIdentity && (idn.Verified() || !k.Verifiable || !k.RequireVerified) {
				n++
			}
		}
	}
	for _, p := range a.plugins {
		if cc, ok := p.(CredentialCounter); ok {
			c, err := cc.SignInCredentials(ctx, userID, exceptCredential)
			if err != nil {
				return err
			}
			n += c
		}
	}
	if n == 0 {
		return ErrLastSignInMethod
	}
	return nil
}

// DeliverRecovery sends m to the user's best recovery channel: the first
// recovery kind, in plugin order, for which the user has a verified identity,
// preferring the primary one. ErrNoRecoveryChannel when there is none.
func (a *Auth) DeliverRecovery(ctx context.Context, userID string, m Message) error {
	for _, k := range a.cfg.RecoveryKinds() {
		ids, err := a.VerifiedIdentities(ctx, userID, k.Name)
		if err != nil {
			return err
		}
		if len(ids) == 0 {
			continue
		}
		best := ids[0]
		for _, idn := range ids {
			if idn.IsPrimary {
				best = idn
			}
		}
		return a.Deliver(ctx, best, m)
	}
	return ErrNoRecoveryChannel
}
