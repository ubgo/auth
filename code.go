package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/ubgo/sqlb"
)

// One-time codes: short numeric codes a person types, sent by SMS or email.
//
// They cannot be verification tokens. A token has 256 bits and is looked up
// by its hash; a six-digit code has a million values, so a lookup by hash
// would let anyone guess somebody's code. A code is therefore always checked
// against one named subject (an identity, a number, an address), with an
// attempt counter, and spent on success.
const (
	TableNameCode = "auth_code"
	// TableAliasCode is reserved by the core.
	TableAliasCode = "oc"

	colCodeID        = "id"
	colCodeSubject   = "subject"
	colCodePurpose   = "purpose"
	colCodeHash      = "code_hash"
	colCodeAttempts  = "attempts"
	colCodeExpiresAt = "expires_at"
	colCodeCreatedAt = "created_at"
	// colCodeSealed holds a reusable generated code, sealed; NULL for every
	// other code. See CodeOptions.Reuse.
	colCodeSealed = "code_sealed"
)

// Code defaults and bounds.
const (
	// DefaultCodeLength is the number of digits of a code unless
	// WithCodeLength says otherwise.
	//ds:def id=defaultcodelength-3vn8hq2k owner=@khanakia stability=stable
	DefaultCodeLength = 6
	// CodeDigits is the default length under its earlier name.
	CodeDigits = DefaultCodeLength
	// MinCodeLength and MaxCodeLength bound WithCodeLength: four digits is the
	// shortest a code can be and still survive DefaultCodeMaxAttempts guesses
	// with a chance below one in two thousand; ten digits is the longest
	// anyone types from a message, and the longest that fits an int64 with
	// room to spare.
	//ds:def id=codelengthbounds-7xq2mt5r owner=@khanakia stability=stable
	MinCodeLength = 4
	MaxCodeLength = 10
	// DefaultCodeMaxAttempts wrong guesses spend a code. A six-digit code
	// accepts one value in a million; five guesses give a guesser one chance
	// in 200 000 per code, and the rate limits bound the codes.
	//ds:def id=defaultcodemaxattempts-qcfgc2jc owner=@khanakia stability=stable
	DefaultCodeMaxAttempts = 5
	idPrefixCode           = "otc"
	// codeBase is what each digit multiplies the number of code values by.
	codeBase = 10
)

// codeModulus returns 10^digits, the number of values a code of that length
// has.
func codeModulus(digits int) int64 {
	m := int64(1)
	for range digits {
		m *= codeBase
	}
	return m
}

var (
	codeID        = sqlb.Col[string](TableCode, colCodeID)
	codeSubject   = sqlb.Col[string](TableCode, colCodeSubject)
	codePurpose   = sqlb.Col[Purpose](TableCode, colCodePurpose)
	codeHashCol   = sqlb.Col[[]byte](TableCode, colCodeHash)
	codeAttempts  = sqlb.Col[int](TableCode, colCodeAttempts)
	codeExpiresAt = sqlb.Col[time.Time](TableCode, colCodeExpiresAt)
	codeCreatedAt = sqlb.Col[time.Time](TableCode, colCodeCreatedAt)
	codeSealed    = sqlb.Col[*string](TableCode, colCodeSealed)
)

// ErrCodeInvalid covers a wrong, spent, expired and exhausted code alike.
var ErrCodeInvalid = NewError("auth.code_invalid", http.StatusBadRequest, "This code is not right, or it has expired.")

// IssueCode replaces any open code of purpose for subject with a new one and
// returns it for delivery. subject names what the code is about and must be
// something only the sender can name: an identity id, or a normalized value.
//
//ds:def id=core-issuecode-ae462y8t owner=@khanakia stability=stable
func (a *Auth) IssueCode(ctx context.Context, purpose Purpose, subject string, ttl time.Duration) (string, error) {
	return a.IssueCodeWith(ctx, purpose, subject, ttl, CodeOptions{})
}

// KeyLabelCodes is the label of the keys a reusable code is derived or
// sealed with; see CodeOptions.Reuse.
const KeyLabelCodes = "codes"

// MaxGeneratedCodeLength is the longest code CodeOptions.Generate may
// return, in bytes: a code is typed or pasted by a person, and a sealed copy
// must stay a short column value.
//
//ds:def id=core-maxgeneratedcodelength-6wq3nk8d owner=@khanakia stability=stable
const MaxGeneratedCodeLength = 64

// CodeOptions changes how IssueCodeWith makes a code. The zero value is
// IssueCode: fresh random digits, replacing any open code.
//
//ds:def id=core-codeoptions-7hq2wn5k owner=@khanakia stability=stable
type CodeOptions struct {
	// Reuse returns the open code of purpose for subject again, with its
	// expiry moved to ttl from now, instead of replacing it. A code with no
	// attempts left (MaxAttempts) or past its expiry is replaced as usual,
	// and a resend never refills the attempt budget. It needs WithSecret
	// (ErrNoSecret otherwise).
	//
	// The core's digits are derived, never stored readable: HMAC-SHA256 of
	// the row id under the key derived from WithSecret under KeyLabelCodes,
	// reduced to CodeLength digits. A Generate code cannot be recomputed, so
	// it is also stored sealed (AES-256-GCM, bound to its row id) in
	// auth_code.code_sealed under the keys derived from every WithSecret
	// secret, current first. Either way, anyone holding the database AND the
	// secret can read every open code. A row whose code does not recompute
	// or open (issued without Reuse, or before every listed secret) gets a
	// fresh code.
	Reuse bool
	// MaxAttempts is the attempt budget Reuse checks the open code against;
	// 0 means DefaultCodeMaxAttempts. Use the value CheckCode is given.
	MaxAttempts int
	// Generate makes the code instead of the core's random digits. The
	// caller checks its strength; an empty code, or one longer than
	// MaxGeneratedCodeLength, is ErrBadOperation.
	Generate func(ctx context.Context) (string, error)
}

// IssueCodeWith is IssueCode with options; see CodeOptions.
//
//ds:def id=core-issuecodewith-3wk8nq2d owner=@khanakia stability=stable
func (a *Auth) IssueCodeWith(ctx context.Context, purpose Purpose, subject string, ttl time.Duration, o CodeOptions) (string, error) {
	var ring *KeyRing
	var key []byte
	if o.Reuse {
		keys, err := a.cfg.DeriveKeys(KeyLabelCodes)
		if err != nil {
			return "", err
		}
		if ring, err = ringOf("CodeOptions.Reuse", keys); err != nil {
			return "", err
		}
		key = keys[0]
		if code, ok, err := a.reuseCode(ctx, purpose, subject, ttl, o.MaxAttempts, key, ring); err != nil || ok {
			return code, err
		}
	}
	// The code is drawn before the id: a reader failure is then the
	// returned error, never crypto/rand's fatal one inside NewID. A derived
	// code comes from the id, so it is made after.
	var code string
	switch {
	case o.Generate != nil:
		var err error
		if code, err = o.Generate(ctx); err != nil {
			return "", err
		}
		if code == "" || len(code) > MaxGeneratedCodeLength {
			return "", fmt.Errorf("%w: a generated code must be 1 to %d bytes, got %d", ErrBadOperation, MaxGeneratedCodeLength, len(code))
		}
	case o.Reuse:
	default:
		n, err := rand.Int(rand.Reader, big.NewInt(codeModulus(a.cfg.CodeLength)))
		if err != nil {
			return "", fmt.Errorf("auth: read random code: %w", err)
		}
		code = fmt.Sprintf("%0*d", a.cfg.CodeLength, n.Int64())
	}
	id, err := a.ids(idPrefixCode)
	if err != nil {
		return "", err
	}
	// sealed is set only for a reusable generated code; every other row
	// leaves the column NULL.
	var sealed *string
	switch {
	case o.Reuse && o.Generate != nil:
		v := ring.Seal([]byte(code), id)
		sealed = &v
	case o.Reuse:
		code = derivedCode(key, id, a.cfg.CodeLength)
	}
	now := a.now()
	d := a.cfg.Dialect
	del := sqlb.NewDelete(d).From(TableCode).Where(sqlb.Eq(codeSubject, subject), sqlb.Eq(codePurpose, purpose))
	if _, err := a.Exec(ctx, del); err != nil {
		return "", err
	}
	ins := sqlb.NewInsert(d).Into(TableCode).Row(
		sqlb.Set(codeID, id), sqlb.Set(codeSubject, subject), sqlb.Set(codePurpose, purpose),
		sqlb.Set(codeHashCol, hashCode(id, code)), sqlb.Set(codeAttempts, 0),
		sqlb.Set(codeExpiresAt, now.Add(ttl)), sqlb.Set(codeCreatedAt, now), sqlb.Set(codeSealed, sealed),
	)
	if _, err := a.Exec(ctx, ins); err != nil {
		return "", fmt.Errorf("auth: insert code: %w", err)
	}
	return code, nil
}

// reuseCode returns the open code of purpose for subject with its expiry
// moved to ttl from now, and true; false when there is none with attempts
// left, or its code neither opens (a sealed copy) nor recomputes (a derived
// one) to the stored hash.
func (a *Auth) reuseCode(ctx context.Context, purpose Purpose, subject string, ttl time.Duration, maxAttempts int, key []byte, ring *KeyRing) (string, bool, error) {
	if maxAttempts <= 0 {
		maxAttempts = DefaultCodeMaxAttempts
	}
	now := a.now()
	var id string
	var hash []byte
	var sealed *string
	q := a.Select().Columns(sqlb.Bind(codeID, &id), sqlb.Bind(codeHashCol, &hash), sqlb.Bind(codeSealed, &sealed)).From(TableCode).
		Where(sqlb.Eq(codeSubject, subject), sqlb.Eq(codePurpose, purpose),
			sqlb.Greater(codeExpiresAt, now), sqlb.Less(codeAttempts, maxAttempts)).
		Limit(1)
	if err := a.One(ctx, q); err != nil {
		if errors.Is(err, sqlb.ErrNoRows) {
			return "", false, nil
		}
		return "", false, err
	}
	var code string
	if sealed != nil {
		plain, err := ring.Open(*sealed, id)
		if err != nil {
			return "", false, nil
		}
		code = string(plain)
	} else {
		code = derivedCode(key, id, a.cfg.CodeLength)
	}
	if subtle.ConstantTimeCompare(hashCode(id, code), hash) != 1 {
		return "", false, nil
	}
	upd := sqlb.NewUpdate(a.cfg.Dialect).Table(TableCode).Set(sqlb.Set(codeExpiresAt, now.Add(ttl))).Where(sqlb.Eq(codeID, id))
	if _, err := a.Exec(ctx, upd); err != nil {
		return "", false, err
	}
	return code, true, nil
}

// derivedCode is the reusable code of row id: HMAC-SHA256(key, id) as a
// number, modulo 10^digits. 256 bits reduced by at most 10^10 leaves no bias
// worth measuring.
func derivedCode(key []byte, id string, digits int) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(id))
	n := new(big.Int).SetBytes(m.Sum(nil))
	n.Mod(n, big.NewInt(codeModulus(digits)))
	return fmt.Sprintf("%0*d", digits, n.Int64())
}

// CheckCode spends the open code of purpose for subject when code matches.
// maxAttempts wrong guesses spend it (0 means DefaultCodeMaxAttempts).
//
// Every wrong guess is counted after the transaction in ctx ends (AfterTx):
// the failed operation rolls its transaction back, and a count that a failure
// rolls back is no count. The success path deletes the row, and a concurrent
// request that also matched finds nothing to delete, so a code works once.
//
//ds:def id=core-checkcode-qm6w8n6c owner=@khanakia stability=stable
func (a *Auth) CheckCode(ctx context.Context, purpose Purpose, subject, code string, maxAttempts int) error {
	id, err := a.matchCode(ctx, purpose, subject, code, maxAttempts)
	if err != nil {
		return err
	}
	del := sqlb.NewDelete(a.cfg.Dialect).From(TableCode).Where(sqlb.Eq(codeID, id))
	n, err := a.Exec(ctx, del)
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrCodeInvalid
	}
	return nil
}

// PeekCode is CheckCode without spending the code: a match leaves the row
// for a later CheckCode, so a form can tell the user their code is right
// before asking for the new password or address. A wrong guess still counts
// an attempt, so peeking cannot be used to guess faster than checking.
//
//ds:def id=core-peekcode-7rn2xk5q owner=@khanakia stability=stable
func (a *Auth) PeekCode(ctx context.Context, purpose Purpose, subject, code string, maxAttempts int) error {
	_, err := a.matchCode(ctx, purpose, subject, code, maxAttempts)
	return err
}

// matchCode is the lookup and comparison CheckCode and PeekCode share: it
// returns the matching row's id, or ErrCodeInvalid after counting the wrong
// attempt.
func (a *Auth) matchCode(ctx context.Context, purpose Purpose, subject, code string, maxAttempts int) (string, error) {
	if maxAttempts <= 0 {
		maxAttempts = DefaultCodeMaxAttempts
	}
	var id string
	var hash []byte
	q := a.Select().Columns(sqlb.Bind(codeID, &id), sqlb.Bind(codeHashCol, &hash)).From(TableCode).
		Where(sqlb.Eq(codeSubject, subject), sqlb.Eq(codePurpose, purpose),
			sqlb.Greater(codeExpiresAt, a.now()), sqlb.Less(codeAttempts, maxAttempts)).
		Limit(1)
	if err := a.One(ctx, q); err != nil {
		if errors.Is(err, sqlb.ErrNoRows) {
			return "", ErrCodeInvalid
		}
		return "", err
	}
	d := a.cfg.Dialect
	if subtle.ConstantTimeCompare(hashCode(id, code), hash) != 1 {
		inc := sqlb.NewUpdate(d).Table(TableCode).
			Set(sqlb.SetExpr(codeAttempts, sqlb.Add(codeAttempts, sqlb.Literal[int]("1")))).
			Where(sqlb.Eq(codeID, id))
		// The ctx AfterTx hands back carries no transaction (the one in
		// ctx has ended), so Exec writes on the database handle.
		a.AfterTx(ctx, func(ctx context.Context) {
			if _, err := a.Exec(ctx, inc); err != nil {
				a.logger.Error("auth: count failed code attempt", "error", err)
			}
		})
		return "", ErrCodeInvalid
	}
	return id, nil
}

// hashCode binds a code to its row, so equal codes in two rows hash apart.
func hashCode(id, code string) []byte {
	h := sha256.Sum256([]byte(id + ":" + code))
	return h[:]
}
