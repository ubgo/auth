package twofactor

import (
	"context"
	"errors"
	"net/http"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// Recovery-code storage. The default keeps a SHA-256 hash of each code and
// nothing else, so a database leak yields no usable code and nothing can show
// a code twice. StoreEncrypted is better-auth's default ("encrypted"): each
// code also keeps a sealed copy, so view-recovery-codes can show the unused
// ones again (better-auth's view-backup-codes). Sign-in still finds a code by
// its hash in both modes; the sealed copy is only ever read by view.

// RecoveryStorage is how recovery codes are kept.
//
//ds:def id=recoverystorage-p3w8vk2n owner=@khanakia stability=stable
type RecoveryStorage string

// The storage modes.
const (
	// StoreHashed keeps the SHA-256 hash only. The default: a leaked table
	// gives an attacker nothing to type.
	StoreHashed RecoveryStorage = "hashed"
	// StoreEncrypted also keeps each code sealed with AES-256-GCM under a key
	// derived from auth.WithSecret (KeyLabelRecoveryCodes), bound to the user
	// id. A leaked table alone still gives nothing; a leaked table AND the
	// secret give every unused code, which hashed storage never would.
	StoreEncrypted RecoveryStorage = "encrypted"
)

// RecoveryStorageValues is the canonical iteration order over storage modes.
var RecoveryStorageValues = []RecoveryStorage{StoreHashed, StoreEncrypted}

// KeyLabelRecoveryCodes is the label the sealing key of StoreEncrypted is
// derived under, from auth.WithSecret. Fixed, so a rotation of the secret
// (current first, previous after) keeps every sealed code opening; distinct
// from the TOTP secrets' auth.KeyLabelTwoFactor, so the two never share a key.
//
//ds:def id=keylabelrecoverycodes-b6m2xq8t owner=@khanakia stability=stable
const KeyLabelRecoveryCodes = "twofactor-recovery-codes"

// Errors of recovery-code storage.
var (
	// ErrBadRecoveryStorage: RecoveryCodeStorage got a value that is not one
	// of RecoveryStorageValues.
	ErrBadRecoveryStorage = errors.New("twofactor: RecoveryCodeStorage must be StoreHashed or StoreEncrypted")
	// ErrRecoveryStorageNeedsSecret: StoreEncrypted derives its key from
	// auth.WithSecret, and the app passed none.
	ErrRecoveryStorageNeedsSecret = errors.New("twofactor: RecoveryCodeStorage(StoreEncrypted) needs auth.WithSecret")
	// ErrRecoveryCodesHidden: an unused code of the user has no sealed copy
	// (it was made before StoreEncrypted was turned on), so the set cannot be
	// shown whole; recovery-codes makes a new one that can.
	ErrRecoveryCodesHidden = auth.NewError("twofactor.recovery_codes_hidden", http.StatusConflict, "These recovery codes cannot be shown again. Make a new set.")
)

// RecoveryCodeStorage chooses how recovery codes are kept; the default is
// StoreHashed. StoreEncrypted registers view-recovery-codes and needs
// auth.WithSecret (ErrRecoveryStorageNeedsSecret). It applies to codes made
// from then on: switching to it leaves the current codes viewable only after
// the user makes a new set, and switching back leaves the sealed copies in
// place until the codes are used or replaced.
func RecoveryCodeStorage(s RecoveryStorage) Option { return func(p *Plugin) { p.recoveryStore = s } }

// buildRecoveryRing settles the storage mode: nothing for StoreHashed; for
// StoreEncrypted, first match wins: WithSealer's Sealer, auth.WithSealer's,
// or the keys derived from every secret, current first.
func (p *Plugin) buildRecoveryRing(cfg *auth.Config) error {
	switch p.recoveryStore {
	case StoreHashed:
		return nil
	case StoreEncrypted:
		if s := firstSealer(p.sealer, cfg.Sealer()); s != nil {
			p.recoveryRing = s
			return nil
		}
		keys, err := cfg.DeriveKeys(KeyLabelRecoveryCodes)
		var ring *auth.KeyRing
		if err == nil {
			ring, err = auth.NewKeyRing(keys[0], keys[1:]...)
		}
		if err != nil {
			return ErrRecoveryStorageNeedsSecret
		}
		p.recoveryRing = auth.RingSealer(ring)
		return nil
	}
	return ErrBadRecoveryStorage
}

// sealRecovery is the stored sealed copy of code: "" under StoreHashed. A
// Sealer that fails fails the whole set rather than storing "" for a code,
// which would read as "this code cannot be shown".
func (p *Plugin) sealRecovery(ctx context.Context, code, userID string) (string, error) {
	if p.recoveryRing == nil {
		return "", nil
	}
	return p.recoveryRing.Seal(ctx, []byte(code), userID)
}

// ViewRecoveryCodes shows the signed-in user's unused recovery codes again,
// as they were handed out, under StoreEncrypted (better-auth's
// view-backup-codes). It needs a fresh sign-in, and the password under
// RequirePassword. Without StoreEncrypted the operation is not registered and
// the call fails.
func (p *Plugin) ViewRecoveryCodes(ctx context.Context, in PasswordRequest) (RecoveryCodes, error) {
	return p.view.Call(ctx, in)
}

// doViewRecoveryCodes opens every unused code of a confirmed factor. One
// without a sealed copy makes the whole answer ErrRecoveryCodesHidden: a
// partial list would look like the full set.
func (p *Plugin) doViewRecoveryCodes(ctx context.Context, c *auth.Call, in PasswordRequest) (RecoveryCodes, error) {
	if err := p.checkPassword(ctx, c.User.ID, in.Password, p.requirePassword); err != nil {
		return RecoveryCodes{}, err
	}
	row, err := p.load(ctx, c.User.ID)
	if err != nil {
		return RecoveryCodes{}, err
	}
	if row.confirmedAt == nil {
		return RecoveryCodes{}, ErrNotEnrolled
	}
	var sealed string
	sel := p.core.Select().Columns(sqlb.Bind(RecoverySealed, &sealed)).From(TableRecovery).
		Where(sqlb.Eq(RecoveryUser, c.User.ID), sqlb.IsNull(RecoveryUsed)).
		// The order the set was handed out in; the id breaks ties between
		// rows made before seq existed, so the answer is stable either way.
		Order(sqlb.OrderBy(RecoverySeq, sqlb.SortAsc), sqlb.OrderBy(RecoveryID, sqlb.SortAsc))
	codes := []string{}
	err = p.core.Each(ctx, sel, func() error {
		if sealed == "" {
			return ErrRecoveryCodesHidden
		}
		code, err := p.openSealed(ctx, p.recoveryRing, sealedRecoveryCode, sealed, c.User.ID)
		if err != nil {
			return err
		}
		codes = append(codes, string(code))
		return nil
	})
	if err != nil {
		return RecoveryCodes{}, err
	}
	return RecoveryCodes{Codes: codes}, nil
}
