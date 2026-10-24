package twofactor

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// Several second factors per user. The user's first factor stays in
// auth_two_factor (the primary row), which also holds the lockout that every
// factor of the user shares; each further code factor (the method the
// primary is not) is a row of auth_two_factor_method; security keys live in
// the WebAuthn plugin that stores them, reached through SecurityKeyStore. A
// user enrolled before factors could be combined has the primary row only,
// which is their one factor exactly as before.
//
// The primary row's method is MethodSecurityKey when the user's only
// factors are security keys: a placeholder without a secret, kept because
// the lockout and the recovery codes hang off it.

// MethodSecurityKey is a WebAuthn authenticator (a USB or NFC key, or the
// device's own platform authenticator) used as a second factor. It exists
// only with WithSecurityKeys. A security key is enrolled through
// security-key-register-begin and -finish, never through enroll, and is
// used at the challenge by sending a SecurityKeyResponse instead of a code.
//
//ds:def id=twofactor-methodsecuritykey-5mw8rq2k owner=@khanakia stability=stable
const MethodSecurityKey Method = "security_key"

// Operation ids of the multi-factor operations.
const (
	// EndpointSecurityKeyChallenge starts the WebAuthn assertion a pending
	// sign-in (or a signed-in step-up) answers with a security key.
	EndpointSecurityKeyChallenge auth.EndpointID = "twofactor.security-key-challenge"
	// EndpointSecurityKeyRegisterBegin and EndpointSecurityKeyRegisterFinish
	// add a security key as a second factor.
	EndpointSecurityKeyRegisterBegin  auth.EndpointID = "twofactor.security-key-register-begin"
	EndpointSecurityKeyRegisterFinish auth.EndpointID = "twofactor.security-key-register-finish"
	// EndpointRemoveFactor removes one factor; removing the last turns
	// two-factor sign-in off, as disable does.
	EndpointRemoveFactor auth.EndpointID = "twofactor.remove-factor"
)

const (
	pathSecurityKeyChallenge      = "/security-key/challenge"
	pathSecurityKeyRegisterBegin  = "/security-key/register-begin"
	pathSecurityKeyRegisterFinish = "/security-key/register-finish"
	pathRemoveFactor              = "/remove-factor"
)

// The table of a user's further code factors, one row per method.
const (
	//ds:def id=tablenamemethod-8vq3kd7w owner=@khanakia stability=stable
	TableNameMethod  = "auth_two_factor_method"
	TableAliasMethod = "tfm"
)

// Typed columns of auth_two_factor_method. The column names are the
// primary row's (ColUserID, ColMethod, ColSecret, ColIssuer, ColLastStep,
// ColConfirmedAt, ColCreatedAt): a further factor carries the same facts,
// without the lockout, which stays on the primary row.
var (
	TableMethod = sqlb.Table{Name: TableNameMethod, Alias: TableAliasMethod}

	MethodUserID      = sqlb.Col[string](TableMethod, ColUserID)
	MethodKind        = sqlb.Col[string](TableMethod, ColMethod)
	MethodSecret      = sqlb.Col[string](TableMethod, ColSecret)
	MethodIssuer      = sqlb.Col[string](TableMethod, ColIssuer)
	MethodLastStep    = sqlb.Col[int64](TableMethod, ColLastStep)
	MethodConfirmedAt = sqlb.Col[*time.Time](TableMethod, ColConfirmedAt)
	MethodCreatedAt   = sqlb.Col[time.Time](TableMethod, ColCreatedAt)
)

// Errors of the multi-factor operations.
var (
	// ErrFactorNotEnrolled: the request names a factor the user does not
	// have (a method never enrolled, or one removed). Not counted as a wrong
	// code: no secret was tried.
	ErrFactorNotEnrolled = auth.NewError("twofactor.factor_not_enrolled", http.StatusBadRequest, "This two-factor method is not set up for your account.")
	// ErrFactorNotFound: remove-factor named a security key id that is not
	// one of the user's keys, or a method the user does not have.
	ErrFactorNotFound = auth.NewError("twofactor.factor_not_found", http.StatusNotFound, "Not found.")
	// ErrProofRequired: adding or removing a factor while two-factor sign-in
	// is on needs a current factor (a code, a recovery code or a security
	// key), or a stolen fresh session could plant its own factor.
	ErrProofRequired = auth.NewError("twofactor.proof_required", http.StatusBadRequest, "Confirm with your current two-factor method first.")
	// ErrSecurityKeyInvalid answers an assertion that does not verify: a
	// wrong or replayed signature, a key of another user, a removed key, an
	// expired or spent ceremony. A SecurityKeyStore returns it (wrapped or
	// not) for every refusal; twofactor counts it as a wrong code.
	ErrSecurityKeyInvalid = auth.NewError("twofactor.security_key_invalid", http.StatusUnauthorized, "This security key could not be verified.")
)

// SecurityKeyChallenge starts a WebAuthn ceremony: the client passes Options
// to navigator.credentials.create or .get and sends Ceremony back with the
// authenticator's answer. Ceremony is a single-use handle.
type SecurityKeyChallenge struct {
	Ceremony string          `json:"ceremony"`
	Options  json.RawMessage `json:"options"`
}

// SecurityKeyResponse answers a security-key assertion: the ceremony from
// the challenge and the browser's PublicKeyCredential JSON.
type SecurityKeyResponse struct {
	Ceremony   string          `json:"ceremony"`
	Credential json.RawMessage `json:"credential"`
}

// SecurityKeyRegistration answers a registration ceremony; Name labels the
// key in the factor list.
type SecurityKeyRegistration struct {
	Ceremony   string          `json:"ceremony"`
	Credential json.RawMessage `json:"credential"`
	Name       string          `json:"name,omitempty"`
}

// SecurityKey is one registered security key, as the factor list shows it.
type SecurityKey struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt"`
	// AAGUID names the authenticator model when it disclosed one.
	AAGUID string `json:"aaguid,omitempty"`
	// Transports are how the key said it is reached ("usb", "nfc", …).
	Transports []string `json:"transports"`
}

// SecurityKeyStore is what twofactor needs from a WebAuthn plugin to offer
// security keys as a second factor; passkey.(*Plugin).SecurityKeys returns
// one. The plugin owns the protocol and the storage; twofactor owns the
// rules (which factors a user has, the lockout, recovery codes, promotion
// of the session). Every method is for one user, and must refuse a key or a
// ceremony of another user.
//
//ds:def id=twofactor-securitykeystore-2hq7wn4c owner=@khanakia stability=stable
type SecurityKeyStore interface {
	// BeginSecurityKeyRegistration starts registering a key for u;
	// attachment is "platform", "cross-platform" or "" for either.
	BeginSecurityKeyRegistration(ctx context.Context, u auth.User, attachment string) (SecurityKeyChallenge, error)
	// FinishSecurityKeyRegistration verifies the attestation of a ceremony
	// begun for userID and stores the key.
	FinishSecurityKeyRegistration(ctx context.Context, userID string, in SecurityKeyRegistration) (SecurityKey, error)
	// BeginSecurityKeyAssertion starts an assertion naming userID's keys.
	BeginSecurityKeyAssertion(ctx context.Context, userID string) (SecurityKeyChallenge, error)
	// FinishSecurityKeyAssertion is nil only for a valid assertion, by one
	// of userID's keys, of a ceremony begun for userID and not used before.
	// Every refusal is ErrSecurityKeyInvalid; any other error is a failure
	// of the server and is not counted against the user.
	FinishSecurityKeyAssertion(ctx context.Context, userID string, in SecurityKeyResponse) error
	// SecurityKeys lists userID's keys, oldest first; never nil.
	SecurityKeys(ctx context.Context, userID string) ([]SecurityKey, error)
	// RemoveSecurityKey deletes one of userID's keys; an id that is not
	// theirs is ErrFactorNotFound.
	RemoveSecurityKey(ctx context.Context, userID, id string) error
	// RemoveSecurityKeys deletes every key of userID.
	RemoveSecurityKeys(ctx context.Context, userID string) error
}

// WithSecurityKeys offers security keys as a second factor, stored by s
// (passkey's SecurityKeys; register the passkey plugin too). Methods and
// status then list MethodSecurityKey, and the security-key operations are
// registered. A nil s is refused (auth.ErrNilOption).
//
//ds:def id=twofactor-withsecuritykeys-6tn2vq8m owner=@khanakia stability=stable
func WithSecurityKeys(s SecurityKeyStore) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("twofactor.WithSecurityKeys", s) {
			return
		}
		p.keys = s
	}
}

// FactorProof is a current second factor of the user, asked for before a
// factor is added or removed while two-factor sign-in is on: a code (TOTP,
// delivered or recovery) or a security-key assertion. Method picks the
// factor the code is from; "" means the user's first code factor.
type FactorProof struct {
	Method      Method               `json:"method,omitempty"`
	Code        string               `json:"code,omitempty"`
	SecurityKey *SecurityKeyResponse `json:"securityKey,omitempty"`
}

// Factor is one of a user's confirmed second factors, as status lists them.
type Factor struct {
	Method Method `json:"method"`
	// ID names a security key (remove-factor takes it); "" for a code factor.
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	// Primary marks the factor a code without a method is checked against.
	Primary    bool       `json:"primary,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
}

// SecurityKeyRegisterBeginRequest is the input of
// security-key-register-begin: the authenticator kind (as passkey's), and the
// password when RequirePassword asks for it.
type SecurityKeyRegisterBeginRequest struct {
	AuthenticatorAttachment string     `json:"authenticatorAttachment,omitempty"`
	Password                auth.Token `json:"password,omitempty"`
}

// SecurityKeyRegisterFinishRequest completes the registration. Proof is
// required when two-factor sign-in is already on (ErrProofRequired).
type SecurityKeyRegisterFinishRequest struct {
	Ceremony   string          `json:"ceremony"`
	Credential json.RawMessage `json:"credential"`
	Name       string          `json:"name,omitempty"`
	Proof      *FactorProof    `json:"proof,omitempty"`
}

// SecurityKeyRegistered is the new key. When it was the user's first factor,
// two-factor sign-in is now on and RecoveryCodes are the user's codes, shown
// this once; otherwise RecoveryCodes is empty and the codes the user holds
// stay valid.
type SecurityKeyRegistered struct {
	Key           SecurityKey `json:"key"`
	RecoveryCodes []string    `json:"recoveryCodes"`
}

// RemoveFactorRequest names the factor to remove: a code method, or
// MethodSecurityKey with the key's ID. Proof is any current factor of the
// user (the one being removed included); Password is asked under
// RequirePassword.
type RemoveFactorRequest struct {
	Method   Method      `json:"method"`
	ID       string      `json:"id,omitempty"`
	Proof    FactorProof `json:"proof"`
	Password auth.Token  `json:"password,omitempty"`
}

// RemoveFactorResult reports whether two-factor sign-in is still on: false
// after the last factor went, which also deleted the recovery codes.
type RemoveFactorResult struct {
	Enabled bool `json:"enabled"`
}

// SecurityKeyChallengeFor starts a security-key assertion for the user of
// the pending or signed-in session in ctx; the answer goes to verify, check,
// reauthenticate or a proof as CodeRequest.SecurityKey.
func (p *Plugin) SecurityKeyChallengeFor(ctx context.Context) (SecurityKeyChallenge, error) {
	return p.skChallenge.Call(ctx, struct{}{})
}

// SecurityKeyRegisterBegin starts adding a security key as a second factor.
func (p *Plugin) SecurityKeyRegisterBegin(ctx context.Context, in SecurityKeyRegisterBeginRequest) (SecurityKeyChallenge, error) {
	return p.skRegBegin.Call(ctx, in)
}

// SecurityKeyRegisterFinish stores the key and, when it is the first factor,
// turns two-factor sign-in on.
func (p *Plugin) SecurityKeyRegisterFinish(ctx context.Context, in SecurityKeyRegisterFinishRequest) (SecurityKeyRegistered, error) {
	return p.skRegFinish.Call(ctx, in)
}

// RemoveFactor removes one factor of the signed-in user.
func (p *Plugin) RemoveFactor(ctx context.Context, in RemoveFactorRequest) (RemoveFactorResult, error) {
	return p.removeFactor.Call(ctx, in)
}

// defineFactorOps defines the multi-factor operations; New calls it.
func (p *Plugin) defineFactorOps() {
	p.skChallenge = auth.Define(auth.OpInfo{ID: EndpointSecurityKeyChallenge, Kind: auth.Mutation, Require: auth.SignedInOrPending, Path: pathSecurityKeyChallenge}, p.doSecurityKeyChallenge)
	p.skRegBegin = auth.Define(auth.OpInfo{ID: EndpointSecurityKeyRegisterBegin, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: pathSecurityKeyRegisterBegin}, p.doSecurityKeyRegisterBegin)
	p.skRegFinish = auth.Define(auth.OpInfo{ID: EndpointSecurityKeyRegisterFinish, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: pathSecurityKeyRegisterFinish}, p.doSecurityKeyRegisterFinish)
	p.removeFactor = auth.Define(auth.OpInfo{ID: EndpointRemoveFactor, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: pathRemoveFactor}, p.doRemoveFactor)
}

// methodMigration creates auth_two_factor_method. The key is (user, method):
// a user has at most one factor of each code method.
func (p *Plugin) methodMigration(t auth.SQLTypes) auth.Migration {
	return auth.Migration{Owner: PluginName, Name: "0006_two_factor_method_table", Statements: []string{
		"CREATE TABLE IF NOT EXISTS " + p.core.TableName(TableMethod) + " (" +
			ColUserID + " " + t.ID + " NOT NULL, " +
			ColMethod + " " + t.Key + " NOT NULL, " +
			ColSecret + " " + t.Text + " NOT NULL, " +
			ColIssuer + " " + t.Text + " NOT NULL, " +
			ColLastStep + " " + t.Int + " NOT NULL DEFAULT 0, " +
			ColConfirmedAt + " " + t.Timestamp + " NULL, " +
			ColCreatedAt + " " + t.Timestamp + " NOT NULL, " +
			"PRIMARY KEY (" + ColUserID + ", " + ColMethod + "))" + t.TableSuffix,
	}}
}

// extras reads userID's further code factors, confirmed or not, oldest
// first. Each carries the primary row's lockout, which is shared.
func (p *Plugin) extras(ctx context.Context, userID string, primary factorRow) ([]factorRow, error) {
	var r factorRow
	var created time.Time
	sel := p.core.Select().Columns(
		sqlb.Bind(MethodKind, &r.method), sqlb.Bind(MethodSecret, &r.secret), sqlb.Bind(MethodIssuer, &r.issuer),
		sqlb.Bind(MethodLastStep, &r.lastStep), sqlb.Bind(MethodConfirmedAt, &r.confirmedAt), sqlb.Bind(MethodCreatedAt, &created),
	).From(TableMethod).Where(sqlb.Eq(MethodUserID, userID)).Order(sqlb.OrderBy(MethodCreatedAt, sqlb.SortAsc), sqlb.OrderBy(MethodKind, sqlb.SortAsc))
	var out []factorRow
	err := p.core.Each(ctx, sel, func() error {
		x := r
		x.extra, x.createdAt = true, created
		x.failures, x.lockedUntil = primary.failures, primary.lockedUntil
		out = append(out, x)
		return nil
	})
	return out, err
}

// isCodeMethod reports whether m produces typed codes (TOTP or delivered).
func isCodeMethod(m Method) bool { return m == MethodTOTP || m == MethodDelivered }

// confirmedCodeFactors are userID's confirmed code factors, the primary
// first.
func (p *Plugin) confirmedCodeFactors(ctx context.Context, userID string, primary factorRow) ([]factorRow, error) {
	var out []factorRow
	if primary.confirmedAt != nil && isCodeMethod(Method(primary.method)) {
		out = append(out, primary)
	}
	ext, err := p.extras(ctx, userID, primary)
	if err != nil {
		return nil, err
	}
	for _, x := range ext {
		if x.confirmedAt != nil {
			out = append(out, x)
		}
	}
	return out, nil
}

// codeFactor is the confirmed code factor a code for method m is checked
// against: m's own, or with m empty the user's first code factor. ok is
// false when the user has none, which leaves only recovery codes; a named
// method the user lacks is ErrFactorNotEnrolled.
func (p *Plugin) codeFactor(ctx context.Context, userID string, primary factorRow, m Method) (factorRow, bool, error) {
	factors, err := p.confirmedCodeFactors(ctx, userID, primary)
	if err != nil {
		return factorRow{}, false, err
	}
	for _, f := range factors {
		if m == "" || Method(f.method) == m {
			return f, true, nil
		}
	}
	if m != "" {
		return factorRow{}, false, ErrFactorNotEnrolled
	}
	return factorRow{}, false, nil
}

// keyList lists userID's security keys; none without WithSecurityKeys.
func (p *Plugin) keyList(ctx context.Context, userID string) ([]SecurityKey, error) {
	if p.keys == nil {
		return []SecurityKey{}, nil
	}
	return p.keys.SecurityKeys(ctx, userID)
}

// passKey checks a security-key assertion for a confirmed factor's user.
// The lockout applies as to codes, and a refused assertion counts as a
// wrong code: a guess is a guess, whatever form it takes.
func (p *Plugin) passKey(ctx context.Context, userID string, row factorRow, in *SecurityKeyResponse) error {
	if p.keys == nil {
		return ErrMethodInvalid
	}
	if in == nil {
		return ErrSecurityKeyInvalid
	}
	if row.lockedUntil != nil && p.core.Now().Before(*row.lockedUntil) {
		return ErrLocked
	}
	keys, err := p.keyList(ctx, userID)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return ErrFactorNotEnrolled
	}
	err = p.keys.FinishSecurityKeyAssertion(ctx, userID, *in)
	if errors.Is(err, ErrSecurityKeyInvalid) {
		p.countFailure(ctx, userID, row.failures)
		return ErrSecurityKeyInvalid
	}
	if err != nil {
		return err
	}
	// A success clears the count, as a right code does.
	upd := sqlb.NewUpdate(p.core.Dialect()).Table(TableFactor).
		Set(sqlb.Set(FactorFailures, 0), sqlb.Set(FactorLockedUntil, (*time.Time)(nil))).
		Where(sqlb.Eq(FactorUserID, userID))
	_, err = p.core.Exec(ctx, upd)
	return err
}

// requireProof checks the proof a change of factors needs while two-factor
// sign-in is on; nil proof is ErrProofRequired.
func (p *Plugin) requireProof(ctx context.Context, userID string, proof *FactorProof) error {
	if proof == nil || (proof.Code == "" && proof.SecurityKey == nil) {
		return ErrProofRequired
	}
	return p.pass(ctx, userID, *proof)
}

// on reports whether userID has a confirmed factor and sign-in asks for it
// (not paused by DisableFor), with the primary row; the row is the zero
// value and found false when there is none.
func (p *Plugin) on(ctx context.Context, userID string) (factorRow, bool, error) {
	row, err := p.load(ctx, userID)
	if errors.Is(err, ErrNotEnrolled) {
		return factorRow{}, false, nil
	}
	if err != nil {
		return factorRow{}, false, err
	}
	if row.confirmedAt == nil {
		return row, false, nil
	}
	enabled, err := p.enabledFor(ctx, userID)
	return row, enabled, err
}

// enrollAdditional adds method beside the factors of a user whose
// two-factor sign-in is on: after a proof of a current factor, as an
// unconfirmed row that confirm turns on (or at once under
// SkipVerificationOnEnable).
func (p *Plugin) enrollAdditional(ctx context.Context, c *auth.Call, in EnrollRequest, method Method, issuer string, primary factorRow) (EnrollResult, error) {
	userID := c.User.ID
	if Method(primary.method) == method {
		return EnrollResult{}, ErrAlreadyEnabled
	}
	ext, err := p.extras(ctx, userID, primary)
	if err != nil {
		return EnrollResult{}, err
	}
	for _, x := range ext {
		if Method(x.method) == method && x.confirmedAt != nil {
			return EnrollResult{}, ErrAlreadyEnabled
		}
	}
	if err := p.requireProof(ctx, userID, in.Proof); err != nil {
		return EnrollResult{}, err
	}
	var secret []byte
	sealed := ""
	if method == MethodTOTP {
		secret = make([]byte, secretBytes)
		rand.Read(secret) // never fails since Go 1.24: it crashes the program instead
		if sealed, err = p.ring.Seal(ctx, secret, userID); err != nil {
			return EnrollResult{}, err
		}
	}
	d := p.core.Dialect()
	// One enrolment in progress at a time: confirm then knows which it is.
	if _, err := p.core.Exec(ctx, sqlb.NewDelete(d).From(TableMethod).Where(sqlb.Eq(MethodUserID, userID), sqlb.IsNull(MethodConfirmedAt))); err != nil {
		return EnrollResult{}, err
	}
	now := p.core.Now()
	var confirmed *time.Time
	if p.skipVerify {
		if method == MethodDelivered {
			if err := p.hasChannel(ctx, userID); err != nil {
				return EnrollResult{}, err
			}
		}
		confirmed = &now
	}
	ins := sqlb.NewInsert(d).Into(TableMethod).Row(
		sqlb.Set(MethodUserID, userID), sqlb.Set(MethodKind, string(method)), sqlb.Set(MethodSecret, sealed),
		sqlb.Set(MethodIssuer, issuer), sqlb.Set(MethodLastStep, int64(0)), sqlb.Set(MethodConfirmedAt, confirmed), sqlb.Set(MethodCreatedAt, now),
	)
	if _, err := p.core.Exec(ctx, ins); err != nil {
		return EnrollResult{}, err
	}
	out := EnrollResult{Method: method, Enabled: confirmed != nil}
	if method == MethodTOTP {
		out.Secret = secretEncoding.EncodeToString(secret)
		out.URL = otpauthURL(p.issuerFor(issuer), p.accountLabel(ctx, *c.User), secret, p.digits, p.period)
	}
	if confirmed == nil && method == MethodDelivered {
		if err := p.sendCode(ctx, userID); err != nil {
			return EnrollResult{}, err
		}
	}
	return out, nil
}

// confirmAdditional confirms the enrolment in progress beside a factor that
// is on. The recovery codes are not replaced: the user already holds them.
func (p *Plugin) confirmAdditional(ctx context.Context, userID string, primary factorRow, in CodeRequest) (RecoveryCodes, error) {
	ext, err := p.extras(ctx, userID, primary)
	if err != nil {
		return RecoveryCodes{}, err
	}
	for _, x := range ext {
		if x.confirmedAt != nil || (in.Method != "" && Method(x.method) != in.Method) {
			continue
		}
		if err := p.checkCurrent(ctx, userID, x, normalizeCode(in.Code)); err != nil {
			return RecoveryCodes{}, err
		}
		now := p.core.Now()
		upd := sqlb.NewUpdate(p.core.Dialect()).Table(TableMethod).Set(sqlb.Set(MethodConfirmedAt, &now)).
			Where(sqlb.Eq(MethodUserID, userID), sqlb.Eq(MethodKind, x.method))
		if _, err := p.core.Exec(ctx, upd); err != nil {
			return RecoveryCodes{}, err
		}
		return RecoveryCodes{Codes: []string{}}, nil
	}
	return RecoveryCodes{}, ErrAlreadyEnabled
}

// wipeFactors deletes every factor of userID but the recovery codes: the
// primary row, the further code factors, the security keys and the trusted
// devices. disable, Reset and a replacement of a paused factor use it.
func (p *Plugin) wipeFactors(ctx context.Context, userID string, primaryToo bool) error {
	d := p.core.Dialect()
	if primaryToo {
		if _, err := p.core.Exec(ctx, sqlb.NewDelete(d).From(TableFactor).Where(sqlb.Eq(FactorUserID, userID))); err != nil {
			return err
		}
	}
	if _, err := p.core.Exec(ctx, sqlb.NewDelete(d).From(TableMethod).Where(sqlb.Eq(MethodUserID, userID))); err != nil {
		return err
	}
	if p.keys != nil {
		if err := p.keys.RemoveSecurityKeys(ctx, userID); err != nil {
			return err
		}
	}
	return p.forgetDevices(ctx, userID)
}

// factorList is what status shows of a user whose factor is on: the code
// factors, then the security keys.
func (p *Plugin) factorList(ctx context.Context, userID string, primary factorRow) ([]Factor, error) {
	codes, err := p.confirmedCodeFactors(ctx, userID, primary)
	if err != nil {
		return nil, err
	}
	out := make([]Factor, 0, len(codes))
	for _, f := range codes {
		created := f.createdAt
		if created.IsZero() && f.confirmedAt != nil {
			created = *f.confirmedAt
		}
		out = append(out, Factor{Method: Method(f.method), Primary: !f.extra, CreatedAt: created})
	}
	keys, err := p.keyList(ctx, userID)
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		out = append(out, Factor{Method: MethodSecurityKey, ID: k.ID, Name: k.Name, CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt})
	}
	return out, nil
}

func (p *Plugin) doSecurityKeyChallenge(ctx context.Context, c *auth.Call, _ struct{}) (SecurityKeyChallenge, error) {
	row, err := p.load(ctx, c.User.ID)
	if err != nil {
		return SecurityKeyChallenge{}, err
	}
	if row.confirmedAt == nil {
		return SecurityKeyChallenge{}, ErrNotEnrolled
	}
	if row.lockedUntil != nil && p.core.Now().Before(*row.lockedUntil) {
		return SecurityKeyChallenge{}, ErrLocked
	}
	keys, err := p.keyList(ctx, c.User.ID)
	if err != nil {
		return SecurityKeyChallenge{}, err
	}
	if len(keys) == 0 {
		return SecurityKeyChallenge{}, ErrFactorNotEnrolled
	}
	return p.keys.BeginSecurityKeyAssertion(ctx, c.User.ID)
}

func (p *Plugin) doSecurityKeyRegisterBegin(ctx context.Context, c *auth.Call, in SecurityKeyRegisterBeginRequest) (SecurityKeyChallenge, error) {
	if err := p.checkPassword(ctx, c.User.ID, in.Password, p.requirePassword); err != nil {
		return SecurityKeyChallenge{}, err
	}
	return p.keys.BeginSecurityKeyRegistration(ctx, *c.User, in.AuthenticatorAttachment)
}

// doSecurityKeyRegisterFinish asks for the proof when two-factor sign-in is
// on, at finish rather than begin, so the decision reads the state the key
// is added to. A key that is the first factor turns sign-in's factor on.
func (p *Plugin) doSecurityKeyRegisterFinish(ctx context.Context, c *auth.Call, in SecurityKeyRegisterFinishRequest) (SecurityKeyRegistered, error) {
	userID := c.User.ID
	primary, enabled, err := p.on(ctx, userID)
	if err != nil {
		return SecurityKeyRegistered{}, err
	}
	if enabled {
		if err := p.requireProof(ctx, userID, in.Proof); err != nil {
			return SecurityKeyRegistered{}, err
		}
	} else if primary.confirmedAt != nil {
		// A paused factor is replaced, as enroll replaces it.
		if err := p.wipeFactors(ctx, userID, true); err != nil {
			return SecurityKeyRegistered{}, err
		}
	}
	key, err := p.keys.FinishSecurityKeyRegistration(ctx, userID, SecurityKeyRegistration{Ceremony: in.Ceremony, Credential: in.Credential, Name: in.Name})
	if err != nil {
		return SecurityKeyRegistered{}, err
	}
	if enabled {
		return SecurityKeyRegistered{Key: key, RecoveryCodes: []string{}}, nil
	}
	// The key is the first factor: a placeholder primary row carries the
	// lockout, and an enrolment in progress of a code method is dropped.
	d := p.core.Dialect()
	if _, err := p.core.Exec(ctx, sqlb.NewDelete(d).From(TableFactor).Where(sqlb.Eq(FactorUserID, userID))); err != nil {
		return SecurityKeyRegistered{}, err
	}
	now := p.core.Now()
	ins := sqlb.NewInsert(d).Into(TableFactor).Row(
		sqlb.Set(FactorUserID, userID), sqlb.Set(FactorSecret, ""), sqlb.Set(FactorLastStep, int64(0)),
		sqlb.Set(FactorFailures, 0), sqlb.Set(FactorCreatedAt, now), sqlb.Set(FactorConfirmedAt, &now),
		sqlb.Set(FactorMethod, string(MethodSecurityKey)), sqlb.Set(FactorIssuer, ""),
	)
	if _, err := p.core.Exec(ctx, ins); err != nil {
		return SecurityKeyRegistered{}, err
	}
	codes, err := p.turnOn(ctx, c)
	if err != nil {
		return SecurityKeyRegistered{}, err
	}
	return SecurityKeyRegistered{Key: key, RecoveryCodes: codes}, nil
}

// doRemoveFactor removes one factor after a proof. Removing the primary
// code factor promotes another factor into its row, because the lockout
// lives there; removing the last factor turns two-factor sign-in off.
func (p *Plugin) doRemoveFactor(ctx context.Context, c *auth.Call, in RemoveFactorRequest) (RemoveFactorResult, error) {
	userID := c.User.ID
	if err := p.checkPassword(ctx, userID, in.Password, p.requirePassword); err != nil {
		return RemoveFactorResult{}, err
	}
	if err := p.pass(ctx, userID, in.Proof); err != nil {
		return RemoveFactorResult{}, err
	}
	primary, err := p.load(ctx, userID)
	if err != nil {
		return RemoveFactorResult{}, err
	}
	d := p.core.Dialect()
	primaryGone := false
	switch {
	case in.Method == MethodSecurityKey && p.keys != nil:
		if in.ID == "" {
			return RemoveFactorResult{}, ErrFactorNotFound
		}
		if err := p.keys.RemoveSecurityKey(ctx, userID, in.ID); err != nil {
			return RemoveFactorResult{}, err
		}
	case isCodeMethod(in.Method) && Method(primary.method) == in.Method:
		primaryGone = true
	case isCodeMethod(in.Method):
		n, err := p.core.Exec(ctx, sqlb.NewDelete(d).From(TableMethod).Where(sqlb.Eq(MethodUserID, userID), sqlb.Eq(MethodKind, string(in.Method))))
		if err != nil {
			return RemoveFactorResult{}, err
		}
		if n == 0 {
			return RemoveFactorResult{}, ErrFactorNotFound
		}
	default:
		return RemoveFactorResult{}, ErrMethodInvalid
	}
	if !primaryGone && Method(primary.method) != MethodSecurityKey {
		return RemoveFactorResult{Enabled: true}, nil
	}
	return p.resettle(ctx, c, primary)
}

// resettle fills the primary row after its factor went (or, for a
// security-key primary, after a key went): with the oldest further code
// factor, else with a security-key placeholder while keys remain, else it
// turns two-factor sign-in off.
func (p *Plugin) resettle(ctx context.Context, c *auth.Call, primary factorRow) (RemoveFactorResult, error) {
	userID := c.User.ID
	d := p.core.Dialect()
	ext, err := p.extras(ctx, userID, primary)
	if err != nil {
		return RemoveFactorResult{}, err
	}
	for _, x := range ext {
		if x.confirmedAt == nil {
			continue
		}
		upd := sqlb.NewUpdate(d).Table(TableFactor).Set(
			sqlb.Set(FactorSecret, x.secret), sqlb.Set(FactorMethod, x.method), sqlb.Set(FactorIssuer, x.issuer),
			sqlb.Set(FactorLastStep, x.lastStep), sqlb.Set(FactorConfirmedAt, x.confirmedAt),
		).Where(sqlb.Eq(FactorUserID, userID))
		if _, err := p.core.Exec(ctx, upd); err != nil {
			return RemoveFactorResult{}, err
		}
		del := sqlb.NewDelete(d).From(TableMethod).Where(sqlb.Eq(MethodUserID, userID), sqlb.Eq(MethodKind, x.method))
		if _, err := p.core.Exec(ctx, del); err != nil {
			return RemoveFactorResult{}, err
		}
		return RemoveFactorResult{Enabled: true}, nil
	}
	keys, err := p.keyList(ctx, userID)
	if err != nil {
		return RemoveFactorResult{}, err
	}
	if len(keys) > 0 {
		if Method(primary.method) != MethodSecurityKey {
			upd := sqlb.NewUpdate(d).Table(TableFactor).Set(
				sqlb.Set(FactorSecret, ""), sqlb.Set(FactorMethod, string(MethodSecurityKey)), sqlb.Set(FactorIssuer, ""), sqlb.Set(FactorLastStep, int64(0)),
			).Where(sqlb.Eq(FactorUserID, userID))
			if _, err := p.core.Exec(ctx, upd); err != nil {
				return RemoveFactorResult{}, err
			}
		}
		return RemoveFactorResult{Enabled: true}, nil
	}
	if err := p.turnOff(ctx, c); err != nil {
		return RemoveFactorResult{}, err
	}
	return RemoveFactorResult{Enabled: false}, nil
}

// turnOff removes every factor, recovery code and trusted device of the
// call's user and clears two_factor_enabled: disable, and remove-factor of
// the last factor.
func (p *Plugin) turnOff(ctx context.Context, c *auth.Call) error {
	userID := c.User.ID
	if err := p.wipeFactors(ctx, userID, true); err != nil {
		return err
	}
	if _, err := p.core.Exec(ctx, sqlb.NewDelete(p.core.Dialect()).From(TableRecovery).Where(sqlb.Eq(RecoveryUser, userID))); err != nil {
		return err
	}
	if auth.RequestDevice(ctx) != "" {
		c.Effects.RememberDevice("", time.Time{})
	}
	return auth.SetUserColumn(ctx, c.Auth, PluginName, userID, Enabled, false)
}

// resetAll is Reset's body: every factor of userID, in the transaction ctx
// carries. It reports whether the user had a primary row.
func (p *Plugin) resetAll(ctx context.Context, userID string) (bool, error) {
	n, err := p.core.Exec(ctx, sqlb.NewDelete(p.core.Dialect()).From(TableFactor).Where(sqlb.Eq(FactorUserID, userID)))
	if err != nil {
		return false, err
	}
	return n > 0, p.wipeFactors(ctx, userID, false)
}
