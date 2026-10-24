package passkey

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/twofactor"
	"github.com/ubgo/sqlb"
)

// Security keys as a second factor. A security key is a WebAuthn credential
// that proves possession after another factor already proved who the user
// is, so it is kept apart from passkeys: its own table, its own ceremony
// purposes, and no sign-in operation reads it. A security key therefore
// never signs anyone in on its own, and a passkey never passes the second
// step. twofactor reaches these keys through the twofactor.SecurityKeyStore
// that SecurityKeys returns; the rules (which factors a user has, the
// lockout, recovery codes, promoting the session) stay in twofactor.

// The security-key table: one row per key, the same shape as auth_passkey.
const (
	//ds:def id=tablenamesecuritykey-4kt9wm2q owner=@khanakia stability=stable
	TableNameSecurityKey  = "auth_passkey_security_key"
	TableAliasSecurityKey = "pksk"
)

// Typed columns of auth_passkey_security_key, for an app that reads it.
var (
	TableSecurityKey        = sqlb.Table{Name: TableNameSecurityKey, Alias: TableAliasSecurityKey}
	SecurityKeyID           = sqlb.Col[string](TableSecurityKey, ColID)
	SecurityKeyUserID       = sqlb.Col[string](TableSecurityKey, ColUserID)
	SecurityKeyCredentialID = sqlb.Col[[]byte](TableSecurityKey, ColCredentialID)
	SecurityKeyCredential   = sqlb.Col[string](TableSecurityKey, ColCredential)
	SecurityKeyName         = sqlb.Col[string](TableSecurityKey, ColName)
	SecurityKeyCreatedAt    = sqlb.Col[time.Time](TableSecurityKey, ColCreatedAt)
	SecurityKeyLastUsedAt   = sqlb.Col[*time.Time](TableSecurityKey, ColLastUsedAt)
)

// Ceremony purposes of security keys, distinct from the passkey ones so a
// passkey ceremony can never finish as a security-key one or the reverse.
// The Identifier of both is the user id.
const (
	PurposeSecurityKeyRegister auth.Purpose = "passkey.security-key-register"
	PurposeSecurityKeyAssert   auth.Purpose = "passkey.security-key"
)

const (
	idPrefixSecurityKey = "pks"
	// indexSecurityKeyUserSuffix names the index on user_id.
	indexSecurityKeyUserSuffix = "_user_idx"
)

// securityKeySelection is what a second-factor key is asked for: not a
// discoverable credential (a key with little storage keeps it free) and no
// user verification, because the key proves possession only; the password
// or the sign-in method before it proved the rest. The attachment is the
// request's.
func securityKeySelection(attachment string) (protocol.AuthenticatorSelection, error) {
	sel := protocol.AuthenticatorSelection{
		ResidentKey:        protocol.ResidentKeyRequirementDiscouraged,
		RequireResidentKey: protocol.ResidentKeyNotRequired(),
		UserVerification:   protocol.VerificationDiscouraged,
	}
	switch attachment {
	case "":
	case AttachmentPlatform, AttachmentCrossPlatform:
		sel.AuthenticatorAttachment = protocol.AuthenticatorAttachment(attachment)
	default:
		return sel, ErrAttachmentInvalid
	}
	return sel, nil
}

// securityKeyMigration creates the security-key table and its user index,
// declared inside CREATE TABLE on MySQL, which has no CREATE INDEX IF NOT
// EXISTS.
func (p *Plugin) securityKeyMigration(engine string, t auth.SQLTypes) auth.Migration {
	table := p.core.TableName(TableSecurityKey)
	index := table + indexSecurityKeyUserSuffix
	create := "CREATE TABLE IF NOT EXISTS " + table + " (" +
		ColID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
		ColUserID + " " + t.ID + " NOT NULL, " +
		ColCredentialID + " " + t.Bytes + " NOT NULL UNIQUE, " +
		ColCredential + " " + t.Doc + " NOT NULL, " +
		ColName + " " + t.Text + " NOT NULL, " +
		ColCreatedAt + " " + t.Timestamp + " NOT NULL, " +
		ColLastUsedAt + " " + t.Timestamp + " NULL"
	st := []string{}
	if engine == auth.EngineMySQL {
		st = append(st, create+", INDEX "+index+" ("+ColUserID+"))"+t.TableSuffix)
	} else {
		st = append(st, create+")"+t.TableSuffix, "CREATE INDEX IF NOT EXISTS "+index+" ON "+table+" ("+ColUserID+")")
	}
	return auth.Migration{Owner: PluginName, Name: "0002_passkey_security_key", Statements: st}
}

// SecurityKeys is the store twofactor.WithSecurityKeys takes: this plugin's
// security keys as second factors. Register the plugin itself with
// auth.WithPlugins too; until auth.New has initialised it, every method is
// auth.ErrOperationNotWired.
//
//ds:def id=passkey-securitykeys-9wd3kq6n owner=@khanakia stability=stable
func (p *Plugin) SecurityKeys() twofactor.SecurityKeyStore { return securityKeys{p: p} }

// securityKeys implements twofactor.SecurityKeyStore over the plugin.
type securityKeys struct{ p *Plugin }

var _ twofactor.SecurityKeyStore = securityKeys{}

// ready is ErrOperationNotWired until the plugin's Init ran.
func (s securityKeys) ready() error {
	if s.p.core == nil || s.p.wa == nil {
		return auth.ErrOperationNotWired
	}
	return nil
}

// keyCredentials reads userID's security-key credentials, oldest first.
func (s securityKeys) keyCredentials(ctx context.Context, userID string) ([]webauthn.Credential, error) {
	var id, doc string
	sel := s.p.core.Select().Columns(sqlb.Bind(SecurityKeyID, &id), sqlb.Bind(SecurityKeyCredential, &doc)).From(TableSecurityKey).
		Where(sqlb.Eq(SecurityKeyUserID, userID)).Order(sqlb.OrderBy(SecurityKeyCreatedAt, sqlb.SortAsc))
	var out []webauthn.Credential
	err := s.p.core.Each(ctx, sel, func() error {
		var c webauthn.Credential
		if err := json.Unmarshal([]byte(doc), &c); err != nil {
			return fmt.Errorf("passkey: stored security key %s: %w", id, err)
		}
		out = append(out, c)
		return nil
	})
	return out, err
}

// BeginSecurityKeyRegistration starts registering a key for u. Every
// credential the user already has, passkeys included, is excluded, so one
// authenticator is not registered twice.
func (s securityKeys) BeginSecurityKeyRegistration(ctx context.Context, u auth.User, attachment string) (twofactor.SecurityKeyChallenge, error) {
	if err := s.ready(); err != nil {
		return twofactor.SecurityKeyChallenge{}, err
	}
	sel, err := securityKeySelection(attachment)
	if err != nil {
		return twofactor.SecurityKeyChallenge{}, err
	}
	keys, err := s.keyCredentials(ctx, u.ID)
	if err != nil {
		return twofactor.SecurityKeyChallenge{}, err
	}
	passkeys, err := s.p.credentials(ctx, u.ID)
	if err != nil {
		return twofactor.SecurityKeyChallenge{}, err
	}
	w := &waUser{u: u}
	if s.p.accountName != nil {
		w.name = s.p.accountName(ctx, s.p.core, u)
	}
	exclude := make([]protocol.CredentialDescriptor, 0, len(keys)+len(passkeys))
	for _, cr := range append(keys, passkeys...) {
		exclude = append(exclude, cr.Descriptor())
	}
	// BeginRegistration fails only on a relying-party configuration Init
	// already validated (webauthn.New) or on its challenge, which comes from
	// crypto/rand and cannot fail since Go 1.24, so its error is never set.
	creation, session, _ := s.p.wa.BeginRegistration(w, webauthn.WithExclusions(exclude), webauthn.WithAuthenticatorSelection(sel))
	b, err := begin(ctx, s.p, PurposeSecurityKeyRegister, u.ID, creation, session)
	return twofactor.SecurityKeyChallenge{Ceremony: b.Ceremony, Options: b.Options}, err
}

// FinishSecurityKeyRegistration verifies the attestation of a ceremony
// begun for userID and stores the key. A ceremony of another user, spent or
// expired, an attestation that does not verify, an authenticator the AAGUID
// policy refuses and a credential id already stored are all refused.
func (s securityKeys) FinishSecurityKeyRegistration(ctx context.Context, userID string, in twofactor.SecurityKeyRegistration) (twofactor.SecurityKey, error) {
	if err := s.ready(); err != nil {
		return twofactor.SecurityKey{}, err
	}
	v, session, err := s.p.finish(ctx, PurposeSecurityKeyRegister, in.Ceremony)
	if err != nil {
		return twofactor.SecurityKey{}, err
	}
	if v.Identifier != userID {
		return twofactor.SecurityKey{}, ErrCeremonyInvalid
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(in.Credential))
	if err != nil {
		return twofactor.SecurityKey{}, ErrPasskeyInvalid
	}
	u, err := s.p.core.User(ctx, userID)
	if err != nil {
		return twofactor.SecurityKey{}, err
	}
	cred, err := s.p.wa.CreateCredential(&waUser{u: u}, session, parsed)
	if err != nil {
		s.p.core.Logger().Info("passkey: security key registration refused", "error", err)
		return twofactor.SecurityKey{}, ErrPasskeyInvalid
	}
	if err := s.p.checkAuthenticator(ctx, cred); err != nil {
		return twofactor.SecurityKey{}, err
	}
	doc, _ := json.Marshal(cred) // a webauthn.Credential is bytes, strings and numbers
	id, err := s.p.core.NewID(idPrefixSecurityKey)
	if err != nil {
		return twofactor.SecurityKey{}, err
	}
	name := auth.TruncateRunes(in.Name, maxNameLength)
	now := s.p.core.Now()
	ins := sqlb.NewInsert(s.p.core.Dialect()).Into(TableSecurityKey).Row(
		sqlb.Set(SecurityKeyID, id), sqlb.Set(SecurityKeyUserID, userID), sqlb.Set(SecurityKeyCredentialID, cred.ID),
		sqlb.Set(SecurityKeyCredential, string(doc)), sqlb.Set(SecurityKeyName, name), sqlb.Set(SecurityKeyCreatedAt, now),
	)
	if _, err := s.p.core.Exec(ctx, ins); err != nil {
		if auth.IsUniqueViolation(err) {
			return twofactor.SecurityKey{}, ErrPasskeyInvalid
		}
		return twofactor.SecurityKey{}, err
	}
	return twofactor.SecurityKey{ID: id, Name: name, CreatedAt: now, AAGUID: aaguidString(cred.Authenticator.AAGUID), Transports: transports(*cred)}, nil
}

// BeginSecurityKeyAssertion starts an assertion that names userID's keys
// and only theirs; a user without a key is twofactor.ErrFactorNotEnrolled.
func (s securityKeys) BeginSecurityKeyAssertion(ctx context.Context, userID string) (twofactor.SecurityKeyChallenge, error) {
	if err := s.ready(); err != nil {
		return twofactor.SecurityKeyChallenge{}, err
	}
	w, err := s.keyUser(ctx, userID)
	if err != nil {
		return twofactor.SecurityKeyChallenge{}, err
	}
	if len(w.creds) == 0 {
		return twofactor.SecurityKeyChallenge{}, twofactor.ErrFactorNotEnrolled
	}
	// BeginLogin fails only on the configuration Init validated, on a user
	// with no credentials (refused just above) or on its crypto/rand
	// challenge, which cannot fail since Go 1.24, so its error is never set.
	assertion, session, _ := s.p.wa.BeginLogin(w, webauthn.WithUserVerification(protocol.VerificationDiscouraged))
	b, err := begin(ctx, s.p, PurposeSecurityKeyAssert, userID, assertion, session)
	return twofactor.SecurityKeyChallenge{Ceremony: b.Ceremony, Options: b.Options}, err
}

// FinishSecurityKeyAssertion verifies an assertion of a ceremony begun for
// userID against userID's keys. Every refusal is
// twofactor.ErrSecurityKeyInvalid: an unknown, spent or expired ceremony,
// one begun for another user, a credential that is not one of the user's
// keys (another user's key, a passkey, a removed key), a bad signature and
// a sign count that went backwards (a cloned key). The ceremony is single
// use, so a replayed assertion finds no ceremony.
func (s securityKeys) FinishSecurityKeyAssertion(ctx context.Context, userID string, in twofactor.SecurityKeyResponse) error {
	if err := s.ready(); err != nil {
		return err
	}
	v, session, err := s.p.finish(ctx, PurposeSecurityKeyAssert, in.Ceremony)
	if errors.Is(err, ErrCeremonyInvalid) {
		return twofactor.ErrSecurityKeyInvalid
	}
	if err != nil {
		return err
	}
	if v.Identifier != userID {
		return twofactor.ErrSecurityKeyInvalid
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(in.Credential))
	if err != nil {
		return twofactor.ErrSecurityKeyInvalid
	}
	w, err := s.keyUser(ctx, userID)
	if err != nil {
		return err
	}
	cred, err := s.p.wa.ValidateLogin(w, session, parsed)
	if err != nil {
		s.p.core.Logger().Info("passkey: security key assertion refused", "error", err)
		return twofactor.ErrSecurityKeyInvalid
	}
	if cred.Authenticator.CloneWarning {
		s.p.core.Logger().Warn("passkey: security key clone warning, refused", "user", userID)
		return twofactor.ErrSecurityKeyInvalid
	}
	doc, _ := json.Marshal(cred) // a webauthn.Credential is bytes, strings and numbers
	now := s.p.core.Now()
	upd := sqlb.NewUpdate(s.p.core.Dialect()).Table(TableSecurityKey).
		Set(sqlb.Set(SecurityKeyCredential, string(doc)), sqlb.Set(SecurityKeyLastUsedAt, &now)).
		Where(sqlb.Eq(SecurityKeyUserID, userID), sqlb.Eq(SecurityKeyCredentialID, cred.ID))
	_, err = s.p.core.Exec(ctx, upd)
	return err
}

// keyUser is userID with their security keys as the WebAuthn user.
func (s securityKeys) keyUser(ctx context.Context, userID string) (*waUser, error) {
	u, err := s.p.core.User(ctx, userID)
	if err != nil {
		return nil, err
	}
	creds, err := s.keyCredentials(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &waUser{u: u, creds: creds}, nil
}

// SecurityKeys lists userID's keys, oldest first; never nil.
func (s securityKeys) SecurityKeys(ctx context.Context, userID string) ([]twofactor.SecurityKey, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	var row twofactor.SecurityKey
	var doc string
	sel := s.p.core.Select().Columns(
		sqlb.Bind(SecurityKeyID, &row.ID), sqlb.Bind(SecurityKeyName, &row.Name), sqlb.Bind(SecurityKeyCreatedAt, &row.CreatedAt),
		sqlb.Bind(SecurityKeyLastUsedAt, &row.LastUsedAt), sqlb.Bind(SecurityKeyCredential, &doc),
	).From(TableSecurityKey).Where(sqlb.Eq(SecurityKeyUserID, userID)).Order(sqlb.OrderBy(SecurityKeyCreatedAt, sqlb.SortAsc))
	out := []twofactor.SecurityKey{}
	err := s.p.core.Each(ctx, sel, func() error {
		var c webauthn.Credential
		if err := json.Unmarshal([]byte(doc), &c); err != nil {
			return fmt.Errorf("passkey: stored security key %s: %w", row.ID, err)
		}
		k := row
		k.AAGUID = aaguidString(c.Authenticator.AAGUID)
		k.Transports = transports(c)
		out = append(out, k)
		return nil
	})
	return out, err
}

// RemoveSecurityKey deletes one of userID's keys; the user_id condition
// makes another user's id a miss, twofactor.ErrFactorNotFound like an
// unknown one.
func (s securityKeys) RemoveSecurityKey(ctx context.Context, userID, id string) error {
	if err := s.ready(); err != nil {
		return err
	}
	n, err := s.p.core.Exec(ctx, sqlb.NewDelete(s.p.core.Dialect()).From(TableSecurityKey).
		Where(sqlb.Eq(SecurityKeyID, id), sqlb.Eq(SecurityKeyUserID, userID)))
	if err != nil {
		return err
	}
	if n != 1 {
		return twofactor.ErrFactorNotFound
	}
	return nil
}

// RemoveSecurityKeys deletes every key of userID.
func (s securityKeys) RemoveSecurityKeys(ctx context.Context, userID string) error {
	if err := s.ready(); err != nil {
		return err
	}
	_, err := s.p.core.Exec(ctx, sqlb.NewDelete(s.p.core.Dialect()).From(TableSecurityKey).Where(sqlb.Eq(SecurityKeyUserID, userID)))
	return err
}

// transports are the ways a credential said its authenticator is reached.
func transports(c webauthn.Credential) []string {
	out := make([]string, 0, len(c.Transport))
	for _, t := range c.Transport {
		out = append(out, string(t))
	}
	return out
}
