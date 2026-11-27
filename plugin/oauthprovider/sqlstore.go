package oauthprovider

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// sqlStore is the default Store: the plugin's tables, through the core's
// own statements (Auth.Exec, One, Each), so every call joins the transaction
// in ctx and a rolled-back request leaves nothing behind. Its statements are
// the ones the provider ran before the Store existed, moved here unchanged:
// single use and rotation are one UPDATE … WHERE … IS NULL each, judged by
// the database, and the re-reads that decide a reuse are locking reads on
// Postgres and MySQL (lockedRead).
type sqlStore struct{ p *Plugin }

// errStoreFmt wraps a database error with the store method that met it.
const errStoreFmt = "oauthprovider: %s: %w"

// bytesOrNull is b for a nullable hash column: nil (NULL) for no hash.
func bytesOrNull(b []byte) *[]byte {
	if b == nil {
		return nil
	}
	return &b
}

// Nullable views of the hash columns, for writes that may store NULL.
var (
	clientSecretNull = sqlb.Col[*[]byte](TableClient, ColSecretHash)
)

func (s sqlStore) a() *auth.Auth { return s.p.core }

func (s sqlStore) dialect() sqlb.Dialect { return s.p.core.Dialect() }

// notFound maps sqlb.ErrNoRows to ErrRecordNotFound.
func notFound(err error) error {
	if errors.Is(err, sqlb.ErrNoRows) {
		return ErrRecordNotFound
	}
	return err
}

// exists maps a unique violation to ErrRecordExists, keeping the database
// error inside so auth.IsUniqueViolation still holds.
func exists(op string, err error) error {
	if err != nil && auth.IsUniqueViolation(err) {
		return fmt.Errorf("oauthprovider: %s: %w: %w", op, ErrRecordExists, err)
	}
	return err
}

// clientBindings are every column of a client row.
func clientBindings(r *ClientRecord) []sqlb.Binding {
	return []sqlb.Binding{
		sqlb.Bind(ClientIDCol, &r.ID), sqlb.Bind(ClientSecret, &r.SecretHash), sqlb.Bind(ClientName, &r.Name),
		sqlb.Bind(ClientRedirs, &r.RedirectURIs), sqlb.Bind(ClientScopes, &r.Scopes), sqlb.Bind(ClientGrants, &r.GrantTypes),
		sqlb.Bind(ClientMethod, &r.AuthMethod), sqlb.Bind(ClientSkip, &r.SkipConsent), sqlb.Bind(ClientPKCE, &r.RequirePKCE),
		sqlb.Bind(ClientIntro, &r.IntrospectAny), sqlb.Bind(ClientOwner, &r.OwnerID), sqlb.Bind(ClientOff, &r.DisabledAt),
		sqlb.Bind(ClientURI, &r.ClientURI), sqlb.Bind(ClientLogo, &r.LogoURI), sqlb.Bind(ClientContact, &r.Contacts),
		sqlb.Bind(ClientTos, &r.TosURI), sqlb.Bind(ClientPolicy, &r.PolicyURI),
		sqlb.Bind(ClientCreated, &r.CreatedAt), sqlb.Bind(ClientUpdated, &r.UpdatedAt),
		sqlb.Bind(ClientPostLogout, &r.PostLogoutRedirectURIs), sqlb.Bind(ClientEndSession, &r.EndSession), sqlb.Bind(ClientJWKS, &r.JWKS),
		sqlb.Bind(ClientDiscovery, &r.Discovery), sqlb.Bind(ClientFetchedAt, &r.FetchedAt), sqlb.Bind(ClientSubject, &r.SubjectType),
		sqlb.Bind(ClientBackURI, &r.BackchannelLogoutURI), sqlb.Bind(ClientBackSess, &r.BackchannelLogoutSessionRequired),
		sqlb.Bind(ClientDPoP, &r.DPoPBound),
		sqlb.Bind(ClientAppType, &r.ApplicationType), sqlb.Bind(ClientCCScopes, &r.ClientCredentialsScopes), sqlb.Bind(ClientRefID, &r.ReferenceID),
		sqlb.Bind(ClientMeta, &r.Metadata), sqlb.Bind(ClientSecretExp, &r.SecretExpiresAt),
		sqlb.Bind(ClientCIMDExpires, &r.CIMDExpiresAt), sqlb.Bind(ClientCIMDETag, &r.CIMDETag), sqlb.Bind(ClientCIMDLastMod, &r.CIMDLastModified),
		sqlb.Bind(ClientSoftwareID, &r.SoftwareID), sqlb.Bind(ClientSoftwareVersion, &r.SoftwareVersion), sqlb.Bind(ClientSoftwareStatement, &r.SoftwareStatement),
		sqlb.Bind(ClientJWKSURI, &r.JWKSURI), sqlb.Bind(ClientSecretEnc, &r.SecretEncrypted),
	}
}

// clientAssignment is the SET of one updatable field from r.
func clientAssignment(f ClientField, r ClientRecord) (sqlb.Assignment, bool) {
	switch f {
	case ClientFieldSecretHash:
		return sqlb.Set(clientSecretNull, bytesOrNull(r.SecretHash)), true
	case ClientFieldSecretEncrypted:
		return sqlb.Set(ClientSecretEnc, r.SecretEncrypted), true
	case ClientFieldName:
		return sqlb.Set(ClientName, r.Name), true
	case ClientFieldRedirectURIs:
		return sqlb.Set(ClientRedirs, r.RedirectURIs), true
	case ClientFieldScopes:
		return sqlb.Set(ClientScopes, r.Scopes), true
	case ClientFieldGrantTypes:
		return sqlb.Set(ClientGrants, r.GrantTypes), true
	case ClientFieldAuthMethod:
		return sqlb.Set(ClientMethod, r.AuthMethod), true
	case ClientFieldSkipConsent:
		return sqlb.Set(ClientSkip, r.SkipConsent), true
	case ClientFieldRequirePKCE:
		return sqlb.Set(ClientPKCE, r.RequirePKCE), true
	case ClientFieldIntrospectAny:
		return sqlb.Set(ClientIntro, r.IntrospectAny), true
	case ClientFieldOwnerID:
		return sqlb.Set(ClientOwner, r.OwnerID), true
	case ClientFieldDisabledAt:
		return sqlb.Set(ClientOff, r.DisabledAt), true
	case ClientFieldClientURI:
		return sqlb.Set(ClientURI, r.ClientURI), true
	case ClientFieldLogoURI:
		return sqlb.Set(ClientLogo, r.LogoURI), true
	case ClientFieldContacts:
		return sqlb.Set(ClientContact, r.Contacts), true
	case ClientFieldTosURI:
		return sqlb.Set(ClientTos, r.TosURI), true
	case ClientFieldPolicyURI:
		return sqlb.Set(ClientPolicy, r.PolicyURI), true
	case ClientFieldUpdatedAt:
		return sqlb.Set(ClientUpdated, r.UpdatedAt), true
	case ClientFieldPostLogoutRedirectURIs:
		return sqlb.Set(ClientPostLogout, r.PostLogoutRedirectURIs), true
	case ClientFieldEndSession:
		return sqlb.Set(ClientEndSession, r.EndSession), true
	case ClientFieldJWKS:
		return sqlb.Set(ClientJWKS, r.JWKS), true
	case ClientFieldJWKSURI:
		return sqlb.Set(ClientJWKSURI, r.JWKSURI), true
	case ClientFieldFetchedAt:
		return sqlb.Set(ClientFetchedAt, r.FetchedAt), true
	case ClientFieldSubjectType:
		return sqlb.Set(ClientSubject, r.SubjectType), true
	case ClientFieldBackchannelLogoutURI:
		return sqlb.Set(ClientBackURI, r.BackchannelLogoutURI), true
	case ClientFieldBackchannelLogoutSessionRequired:
		return sqlb.Set(ClientBackSess, r.BackchannelLogoutSessionRequired), true
	case ClientFieldDPoPBound:
		return sqlb.Set(ClientDPoP, r.DPoPBound), true
	case ClientFieldApplicationType:
		return sqlb.Set(ClientAppType, r.ApplicationType), true
	case ClientFieldClientCredentialsScopes:
		return sqlb.Set(ClientCCScopes, r.ClientCredentialsScopes), true
	case ClientFieldReferenceID:
		return sqlb.Set(ClientRefID, r.ReferenceID), true
	case ClientFieldMetadata:
		return sqlb.Set(ClientMeta, r.Metadata), true
	case ClientFieldSecretExpiresAt:
		return sqlb.Set(ClientSecretExp, r.SecretExpiresAt), true
	case ClientFieldSoftwareID:
		return sqlb.Set(ClientSoftwareID, r.SoftwareID), true
	case ClientFieldSoftwareVersion:
		return sqlb.Set(ClientSoftwareVersion, r.SoftwareVersion), true
	case ClientFieldSoftwareStatement:
		return sqlb.Set(ClientSoftwareStatement, r.SoftwareStatement), true
	case ClientFieldCIMDExpiresAt:
		return sqlb.Set(ClientCIMDExpires, r.CIMDExpiresAt), true
	case ClientFieldCIMDETag:
		return sqlb.Set(ClientCIMDETag, r.CIMDETag), true
	case ClientFieldCIMDLastModified:
		return sqlb.Set(ClientCIMDLastMod, r.CIMDLastModified), true
	}
	return sqlb.Assignment{}, false
}

// clientWhere is the condition of a ClientFilter.
func clientWhere(f ClientFilter) []sqlb.Predicate {
	var where []sqlb.Predicate
	if f.OwnerID != nil {
		where = append(where, sqlb.Eq(ClientOwner, f.OwnerID))
	}
	if f.ReferenceID != nil {
		where = append(where, sqlb.Eq(ClientRefID, f.ReferenceID))
	}
	return where
}

// Client implements Store.
func (s sqlStore) Client(ctx context.Context, id string) (ClientRecord, error) {
	var r ClientRecord
	err := s.a().One(ctx, s.a().Select().Columns(clientBindings(&r)...).From(TableClient).Where(sqlb.Eq(ClientIDCol, id)))
	return r, notFound(err)
}

// InsertClient implements Store.
func (s sqlStore) InsertClient(ctx context.Context, r ClientRecord) error {
	_, err := s.a().Exec(ctx, sqlb.NewInsert(s.dialect()).Into(TableClient).Row(
		sqlb.Set(ClientIDCol, r.ID), sqlb.Set(clientSecretNull, bytesOrNull(r.SecretHash)), sqlb.Set(ClientSecretEnc, r.SecretEncrypted), sqlb.Set(ClientName, r.Name),
		sqlb.Set(ClientRedirs, r.RedirectURIs), sqlb.Set(ClientScopes, r.Scopes),
		sqlb.Set(ClientGrants, r.GrantTypes), sqlb.Set(ClientMethod, r.AuthMethod),
		sqlb.Set(ClientSkip, r.SkipConsent), sqlb.Set(ClientPKCE, r.RequirePKCE), sqlb.Set(ClientIntro, r.IntrospectAny),
		sqlb.Set(ClientOwner, r.OwnerID), sqlb.Set(ClientOff, r.DisabledAt), sqlb.Set(ClientURI, r.ClientURI), sqlb.Set(ClientLogo, r.LogoURI),
		sqlb.Set(ClientContact, r.Contacts), sqlb.Set(ClientTos, r.TosURI),
		sqlb.Set(ClientPolicy, r.PolicyURI), sqlb.Set(ClientCreated, r.CreatedAt), sqlb.Set(ClientUpdated, r.UpdatedAt),
		sqlb.Set(ClientPostLogout, r.PostLogoutRedirectURIs),
		sqlb.Set(ClientEndSession, r.EndSession), sqlb.Set(ClientJWKS, r.JWKS), sqlb.Set(ClientJWKSURI, r.JWKSURI),
		sqlb.Set(ClientDiscovery, r.Discovery), sqlb.Set(ClientFetchedAt, r.FetchedAt),
		sqlb.Set(ClientSubject, r.SubjectType),
		sqlb.Set(ClientBackURI, r.BackchannelLogoutURI), sqlb.Set(ClientBackSess, r.BackchannelLogoutSessionRequired),
		sqlb.Set(ClientDPoP, r.DPoPBound),
		sqlb.Set(ClientAppType, r.ApplicationType), sqlb.Set(ClientCCScopes, r.ClientCredentialsScopes), sqlb.Set(ClientRefID, r.ReferenceID),
		sqlb.Set(ClientMeta, r.Metadata), sqlb.Set(ClientSecretExp, r.SecretExpiresAt),
		sqlb.Set(ClientSoftwareID, r.SoftwareID), sqlb.Set(ClientSoftwareVersion, r.SoftwareVersion),
		sqlb.Set(ClientSoftwareStatement, r.SoftwareStatement),
		sqlb.Set(ClientCIMDExpires, r.CIMDExpiresAt), sqlb.Set(ClientCIMDETag, r.CIMDETag), sqlb.Set(ClientCIMDLastMod, r.CIMDLastModified),
	))
	return exists("insert client", err)
}

// UpdateClient implements Store: one UPDATE that sets only the named
// columns, so a concurrent update of other columns is never overwritten.
func (s sqlStore) UpdateClient(ctx context.Context, u ClientUpdate) (bool, error) {
	if len(u.Fields) == 0 {
		return false, fmt.Errorf("%w: no field named", ErrBadClientField)
	}
	set := make([]sqlb.Assignment, 0, len(u.Fields))
	for _, f := range u.Fields {
		a, ok := clientAssignment(f, u.Record)
		if !ok {
			return false, fmt.Errorf("%w: %q", ErrBadClientField, f)
		}
		set = append(set, a)
	}
	where := []sqlb.Predicate{sqlb.Eq(ClientIDCol, u.ID)}
	if u.IfDiscovery != nil {
		where = append(where, sqlb.Eq(ClientDiscovery, u.IfDiscovery))
	}
	n, err := s.a().Exec(ctx, sqlb.NewUpdate(s.dialect()).Table(TableClient).Set(set...).Where(where...))
	return n > 0, err
}

// DeleteClient implements Store.
func (s sqlStore) DeleteClient(ctx context.Context, id string) (bool, error) {
	d := s.dialect()
	for _, st := range []auth.Statement{
		sqlb.NewDelete(d).From(TableCode).Where(sqlb.Eq(CodeClient, id)),
		sqlb.NewDelete(d).From(TableToken).Where(sqlb.Eq(TokenClient, id)),
		sqlb.NewDelete(d).From(TableConsent).Where(sqlb.Eq(ConsentClient, id)),
	} {
		if _, err := s.a().Exec(ctx, st); err != nil {
			return false, err
		}
	}
	n, err := s.a().Exec(ctx, sqlb.NewDelete(d).From(TableClient).Where(sqlb.Eq(ClientIDCol, id)))
	return n > 0, err
}

// Clients implements Store.
func (s sqlStore) Clients(ctx context.Context, f ClientFilter) ([]ClientRecord, error) {
	var r ClientRecord
	out := []ClientRecord{}
	q := s.a().Select().Columns(clientBindings(&r)...).From(TableClient).Where(clientWhere(f)...).
		Order(sqlb.OrderBy(ClientCreated, sqlb.SortAsc), sqlb.OrderBy(ClientIDCol, sqlb.SortAsc))
	err := s.a().Each(ctx, q, func() error { out = append(out, r); return nil })
	return out, err
}

// CountClients implements Store.
func (s sqlStore) CountClients(ctx context.Context, f ClientFilter) (int64, error) {
	var n int64
	err := s.a().One(ctx, s.a().Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(TableClient).Where(clientWhere(f)...))
	return n, err
}

// codeBindings are every column of a code row.
func codeBindings(r *CodeRecord) []sqlb.Binding {
	return []sqlb.Binding{
		sqlb.Bind(CodeID, &r.ID), sqlb.Bind(CodeHash, &r.Hash), sqlb.Bind(CodeClient, &r.ClientID), sqlb.Bind(CodeUser, &r.UserID), sqlb.Bind(CodeSession, &r.SessionID),
		sqlb.Bind(CodeRedirect, &r.RedirectURI), sqlb.Bind(CodeScopes, &r.Scopes), sqlb.Bind(CodeChallenge, &r.Challenge),
		sqlb.Bind(CodeMethod, &r.ChallengeMethod), sqlb.Bind(CodeNonce, &r.Nonce), sqlb.Bind(CodeAuthTime, &r.AuthTime),
		sqlb.Bind(CodeExpires, &r.ExpiresAt), sqlb.Bind(CodeCreated, &r.CreatedAt), sqlb.Bind(CodeConsumed, &r.ConsumedAt), sqlb.Bind(CodeResource, &r.Resource),
		sqlb.Bind(CodeClaims, &r.Claims), sqlb.Bind(CodeJKT, &r.DPoPJKT), sqlb.Bind(CodeRef, &r.ReferenceID),
	}
}

// InsertCode implements Store.
func (s sqlStore) InsertCode(ctx context.Context, r CodeRecord) error {
	_, err := s.a().Exec(ctx, sqlb.NewInsert(s.dialect()).Into(TableCode).Row(
		sqlb.Set(CodeID, r.ID), sqlb.Set(CodeHash, r.Hash), sqlb.Set(CodeClient, r.ClientID),
		sqlb.Set(CodeUser, r.UserID), sqlb.Set(CodeSession, r.SessionID), sqlb.Set(CodeRedirect, r.RedirectURI),
		sqlb.Set(CodeScopes, r.Scopes), sqlb.Set(CodeChallenge, r.Challenge),
		sqlb.Set(CodeMethod, r.ChallengeMethod), sqlb.Set(CodeNonce, r.Nonce),
		sqlb.Set(CodeAuthTime, r.AuthTime), sqlb.Set(CodeExpires, r.ExpiresAt), sqlb.Set(CodeCreated, r.CreatedAt),
		sqlb.Set(CodeConsumed, r.ConsumedAt),
		sqlb.Set(CodeResource, r.Resource), sqlb.Set(CodeClaims, r.Claims), sqlb.Set(CodeJKT, r.DPoPJKT),
		sqlb.Set(CodeRef, r.ReferenceID),
	))
	return exists("insert code", err)
}

// spendCode is the single-use UPDATE: it changes a row only while
// consumed_at is null, so of two requests with one code exactly one does.
func (s sqlStore) spendCode(ctx context.Context, hash []byte, now time.Time) (int64, error) {
	return s.a().Exec(ctx, sqlb.NewUpdate(s.dialect()).Table(TableCode).Set(sqlb.Set(CodeConsumed, &now)).
		Where(sqlb.Eq(CodeHash, hash), sqlb.IsNull(CodeConsumed)))
}

// RedeemCode implements Store: the UPDATE claims, then the row is read
// back (no RETURNING, which MySQL lacks).
func (s sqlStore) RedeemCode(ctx context.Context, hash []byte, now time.Time) (CodeRecord, bool, error) {
	n, err := s.spendCode(ctx, hash, now)
	if err != nil {
		return CodeRecord{}, false, err
	}
	var r CodeRecord
	err = s.a().One(ctx, s.a().Select().Columns(codeBindings(&r)...).From(TableCode).Where(sqlb.Eq(CodeHash, hash)))
	if err != nil {
		return CodeRecord{}, false, notFound(err)
	}
	return r, n == 1, nil
}

// RestoreCode implements Store.
func (s sqlStore) RestoreCode(ctx context.Context, hash []byte) (bool, error) {
	n, err := s.a().Exec(ctx, sqlb.NewUpdate(s.dialect()).Table(TableCode).Set(sqlb.Set(CodeConsumed, (*time.Time)(nil))).
		Where(sqlb.Eq(CodeHash, hash), sqlb.IsNotNull(CodeConsumed)))
	return n > 0, err
}

// BurnCode implements Store.
func (s sqlStore) BurnCode(ctx context.Context, hash []byte, now time.Time) (bool, error) {
	n, err := s.spendCode(ctx, hash, now)
	return n > 0, err
}

// DeleteCodes implements Store.
func (s sqlStore) DeleteCodes(ctx context.Context, f CodeFilter) (int64, error) {
	if f.Empty() {
		return 0, ErrEmptyFilter
	}
	var where []sqlb.Predicate
	if f.UserID != "" {
		where = append(where, sqlb.Eq(CodeUser, f.UserID))
	}
	if f.ClientID != "" {
		where = append(where, sqlb.Eq(CodeClient, f.ClientID))
	}
	if f.OnlyUnredeemed {
		where = append(where, sqlb.IsNull(CodeConsumed))
	}
	return s.a().Exec(ctx, sqlb.NewDelete(s.dialect()).From(TableCode).Where(where...))
}

// tokenBindings are every column of a token row but the replay pair.
func tokenBindings(r *TokenRecord) []sqlb.Binding {
	return []sqlb.Binding{
		sqlb.Bind(TokenID, &r.ID), sqlb.Bind(TokenAccessHash, &r.AccessHash), sqlb.Bind(TokenRefresh, &r.RefreshHash),
		sqlb.Bind(TokenFamily, &r.Family), sqlb.Bind(TokenClient, &r.ClientID), sqlb.Bind(TokenScopes, &r.Scopes),
		sqlb.Bind(TokenUser, &r.UserID), sqlb.Bind(TokenSession, &r.SessionID), sqlb.Bind(TokenAccessExpires, &r.AccessExpiresAt),
		sqlb.Bind(TokenRefreshExpires, &r.RefreshExpiresAt), sqlb.Bind(TokenAuthTime, &r.AuthTime), sqlb.Bind(TokenCreated, &r.CreatedAt),
		sqlb.Bind(TokenRotated, &r.RotatedAt), sqlb.Bind(TokenRevoked, &r.RevokedAt), sqlb.Bind(TokenResource, &r.Resource), sqlb.Bind(TokenClaims, &r.Claims), sqlb.Bind(TokenJKT, &r.JKT),
		sqlb.Bind(TokenX5T, &r.X5T), sqlb.Bind(TokenRef, &r.ReferenceID), sqlb.Bind(TokenAccessRevoked, &r.AccessRevokedAt),
	}
}

// tokenWhere is the condition of a TokenFilter.
func tokenWhere(f TokenFilter) []sqlb.Predicate {
	var where []sqlb.Predicate
	if f.ID != "" {
		where = append(where, sqlb.Eq(TokenID, f.ID))
	}
	if f.Family != "" {
		where = append(where, sqlb.Eq(TokenFamily, f.Family))
	}
	if f.UserID != "" {
		where = append(where, sqlb.Eq(TokenUser, &f.UserID))
	}
	if f.ClientID != "" {
		where = append(where, sqlb.Eq(TokenClient, f.ClientID))
	}
	if f.SessionID != "" {
		where = append(where, sqlb.Eq(TokenSession, &f.SessionID))
	}
	if f.AnySession {
		where = append(where, sqlb.IsNotNull(TokenSession))
		if f.ExceptSession != "" {
			where = append(where, sqlb.NotEq(TokenSession, &f.ExceptSession))
		}
	}
	if f.OnlyUnrevoked {
		where = append(where, sqlb.IsNull(TokenRevoked))
	}
	return where
}

// InsertToken implements Store.
func (s sqlStore) InsertToken(ctx context.Context, r TokenRecord) error {
	_, err := s.a().Exec(ctx, sqlb.NewInsert(s.dialect()).Into(TableToken).Row(
		sqlb.Set(TokenID, r.ID), sqlb.Set(TokenAccessHash, r.AccessHash), sqlb.Set(TokenRefreshNull, bytesOrNull(r.RefreshHash)),
		sqlb.Set(TokenFamily, r.Family), sqlb.Set(TokenClient, r.ClientID), sqlb.Set(TokenUser, r.UserID),
		sqlb.Set(TokenSession, r.SessionID), sqlb.Set(TokenScopes, r.Scopes), sqlb.Set(TokenAccessExpires, r.AccessExpiresAt),
		sqlb.Set(TokenRefreshExpires, r.RefreshExpiresAt), sqlb.Set(TokenAuthTime, r.AuthTime), sqlb.Set(TokenCreated, r.CreatedAt),
		sqlb.Set(TokenRotated, r.RotatedAt), sqlb.Set(TokenRevoked, r.RevokedAt),
		sqlb.Set(TokenResource, r.Resource), sqlb.Set(TokenClaims, r.Claims), sqlb.Set(TokenJKT, r.JKT),
		sqlb.Set(TokenX5T, r.X5T), sqlb.Set(TokenRef, r.ReferenceID), sqlb.Set(TokenAccessRevoked, r.AccessRevokedAt),
	))
	return exists("insert token", err)
}

// tokenBy reads one token by a hash column.
func (s sqlStore) tokenBy(ctx context.Context, col sqlb.Expr[[]byte], hash []byte) (TokenRecord, error) {
	var r TokenRecord
	err := s.a().One(ctx, s.a().Select().Columns(tokenBindings(&r)...).From(TableToken).Where(sqlb.Eq(col, hash)))
	return r, notFound(err)
}

// TokenByAccessHash implements Store.
func (s sqlStore) TokenByAccessHash(ctx context.Context, hash []byte) (TokenRecord, error) {
	return s.tokenBy(ctx, TokenAccessHash, hash)
}

// TokenByRefreshHash implements Store.
func (s sqlStore) TokenByRefreshHash(ctx context.Context, hash []byte) (TokenRecord, error) {
	return s.tokenBy(ctx, TokenRefresh, hash)
}

// RotateRefresh implements Store. The UPDATE matches only a row neither
// rotated nor revoked, so of two requests with one token exactly one
// changes it. When it changed nothing the token is spent, revoked or
// unknown, and what decides between a reuse inside RefreshReuseInterval and
// a reuse that revokes the family is the rotation another request committed,
// possibly while this transaction was open (two tabs refreshing at once).
// The UPDATE already judged the newest committed row; the re-read must too,
// or on MySQL's REPEATABLE READ it returns this transaction's older
// snapshot (rotated still NULL) and a reuse inside the window revokes the
// family. TestOAuthProvider_ConcurrentRefreshInsideReuseWindow pins it on
// all three engines.
func (s sqlStore) RotateRefresh(ctx context.Context, hash []byte, now time.Time) (TokenRecord, bool, error) {
	n, err := s.a().Exec(ctx, sqlb.NewUpdate(s.dialect()).Table(TableToken).Set(sqlb.Set(TokenRotated, &now)).
		Where(sqlb.Eq(TokenRefresh, hash), sqlb.IsNull(TokenRotated), sqlb.IsNull(TokenRevoked)))
	if err != nil {
		return TokenRecord{}, false, err
	}
	var r TokenRecord
	read := s.a().Select().Columns(tokenBindings(&r)...).From(TableToken).Where(sqlb.Eq(TokenRefresh, hash))
	if n == 0 {
		read = s.p.lockedRead(read)
	}
	if err := s.a().One(ctx, read); err != nil {
		return TokenRecord{}, false, notFound(err)
	}
	return r, n == 1, nil
}

// RestoreRefresh implements Store.
func (s sqlStore) RestoreRefresh(ctx context.Context, hash []byte) (bool, error) {
	n, err := s.a().Exec(ctx, sqlb.NewUpdate(s.dialect()).Table(TableToken).Set(sqlb.Set(TokenRotated, (*time.Time)(nil))).
		Where(sqlb.Eq(TokenRefresh, hash), sqlb.IsNotNull(TokenRotated), sqlb.IsNull(TokenRevoked)))
	return n > 0, err
}

// RevokeTokens implements Store: one UPDATE, and only rows whose
// revoked_at is null, so a row is counted by exactly one call.
func (s sqlStore) RevokeTokens(ctx context.Context, f TokenFilter, now time.Time) (int64, error) {
	if f.Empty() {
		return 0, ErrEmptyFilter
	}
	f.OnlyUnrevoked = true
	return s.a().Exec(ctx, sqlb.NewUpdate(s.dialect()).Table(TableToken).Set(sqlb.Set(TokenRevoked, &now)).Where(tokenWhere(f)...))
}

// RevokeAccess implements Store.
func (s sqlStore) RevokeAccess(ctx context.Context, id string, now time.Time) (int64, error) {
	return s.a().Exec(ctx, sqlb.NewUpdate(s.dialect()).Table(TableToken).Set(sqlb.Set(TokenAccessRevoked, &now)).
		Where(sqlb.Eq(TokenID, id), sqlb.IsNull(TokenAccessRevoked)))
}

// Tokens implements Store.
func (s sqlStore) Tokens(ctx context.Context, f TokenFilter) ([]TokenRecord, error) {
	if f.Empty() {
		return nil, ErrEmptyFilter
	}
	var r TokenRecord
	var out []TokenRecord
	q := s.a().Select().Columns(tokenBindings(&r)...).From(TableToken).Where(tokenWhere(f)...)
	err := s.a().Each(ctx, q, func() error { out = append(out, r); return nil })
	return out, err
}

// EndTokenSession implements Store.
func (s sqlStore) EndTokenSession(ctx context.Context, id string, now time.Time, revokeRefresh bool) error {
	set := []sqlb.Assignment{sqlb.Set(TokenAccessExpires, now)}
	if revokeRefresh {
		set = append(set, sqlb.Set(TokenRevoked, &now))
	}
	_, err := s.a().Exec(ctx, sqlb.NewUpdate(s.dialect()).Table(TableToken).Set(set...).Where(sqlb.Eq(TokenID, id)))
	return err
}

// MoveSession implements Store.
func (s sqlStore) MoveSession(ctx context.Context, from, to string) error {
	_, err := s.a().Exec(ctx, sqlb.NewUpdate(s.dialect()).Table(TableToken).Set(sqlb.Set(TokenSession, &to)).Where(sqlb.Eq(TokenSession, &from)))
	return err
}

// SetReplay implements Store.
func (s sqlStore) SetReplay(ctx context.Context, id string, r ReplayRecord) error {
	_, err := s.a().Exec(ctx, sqlb.NewUpdate(s.dialect()).Table(TableToken).Set(
		sqlb.Set(TokenReplay, &r.Sealed), sqlb.Set(TokenReplayExpires, &r.ExpiresAt)).Where(sqlb.Eq(TokenID, id)))
	return err
}

// Replay implements Store. The read is a locking one for the reason
// RotateRefresh's re-read is: the answer was stored by the request that
// rotated the token, which may have committed while this transaction was
// open, and a plain read on MySQL's REPEATABLE READ would miss it and issue
// a second pair.
func (s sqlStore) Replay(ctx context.Context, id string) (ReplayRecord, bool, error) {
	var sealed *string
	var exp *time.Time
	read := s.a().Select().Columns(sqlb.Bind(TokenReplay, &sealed), sqlb.Bind(TokenReplayExpires, &exp)).From(TableToken).Where(sqlb.Eq(TokenID, id))
	if err := s.a().One(ctx, s.p.lockedRead(read)); err != nil {
		return ReplayRecord{}, false, notFound(err)
	}
	if sealed == nil || exp == nil {
		return ReplayRecord{}, false, nil
	}
	return ReplayRecord{Sealed: *sealed, ExpiresAt: *exp}, true, nil
}

// consentBindings are every column of a consent row.
func consentBindings(r *ConsentRecord) []sqlb.Binding {
	return []sqlb.Binding{
		sqlb.Bind(ConsentID, &r.ID), sqlb.Bind(ConsentUser, &r.UserID), sqlb.Bind(ConsentClient, &r.ClientID), sqlb.Bind(ConsentScopes, &r.Scopes),
		sqlb.Bind(ConsentClaims, &r.Claims), sqlb.Bind(ConsentRef, &r.ReferenceID), sqlb.Bind(ConsentResources, &r.Resources),
		sqlb.Bind(ConsentCreated, &r.CreatedAt), sqlb.Bind(ConsentUpdated, &r.UpdatedAt),
	}
}

// consentWhere reads one consent.
func (s sqlStore) consentWhere(ctx context.Context, where ...sqlb.Predicate) (ConsentRecord, error) {
	var r ConsentRecord
	err := s.a().One(ctx, s.a().Select().Columns(consentBindings(&r)...).From(TableConsent).Where(where...))
	return r, notFound(err)
}

// Consent implements Store.
func (s sqlStore) Consent(ctx context.Context, userID, clientID string) (ConsentRecord, error) {
	return s.consentWhere(ctx, sqlb.Eq(ConsentUser, userID), sqlb.Eq(ConsentClient, clientID))
}

// ConsentByID implements Store.
func (s sqlStore) ConsentByID(ctx context.Context, userID, id string) (ConsentRecord, error) {
	return s.consentWhere(ctx, sqlb.Eq(ConsentID, id), sqlb.Eq(ConsentUser, userID))
}

// Consents implements Store.
func (s sqlStore) Consents(ctx context.Context, userID string) ([]ConsentRecord, error) {
	var r ConsentRecord
	out := []ConsentRecord{}
	q := s.a().Select().Columns(consentBindings(&r)...).From(TableConsent).Where(sqlb.Eq(ConsentUser, userID)).
		Order(sqlb.OrderBy(ConsentCreated, sqlb.SortAsc), sqlb.OrderBy(ConsentID, sqlb.SortAsc))
	err := s.a().Each(ctx, q, func() error { out = append(out, r); return nil })
	return out, err
}

// InsertConsent implements Store; the (user_id, client_id) unique
// constraint refuses a second consent.
func (s sqlStore) InsertConsent(ctx context.Context, r ConsentRecord) error {
	_, err := s.a().Exec(ctx, sqlb.NewInsert(s.dialect()).Into(TableConsent).Row(
		sqlb.Set(ConsentID, r.ID), sqlb.Set(ConsentUser, r.UserID), sqlb.Set(ConsentClient, r.ClientID),
		sqlb.Set(ConsentScopes, r.Scopes), sqlb.Set(ConsentCreated, r.CreatedAt), sqlb.Set(ConsentUpdated, r.UpdatedAt),
		sqlb.Set(ConsentClaims, r.Claims), sqlb.Set(ConsentRef, r.ReferenceID), sqlb.Set(ConsentResources, r.Resources)))
	return exists("insert consent", err)
}

// UpdateConsent implements Store.
func (s sqlStore) UpdateConsent(ctx context.Context, r ConsentRecord) (bool, error) {
	n, err := s.a().Exec(ctx, sqlb.NewUpdate(s.dialect()).Table(TableConsent).
		Set(sqlb.Set(ConsentScopes, r.Scopes), sqlb.Set(ConsentClaims, r.Claims), sqlb.Set(ConsentRef, r.ReferenceID),
			sqlb.Set(ConsentResources, r.Resources), sqlb.Set(ConsentUpdated, r.UpdatedAt)).Where(sqlb.Eq(ConsentID, r.ID)))
	return n > 0, err
}

// DeleteConsent implements Store.
func (s sqlStore) DeleteConsent(ctx context.Context, userID, clientID string) (bool, error) {
	n, err := s.a().Exec(ctx, sqlb.NewDelete(s.dialect()).From(TableConsent).Where(sqlb.Eq(ConsentUser, userID), sqlb.Eq(ConsentClient, clientID)))
	return n > 0, err
}

// Sweep implements Store.
func (s sqlStore) Sweep(ctx context.Context, cutoff time.Time) (int64, error) {
	n, err := s.a().Exec(ctx, sqlb.NewDelete(s.dialect()).From(TableCode).Where(sqlb.Less(CodeExpires, cutoff)))
	if err != nil {
		return n, err
	}
	m, err := s.a().Exec(ctx, sqlb.NewDelete(s.dialect()).From(TableToken).Where(
		sqlb.Less(TokenAccessExpires, cutoff),
		sqlb.Or(sqlb.IsNull(TokenRefreshExpires), sqlb.Less(TokenRefreshExpires, &cutoff)),
	))
	return n + m, err
}

// DeleteUser implements Store. auth.DeleteUser reaches the SQL rows through
// UserTables already; this is the same deletion for the conformance suite
// and for a caller that holds the store alone.
func (s sqlStore) DeleteUser(ctx context.Context, userID string) error {
	d := s.dialect()
	for _, st := range []auth.Statement{
		sqlb.NewDelete(d).From(TableClient).Where(sqlb.Eq(ClientOwner, &userID)),
		sqlb.NewDelete(d).From(TableCode).Where(sqlb.Eq(CodeUser, userID)),
		sqlb.NewDelete(d).From(TableToken).Where(sqlb.Eq(TokenUser, &userID)),
		sqlb.NewDelete(d).From(TableConsent).Where(sqlb.Eq(ConsentUser, userID)),
	} {
		if _, err := s.a().Exec(ctx, st); err != nil {
			return err
		}
	}
	return nil
}

var _ Store = sqlStore{}
