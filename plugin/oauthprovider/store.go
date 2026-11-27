package oauthprovider

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// Store is where the provider keeps its clients, authorization codes, tokens
// and consents. The SQL store on the plugin's tables (auth_oauth_client,
// auth_oauth_code, auth_oauth_token, auth_oauth_consent) is the default;
// WithStore replaces it, with a key-value store or a separate database, say.
// The resource registry and the private_key_jwt and DPoP replay caches stay
// on the core database (auth.WithDB) whatever the store.
//
// The provider keeps every rule: lifetimes, PKCE, scopes, the reuse window,
// what a refused request revokes, when a client is notified. A store saves
// and finds, and keeps the few rules that need an atomic step, each named in
// its method's contract, so no rule depends on the plugin composing a read
// and a write. github.com/ubgo/auth/plugin/oauthprovider/storetest checks
// every contract, races included; a custom store runs it before it ships.
// The contracts every store keeps:
//
//   - A store sees no usable secret: client secrets, codes and tokens arrive
//     as their stored hash (HashStoredSecrets), a recoverable client secret
//     as its EncryptClientSecrets ciphertext, a RefreshReplay answer sealed.
//   - Every field of a record is kept as given and returned unchanged; a
//     store reads only the fields its lookups, filters and conditions name.
//   - Times are the ones the provider passes; a store never reads a clock of
//     its own.
//   - RedeemCode and RotateRefresh have exactly one winner among concurrent
//     calls for one hash; RevokeTokens counts each token once, ever.
//   - A lookup that finds nothing is ErrRecordNotFound, an insert whose key
//     is taken ErrRecordExists.
//
// What a store outside the database gives up: it joins no transaction. A
// code redeemed or a refresh token rotated by a request that then fails is
// put back by the provider once the request's transaction ends without a
// commit (RestoreCode, RestoreRefresh), as the SQL rollback would; until
// then a second request presenting it sees it spent, where the database
// would have made that request wait for the first. A token row written by
// an issuance that then fails stays,
// unreachable because nobody received its token, until Sweep removes it.
// RevokeUserForClient and RevokeUserFamily are not all-or-nothing across a
// store and the database. A user's rows in such a store are removed by
// DeleteUser, which auth.DeleteUser reaches through the plugin's data hook.
//
//ds:def id=oauthprovider-store-7kq3vn2x owner=@khanakia stability=stable
type Store interface {
	// Client returns the client with this id.
	Client(ctx context.Context, id string) (ClientRecord, error)
	// InsertClient saves a new client; ErrRecordExists when the id is
	// taken. Of concurrent inserts of one id exactly one succeeds.
	InsertClient(ctx context.Context, c ClientRecord) error
	// UpdateClient writes the fields u.Fields names, taken from u.Record, to
	// client u.ID, and reports whether a client matched. Every other field
	// keeps its stored value, even when another update of the same client
	// runs at the same time: a metadata edit racing a disable must not
	// enable the client again. With u.IfDiscovery set, only a client whose
	// Discovery equals it matches. A field outside ClientFields is
	// ErrBadClientField and writes nothing.
	UpdateClient(ctx context.Context, u ClientUpdate) (bool, error)
	// DeleteClient removes the client and every code, token and consent of
	// it, and reports whether the client existed.
	DeleteClient(ctx context.Context, id string) (bool, error)
	// Clients returns the clients f selects, oldest first, ties by id.
	Clients(ctx context.Context, f ClientFilter) ([]ClientRecord, error)
	// CountClients is how many clients f selects.
	CountClients(ctx context.Context, f ClientFilter) (int64, error)

	// InsertCode saves a new authorization code under c.Hash.
	InsertCode(ctx context.Context, c CodeRecord) error
	// RedeemCode spends the code whose hash is hash, atomically: when it is
	// unspent it sets ConsumedAt to now and returns the record and true;
	// when it is spent already it returns the record, unchanged, and false
	// (the provider reads that as a replay and revokes the code's tokens).
	// Of any number of concurrent calls with one hash exactly one returns
	// true. Expiry is the provider's to judge on the record.
	RedeemCode(ctx context.Context, hash []byte, now time.Time) (CodeRecord, bool, error)
	// RestoreCode unspends the code whose hash is hash and reports whether
	// it did: what the SQL store's rollback does when the request that
	// redeemed the code then fails without spending it on purpose (a
	// refusal after the code's bindings held, a failed write). The provider
	// calls it only for a store outside the database, only for a code its
	// own failed request redeemed, after that request's transaction ended
	// and before any burn of the same request, so a refusal that spends the
	// code still does.
	RestoreCode(ctx context.Context, hash []byte) (bool, error)
	// BurnCode spends the code whose hash is hash if it is unspent and
	// reports whether this call spent it; an unknown hash is false, nil.
	// The provider calls it after a refused exchange's rollback, so a
	// refused code cannot be redeemed again.
	BurnCode(ctx context.Context, hash []byte, now time.Time) (bool, error)
	// DeleteCodes deletes the codes f selects and reports how many.
	DeleteCodes(ctx context.Context, f CodeFilter) (int64, error)

	// InsertToken saves a new token issuance: an access token and, when
	// t.RefreshHash is set, its refresh token.
	InsertToken(ctx context.Context, t TokenRecord) error
	// TokenByAccessHash returns the issuance whose access token hashes to
	// hash, as last committed.
	TokenByAccessHash(ctx context.Context, hash []byte) (TokenRecord, error)
	// TokenByRefreshHash returns the issuance whose refresh token hashes to
	// hash, as last committed.
	TokenByRefreshHash(ctx context.Context, hash []byte) (TokenRecord, error)
	// RotateRefresh spends the refresh token whose hash is hash,
	// atomically: when neither RotatedAt nor RevokedAt is set it sets
	// RotatedAt to now and returns the record and true. Otherwise it
	// returns false and the record as last committed by anyone, so a
	// rotation another request committed a moment ago shows: the provider
	// judges the reuse window, and whether a reuse revokes the family, on
	// it. Of any number of concurrent calls with one hash exactly one
	// returns true.
	RotateRefresh(ctx context.Context, hash []byte, now time.Time) (TokenRecord, bool, error)
	// RestoreRefresh clears the RotatedAt of the refresh token whose hash is
	// hash, only while its RevokedAt is unset, and reports whether it did:
	// RestoreCode's counterpart for a rotation whose request failed, called
	// on the same terms. A family revoked in the meantime stays revoked.
	RestoreRefresh(ctx context.Context, hash []byte) (bool, error)
	// RevokeTokens sets RevokedAt to now on every token f selects whose
	// RevokedAt is unset, and reports how many it changed. A token already
	// revoked is never counted again, so a repeat returns 0 and concurrent
	// calls count each token once in total: the provider notifies clients
	// and reports events only for a non-zero count. A filter that selects
	// by nothing is ErrEmptyFilter. A family revoke is TokenFilter{Family}.
	RevokeTokens(ctx context.Context, f TokenFilter, now time.Time) (int64, error)
	// RevokeAccess sets AccessRevokedAt to now on token id when it is unset
	// (RevokeAccessTokenOnly: the refresh token stays usable), reporting
	// how many it changed.
	RevokeAccess(ctx context.Context, id string, now time.Time) (int64, error)
	// Tokens returns the tokens f selects, in no particular order. A filter
	// that selects by nothing is ErrEmptyFilter.
	Tokens(ctx context.Context, f TokenFilter) ([]TokenRecord, error)
	// EndTokenSession ends token id because its session ended: its access
	// token expires now (AccessExpiresAt = now) and, with revokeRefresh,
	// RevokedAt is set to now as well. Nothing else changes.
	EndTokenSession(ctx context.Context, id string, now time.Time, revokeRefresh bool) error
	// MoveSession moves every token issued on session from to session to.
	MoveSession(ctx context.Context, from, to string) error
	// SetReplay stores RefreshReplay's sealed first answer on token id,
	// replacing any earlier one.
	SetReplay(ctx context.Context, id string, r ReplayRecord) error
	// Replay returns what SetReplay stored on token id, as last committed
	// by anyone, and whether there is one; ErrRecordNotFound when the token
	// is unknown.
	Replay(ctx context.Context, id string) (ReplayRecord, bool, error)

	// Consent returns the user's consent to the client.
	Consent(ctx context.Context, userID, clientID string) (ConsentRecord, error)
	// ConsentByID returns the consent id of the user; another user's is
	// ErrRecordNotFound, the same as an unknown one.
	ConsentByID(ctx context.Context, userID, id string) (ConsentRecord, error)
	// Consents returns the user's consents, oldest first, ties by id.
	Consents(ctx context.Context, userID string) ([]ConsentRecord, error)
	// InsertConsent saves a new consent; ErrRecordExists when the user has
	// one for the client already. A user has at most one per client.
	InsertConsent(ctx context.Context, c ConsentRecord) error
	// UpdateConsent replaces the Scopes, Claims, Resources, ReferenceID and
	// UpdatedAt of consent c.ID with c's, never merging, and reports
	// whether it matched. Whether a new approval widens or replaces a grant
	// is the provider's decision (an expired one is replaced).
	UpdateConsent(ctx context.Context, c ConsentRecord) (bool, error)
	// DeleteConsent deletes the user's consent to the client and reports
	// whether there was one.
	DeleteConsent(ctx context.Context, userID, clientID string) (bool, error)

	// Sweep deletes codes that expired before cutoff and tokens whose access
	// token expired before cutoff and whose refresh token, if any, did too,
	// and reports how many. A token whose refresh token is still live stays,
	// rotated or not: a replay of a rotated refresh token must still find
	// its family to revoke it. A store that expires records itself returns
	// 0.
	Sweep(ctx context.Context, cutoff time.Time) (int64, error)
	// DeleteUser deletes every client the user owns and every code, token
	// and consent of the user.
	DeleteUser(ctx context.Context, userID string) error
}

// ErrRecordNotFound is a Store lookup that finds nothing. The provider turns
// it into the answer of the endpoint (ErrClientNotFound, invalid_grant); a
// store returns this one so the provider can tell "not there" from "the
// store failed", which must never read as a refusal.
var ErrRecordNotFound = errors.New("oauthprovider: record not found")

// ErrRecordExists is a Store insert whose key is taken: a client id, or a
// second consent of one user to one client. The SQL store wraps the
// database's unique violation, so auth.IsUniqueViolation holds for it too.
var ErrRecordExists = errors.New("oauthprovider: record already stored")

// ErrEmptyFilter is a TokenFilter or CodeFilter that selects by nothing. A
// store refuses it, so a caller's bug can never revoke or delete every token.
var ErrEmptyFilter = errors.New("oauthprovider: store filter selects by nothing")

// ErrBadClientField is a ClientUpdate naming a field outside ClientFields.
var ErrBadClientField = errors.New("oauthprovider: unknown client field")

// ClientRecord is a client as stored. The list fields hold what the
// provider writes (RedirectURIs and PostLogoutRedirectURIs newline-joined,
// Scopes, GrantTypes, Contacts and ClientCredentialsScopes space-joined); a
// store keeps them as opaque text. SecretHash is nil for a client without a
// secret; SecretEncrypted is set only under EncryptClientSecrets.
type ClientRecord struct {
	ID                               string
	SecretHash                       []byte
	SecretEncrypted                  *string
	Name                             string
	RedirectURIs                     string
	Scopes                           string
	GrantTypes                       string
	AuthMethod                       string
	SkipConsent                      bool
	RequirePKCE                      bool
	IntrospectAny                    bool
	OwnerID                          *string
	DisabledAt                       *time.Time
	ClientURI                        *string
	LogoURI                          *string
	Contacts                         *string
	TosURI                           *string
	PolicyURI                        *string
	CreatedAt                        time.Time
	UpdatedAt                        time.Time
	PostLogoutRedirectURIs           *string
	EndSession                       bool
	JWKS                             *string
	JWKSURI                          *string
	Discovery                        *string
	FetchedAt                        *time.Time
	SubjectType                      *string
	BackchannelLogoutURI             *string
	BackchannelLogoutSessionRequired bool
	DPoPBound                        bool
	ApplicationType                  *string
	ClientCredentialsScopes          *string
	ReferenceID                      *string
	Metadata                         *string
	SecretExpiresAt                  *time.Time
	SoftwareID                       *string
	SoftwareVersion                  *string
	SoftwareStatement                *string
	CIMDExpiresAt                    *time.Time
	CIMDETag                         *string
	CIMDLastModified                 *string
}

// ClientField names one field of a ClientRecord that UpdateClient can
// write. The values are the SQL column names, so the SQL store maps them
// one to one; ID, CreatedAt and Discovery are never updated.
type ClientField string

// The fields UpdateClient can write, each the ClientRecord field of the
// same name.
const (
	ClientFieldSecretHash                       ClientField = ColSecretHash
	ClientFieldSecretEncrypted                  ClientField = ColSecretEncrypted
	ClientFieldName                             ClientField = ColName
	ClientFieldRedirectURIs                     ClientField = ColRedirectURIs
	ClientFieldScopes                           ClientField = ColScopes
	ClientFieldGrantTypes                       ClientField = ColGrantTypes
	ClientFieldAuthMethod                       ClientField = ColAuthMethod
	ClientFieldSkipConsent                      ClientField = ColSkipConsent
	ClientFieldRequirePKCE                      ClientField = ColRequirePKCE
	ClientFieldIntrospectAny                    ClientField = ColIntrospectAny
	ClientFieldOwnerID                          ClientField = ColUserID
	ClientFieldDisabledAt                       ClientField = ColDisabledAt
	ClientFieldClientURI                        ClientField = ColClientURI
	ClientFieldLogoURI                          ClientField = ColLogoURI
	ClientFieldContacts                         ClientField = ColContacts
	ClientFieldTosURI                           ClientField = ColTosURI
	ClientFieldPolicyURI                        ClientField = ColPolicyURI
	ClientFieldUpdatedAt                        ClientField = ColUpdatedAt
	ClientFieldPostLogoutRedirectURIs           ClientField = ColPostLogoutURIs
	ClientFieldEndSession                       ClientField = ColEndSession
	ClientFieldJWKS                             ClientField = ColJWKS
	ClientFieldJWKSURI                          ClientField = ColJWKSURI
	ClientFieldFetchedAt                        ClientField = ColFetchedAt
	ClientFieldSubjectType                      ClientField = ColSubjectType
	ClientFieldBackchannelLogoutURI             ClientField = ColBackchannelURI
	ClientFieldBackchannelLogoutSessionRequired ClientField = ColBackchannelSession
	ClientFieldDPoPBound                        ClientField = ColDPoPBound
	ClientFieldApplicationType                  ClientField = ColAppType
	ClientFieldClientCredentialsScopes          ClientField = ColCCScopes
	ClientFieldReferenceID                      ClientField = ColReferenceID
	ClientFieldMetadata                         ClientField = ColMetadata
	ClientFieldSecretExpiresAt                  ClientField = ColSecretExpires
	ClientFieldSoftwareID                       ClientField = ColSoftwareID
	ClientFieldSoftwareVersion                  ClientField = ColSoftwareVersion
	ClientFieldSoftwareStatement                ClientField = ColSoftwareStatement
	ClientFieldCIMDExpiresAt                    ClientField = ColCIMDExpires
	ClientFieldCIMDETag                         ClientField = ColCIMDETag
	ClientFieldCIMDLastModified                 ClientField = ColCIMDLastMod
)

// ClientFields is every field UpdateClient can write, for a store that
// copies fields by name and for the conformance suite.
var ClientFields = []ClientField{
	ClientFieldSecretHash, ClientFieldSecretEncrypted, ClientFieldName, ClientFieldRedirectURIs, ClientFieldScopes,
	ClientFieldGrantTypes, ClientFieldAuthMethod, ClientFieldSkipConsent, ClientFieldRequirePKCE, ClientFieldIntrospectAny,
	ClientFieldOwnerID, ClientFieldDisabledAt, ClientFieldClientURI, ClientFieldLogoURI, ClientFieldContacts,
	ClientFieldTosURI, ClientFieldPolicyURI, ClientFieldUpdatedAt, ClientFieldPostLogoutRedirectURIs, ClientFieldEndSession,
	ClientFieldJWKS, ClientFieldJWKSURI, ClientFieldFetchedAt, ClientFieldSubjectType, ClientFieldBackchannelLogoutURI,
	ClientFieldBackchannelLogoutSessionRequired, ClientFieldDPoPBound, ClientFieldApplicationType, ClientFieldClientCredentialsScopes,
	ClientFieldReferenceID, ClientFieldMetadata, ClientFieldSecretExpiresAt, ClientFieldSoftwareID, ClientFieldSoftwareVersion,
	ClientFieldSoftwareStatement, ClientFieldCIMDExpiresAt, ClientFieldCIMDETag, ClientFieldCIMDLastModified,
}

// ClientUpdate is one UpdateClient: the client, the fields to write and
// their new values.
type ClientUpdate struct {
	ID string
	// Record holds the new values; only the fields Fields names are read.
	Record ClientRecord
	Fields []ClientField
	// IfDiscovery, when set, limits the update to a client whose Discovery
	// equals it: a refresh of a fetched client's document never overwrites
	// a registered client of the same id.
	IfDiscovery *string
}

// Apply copies the fields u.Fields names from u.Record into dst, for a
// store that reads a client, changes it and writes it back in one atomic
// step (a compare-and-swap, a transaction, a lock). ErrBadClientField for a
// field outside ClientFields, and then dst is unchanged.
func (u ClientUpdate) Apply(dst *ClientRecord) error {
	out := *dst
	r := u.Record
	for _, f := range u.Fields {
		switch f {
		case ClientFieldSecretHash:
			out.SecretHash = r.SecretHash
		case ClientFieldSecretEncrypted:
			out.SecretEncrypted = r.SecretEncrypted
		case ClientFieldName:
			out.Name = r.Name
		case ClientFieldRedirectURIs:
			out.RedirectURIs = r.RedirectURIs
		case ClientFieldScopes:
			out.Scopes = r.Scopes
		case ClientFieldGrantTypes:
			out.GrantTypes = r.GrantTypes
		case ClientFieldAuthMethod:
			out.AuthMethod = r.AuthMethod
		case ClientFieldSkipConsent:
			out.SkipConsent = r.SkipConsent
		case ClientFieldRequirePKCE:
			out.RequirePKCE = r.RequirePKCE
		case ClientFieldIntrospectAny:
			out.IntrospectAny = r.IntrospectAny
		case ClientFieldOwnerID:
			out.OwnerID = r.OwnerID
		case ClientFieldDisabledAt:
			out.DisabledAt = r.DisabledAt
		case ClientFieldClientURI:
			out.ClientURI = r.ClientURI
		case ClientFieldLogoURI:
			out.LogoURI = r.LogoURI
		case ClientFieldContacts:
			out.Contacts = r.Contacts
		case ClientFieldTosURI:
			out.TosURI = r.TosURI
		case ClientFieldPolicyURI:
			out.PolicyURI = r.PolicyURI
		case ClientFieldUpdatedAt:
			out.UpdatedAt = r.UpdatedAt
		case ClientFieldPostLogoutRedirectURIs:
			out.PostLogoutRedirectURIs = r.PostLogoutRedirectURIs
		case ClientFieldEndSession:
			out.EndSession = r.EndSession
		case ClientFieldJWKS:
			out.JWKS = r.JWKS
		case ClientFieldJWKSURI:
			out.JWKSURI = r.JWKSURI
		case ClientFieldFetchedAt:
			out.FetchedAt = r.FetchedAt
		case ClientFieldSubjectType:
			out.SubjectType = r.SubjectType
		case ClientFieldBackchannelLogoutURI:
			out.BackchannelLogoutURI = r.BackchannelLogoutURI
		case ClientFieldBackchannelLogoutSessionRequired:
			out.BackchannelLogoutSessionRequired = r.BackchannelLogoutSessionRequired
		case ClientFieldDPoPBound:
			out.DPoPBound = r.DPoPBound
		case ClientFieldApplicationType:
			out.ApplicationType = r.ApplicationType
		case ClientFieldClientCredentialsScopes:
			out.ClientCredentialsScopes = r.ClientCredentialsScopes
		case ClientFieldReferenceID:
			out.ReferenceID = r.ReferenceID
		case ClientFieldMetadata:
			out.Metadata = r.Metadata
		case ClientFieldSecretExpiresAt:
			out.SecretExpiresAt = r.SecretExpiresAt
		case ClientFieldSoftwareID:
			out.SoftwareID = r.SoftwareID
		case ClientFieldSoftwareVersion:
			out.SoftwareVersion = r.SoftwareVersion
		case ClientFieldSoftwareStatement:
			out.SoftwareStatement = r.SoftwareStatement
		case ClientFieldCIMDExpiresAt:
			out.CIMDExpiresAt = r.CIMDExpiresAt
		case ClientFieldCIMDETag:
			out.CIMDETag = r.CIMDETag
		case ClientFieldCIMDLastModified:
			out.CIMDLastModified = r.CIMDLastModified
		default:
			return fmt.Errorf("%w: %q", ErrBadClientField, f)
		}
	}
	*dst = out
	return nil
}

// ClientFilter selects clients. A nil field sets no condition; a pointer to
// "" matches only a client whose field is "" (none does), never every
// client. The zero filter selects every client.
type ClientFilter struct {
	OwnerID     *string
	ReferenceID *string
}

// CodeRecord is an authorization code as stored, under Hash.
type CodeRecord struct {
	ID              string
	Hash            []byte
	ClientID        string
	UserID          string
	SessionID       string
	RedirectURI     string
	Scopes          string
	Challenge       *string
	ChallengeMethod *string
	Nonce           *string
	AuthTime        time.Time
	ExpiresAt       time.Time
	CreatedAt       time.Time
	ConsumedAt      *time.Time
	Resource        *string
	Claims          *string
	DPoPJKT         *string
	ReferenceID     *string
}

// CodeFilter selects codes by user and client; at least one must be set.
// OnlyUnredeemed leaves out spent codes: a spent code is the root of its
// token family, and must stay so presenting it again still reads as a
// replay.
type CodeFilter struct {
	UserID         string
	ClientID       string
	OnlyUnredeemed bool
}

// TokenRecord is a token issuance as stored: an access token and, with
// offline_access, its refresh token. Family ties every issuance descended
// from one code or one client_credentials grant.
type TokenRecord struct {
	ID               string
	AccessHash       []byte
	RefreshHash      []byte
	Family           string
	ClientID         string
	UserID           *string
	SessionID        *string
	Scopes           string
	AccessExpiresAt  time.Time
	RefreshExpiresAt *time.Time
	AuthTime         *time.Time
	CreatedAt        time.Time
	RotatedAt        *time.Time
	RevokedAt        *time.Time
	Resource         *string
	Claims           *string
	JKT              *string
	X5T              *string
	ReferenceID      *string
	AccessRevokedAt  *time.Time
}

// TokenFilter selects tokens. Every set field must match; at least one of
// ID, Family, UserID, ClientID, SessionID or AnySession must be set, or the
// store answers ErrEmptyFilter.
type TokenFilter struct {
	ID       string
	Family   string
	UserID   string
	ClientID string
	// SessionID selects tokens issued on that session.
	SessionID string
	// AnySession selects tokens issued on any session (not on none);
	// ExceptSession then leaves that one out.
	AnySession    bool
	ExceptSession string
	// OnlyUnrevoked leaves out tokens whose RevokedAt is set (Tokens only;
	// RevokeTokens changes unrevoked tokens by definition).
	OnlyUnrevoked bool
}

// Empty reports whether f selects by nothing, the filter a store refuses
// with ErrEmptyFilter.
func (f TokenFilter) Empty() bool {
	return f.ID == "" && f.Family == "" && f.UserID == "" && f.ClientID == "" && f.SessionID == "" && !f.AnySession
}

// Empty reports whether f selects by nothing, the filter a store refuses
// with ErrEmptyFilter.
func (f CodeFilter) Empty() bool { return f.UserID == "" && f.ClientID == "" }

// ReplayRecord is RefreshReplay's sealed first answer to a rotation and the
// end of the window it may be replayed in.
type ReplayRecord struct {
	Sealed    string
	ExpiresAt time.Time
}

// ConsentRecord is a user's consent to a client as stored. Scopes are
// space-joined, Claims and Resources as the provider writes them.
type ConsentRecord struct {
	ID          string
	UserID      string
	ClientID    string
	Scopes      string
	Claims      *string
	ReferenceID *string
	Resources   *string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// WithStore keeps the provider's clients, codes, tokens and consents in s
// instead of the plugin's SQL tables; see Store for the contract and what a
// store outside the database gives up. The tables are still created, so
// switching back needs no migration (the rows do not move by themselves).
// A nil store fails auth.New.
//
//ds:def id=oauthprovider-withstore-3nd8kv5q owner=@khanakia stability=stable
func WithStore(s Store) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("oauthprovider.WithStore", s) {
			return
		}
		p.store, p.customStore = s, true
	}
}

// Store returns the store the provider uses: the one WithStore set, or the
// SQL store once auth.New has initialized the plugin (nil before). It is
// what a conformance test of the SQL store runs against.
func (p *Plugin) Store() Store { return p.store }

// DataHooks removes a deleted user's rows from a custom store, inside the
// transaction that deletes the user. With the SQL store there is no hook:
// UserTables already deletes those rows in that transaction.
func (p *Plugin) DataHooks() auth.DataHooks {
	if !p.customStore {
		return auth.DataHooks{}
	}
	return auth.DataHooks{User: auth.TableHooks[auth.User]{
		BeforeDelete: func(ctx context.Context, _ sqlb.DBTX, u *auth.User) error { return p.store.DeleteUser(ctx, u.ID) },
	}}
}

var _ auth.DataHooker = (*Plugin)(nil)
