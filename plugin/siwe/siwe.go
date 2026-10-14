// Package siwe signs users in with an Ethereum wallet: Sign-In with Ethereum,
// ERC-4361.
//
// The flow is two calls. POST /siwe/nonce hands out a single-use nonce for a
// wallet and chain; the client builds the ERC-4361 message with it, the
// wallet signs it, and POST /siwe/verify checks the message (domain, URI,
// chain, time window, nonce) and the signature, then signs in the wallet's
// user or creates one. Wallets live in the plugin's own table, auth_siwe_wallet,
// several per user: a signed-in user adds another with POST /siwe/link.
//
// Signature checking is a Verifier: the default recovers an EIP-191
// personal_sign signature with secp256k1, which covers every externally owned
// account; a smart-contract wallet needs an RPC call, which the app plugs in
// with WithVerifier. ENS names are an optional NameResolver for the same
// reason: the module ships no RPC client and no vendor connector.
package siwe

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/sqlb"
)

// PluginName is the plugin's permanent identity: its route prefix and its
// owner name in the migration ledger.
const PluginName = "siwe"

// Operation ids, exported so a hook or a rate rule can name them. They are
// wire names, stable across releases.
const (
	EndpointNonce   auth.EndpointID = "siwe.nonce"
	EndpointVerify  auth.EndpointID = "siwe.verify"
	EndpointLink    auth.EndpointID = "siwe.link"
	EndpointWallets auth.EndpointID = "siwe.wallets"
	EndpointUnlink  auth.EndpointID = "siwe.unlink"
)

// Routes under the plugin's prefix, better-auth's names for nonce and verify.
const (
	pathNonce   = "/nonce"
	pathVerify  = "/verify"
	pathLink    = "/link"
	pathWallets = "/wallets"
	pathUnlink  = "/unlink"
)

// PurposeNonce is the verification purpose of a nonce. Its Identifier is
// "<normalized address>:<chain id>": the nonce is bound to the wallet and
// chain it was asked for, so a nonce issued for one wallet cannot sign in
// another. Its token is the nonce itself, stored hashed like every token.
const PurposeNonce auth.Purpose = "siwe.nonce"

// nonceIdentifierSeparator joins address and chain in a nonce's Identifier.
// An address is hex and a chain id decimal, so neither contains it.
const nonceIdentifierSeparator = ":"

// Defaults and limits.
const (
	// DefaultNonceTTL is how long a nonce works: long enough for a person to
	// read the wallet's prompt and approve it, short enough that a message
	// left unsigned is useless soon after. better-auth uses the same.
	DefaultNonceTTL = 15 * time.Minute
	// ClockSkew is how far in the future a message's Issued At may be, and
	// how far past its Expiration Time it is still accepted, for a client
	// clock a little off the server's.
	ClockSkew = time.Minute
	// nonceBytes of randomness per nonce, written as hex: 256 bits, the same
	// strength as every other token, and hex is alphanumeric as ERC-4361
	// requires.
	nonceBytes = 32
	// nonceIPLimit nonces per IP per nonceIPWindow: every call stores a row,
	// and a real sign-in needs one, or a few after cancelled prompts.
	nonceIPLimit  = 30
	nonceIPWindow = time.Minute
	// verifyIPLimit verifications per IP per verifyIPWindow bounds the
	// signature recoveries an anonymous client can ask for.
	verifyIPLimit  = 30
	verifyIPWindow = time.Minute
	// maxSignatureHexLength bounds the signature text: 65 bytes for an
	// account, more for a smart-contract wallet's EIP-6492 wrapper; 16 KiB of
	// hex is far beyond any real one.
	maxSignatureHexLength = 16 << 10
)

// The plugin's table: one row per (wallet, chain), owned by one user.
const (
	TableNameWallet  = "auth_siwe_wallet"
	TableAliasWallet = "sw"
	ColID            = "id"
	ColUserID        = "user_id"
	// ColAddress is the normalized address: "0x" and 40 lower-case hex
	// digits (NormalizeAddress), so every spelling of a wallet is one row.
	ColAddress   = "address"
	ColChainID   = "chain_id"
	ColPrimary   = "is_primary"
	ColCreatedAt = "created_at"
	ColLastUsed  = "last_used_at"
)

// Typed columns, for an app that reads the table (reads are open; only the
// plugin writes it).
var (
	TableWallet     = sqlb.Table{Name: TableNameWallet, Alias: TableAliasWallet}
	WalletID        = sqlb.Col[string](TableWallet, ColID)
	WalletUserID    = sqlb.Col[string](TableWallet, ColUserID)
	WalletAddress   = sqlb.Col[string](TableWallet, ColAddress)
	WalletChainID   = sqlb.Col[int64](TableWallet, ColChainID)
	WalletPrimary   = sqlb.Col[bool](TableWallet, ColPrimary)
	WalletCreatedAt = sqlb.Col[time.Time](TableWallet, ColCreatedAt)
	WalletLastUsed  = sqlb.Col[*time.Time](TableWallet, ColLastUsed)
)

const (
	idPrefix         = "wlt"
	migrationWallet  = "0001_wallet"
	indexUserSuffix  = "_user_idx"
	uniqueAddrSuffix = "_address_chain"
)

// Errors the operations answer. None depends on whether a wallet has an
// account, so the answers reveal nothing about who has signed in before.
var (
	// ErrMessageInvalid is a message that is not ERC-4361, or whose address,
	// chain or nonce do not match the request.
	ErrMessageInvalid = auth.NewError("siwe.message_invalid", http.StatusBadRequest, "The sign-in message is not valid.")
	// ErrDomainInvalid is a message whose domain, scheme or URI is not this
	// app's: a message signed for another site, which a phishing page would
	// relay.
	ErrDomainInvalid = auth.NewError("siwe.domain_invalid", http.StatusBadRequest, "The sign-in message is for another site.")
	// ErrChainInvalid is a chain this app does not accept (Chains).
	ErrChainInvalid = auth.NewError("siwe.chain_invalid", http.StatusBadRequest, "This network is not accepted.")
	// ErrMessageExpired is a message outside its time window: issued in the
	// future, older than the nonce, past its Expiration Time or before its
	// Not Before.
	ErrMessageExpired = auth.NewError("siwe.message_expired", http.StatusBadRequest, "The sign-in message has expired or is not valid yet.")
	// ErrNonceInvalid is a nonce that is unknown, spent, expired, or was
	// issued for another wallet or chain.
	ErrNonceInvalid = auth.NewError("siwe.nonce_invalid", http.StatusBadRequest, "The sign-in request has expired. Please try again.")
	// ErrSignatureInvalid is a signature that is not the message address's.
	ErrSignatureInvalid = auth.NewError("siwe.signature_invalid", http.StatusUnauthorized, "The signature is not valid.")
	// ErrAddressInvalidInput is a walletAddress that is not an address.
	ErrAddressInvalidInput = auth.NewError("siwe.address_invalid", http.StatusBadRequest, "That is not an Ethereum address.")
	// ErrEmailRequired is a first sign-in without an email under
	// RequireEmail.
	ErrEmailRequired = auth.NewError("siwe.email_required", http.StatusBadRequest, "An email address is required to create the account.")
	// ErrEmailNotAccepted is an email given to an app without the email
	// plugin: there is nowhere to keep it, and dropping it silently would
	// hide a wiring mistake.
	ErrEmailNotAccepted = auth.NewError("siwe.email_not_accepted", http.StatusBadRequest, "This app does not take an email address here.")
	// ErrSignUpDisabled is a first sign-in under NoSignUp: only a wallet a
	// signed-in user linked can sign in.
	ErrSignUpDisabled = auth.NewError("siwe.sign_up_disabled", http.StatusForbidden, "This wallet is not linked to an account.")
	// ErrWalletLinkedElsewhere is a link of a wallet another user owns.
	ErrWalletLinkedElsewhere = auth.NewError("siwe.wallet_linked_elsewhere", http.StatusConflict, "This wallet belongs to another account.")
	// ErrWalletNotFound is an unlink of a wallet the caller does not own.
	ErrWalletNotFound = auth.NewError("siwe.wallet_not_found", http.StatusNotFound, "No such wallet.")
)

// Configuration errors auth.New returns.
var (
	// ErrNoOrigin is a configuration with neither auth.WithBaseURL nor
	// Origins: no message domain could ever match.
	ErrNoOrigin = errors.New("siwe: messages need auth.WithBaseURL or siwe.Origins to check their domain against")
	// ErrRequireEmailNoKind is RequireEmail without the email plugin.
	ErrRequireEmailNoKind = errors.New("siwe: RequireEmail needs the email plugin, which holds the address")
)

// NameResolver looks up a wallet's public name, such as its ENS name and
// avatar, for the profile of a user the plugin creates. It is optional and
// the app supplies it, because resolving ENS needs an RPC endpoint and the
// module ships no client. A lookup that fails is logged and the user is
// created without the name: a name service outage must not stop a sign-in.
type NameResolver interface {
	// LookupName returns the name of the normalized address on chainID, or
	// a zero WalletName when it has none.
	LookupName(ctx context.Context, address string, chainID int64) (WalletName, error)
}

// NameResolverFunc adapts a function to NameResolver.
type NameResolverFunc func(ctx context.Context, address string, chainID int64) (WalletName, error)

// LookupName calls f.
func (f NameResolverFunc) LookupName(ctx context.Context, address string, chainID int64) (WalletName, error) {
	return f(ctx, address, chainID)
}

// WalletName is a resolved name: the user's display name and image.
type WalletName struct {
	Name   string
	Avatar string
}

// Plugin is the Sign-In with Ethereum method. Build it with New.
type Plugin struct {
	// optErrs collects what the options found while they ran, such as a nil
	// Verifier (auth.ErrNilOption); see OptionErr.
	optErrs      auth.OptionErrors
	verifier     Verifier
	names        NameResolver
	requireEmail bool
	noSignUp     bool
	nonceTTL     time.Duration
	// origins, when set by Origins, replace the core's trusted origins as
	// the sites a message may name.
	origins map[string]bool
	// chains, when set by Chains, are the only chain ids accepted.
	chains map[int64]bool
	core   *auth.Auth

	nonce   *auth.Op[NonceRequest, NonceResult]
	verify  *auth.Op[VerifyRequest, SignInResult]
	link    *auth.Op[LinkRequest, Wallet]
	wallets *auth.Op[struct{}, WalletsResult]
	unlink  *auth.Op[UnlinkRequest, auth.Done]
}

// OptionErr is every error the options recorded; auth.New refuses to start
// while it is not nil (auth.OptionChecker).
func (p *Plugin) OptionErr() error { return p.optErrs.OptionErr() }

// Option configures the plugin; New applies them in order.
type Option func(*Plugin)

// RequireEmail makes a first sign-in carry an email address, stored
// unverified on the new user (better-auth's anonymous: false). Without it a
// wallet alone is an account. It needs the email plugin.
func RequireEmail() Option { return func(p *Plugin) { p.requireEmail = true } }

// NoSignUp lets only a wallet already linked to a user sign in: a first
// sign-in answers ErrSignUpDisabled. Users add wallets with POST /siwe/link
// after signing in another way.
func NoSignUp() Option { return func(p *Plugin) { p.noSignUp = true } }

// WithVerifier replaces PersonalSign, the EIP-191 recovery, as the check of
// a signature: for smart-contract wallets (EIP-1271, EIP-6492), which need
// the chain.
func WithVerifier(v Verifier) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("siwe.WithVerifier", v) {
			return
		}
		p.verifier = v
	}
}

// WithNameResolver looks up a new user's name and avatar, such as from ENS.
func WithNameResolver(r NameResolver) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("siwe.WithNameResolver", r) {
			return
		}
		p.names = r
	}
}

// WithNonceTTL replaces DefaultNonceTTL. It must be positive.
func WithNonceTTL(d time.Duration) Option {
	return func(p *Plugin) {
		if d <= 0 {
			p.optErrs.JoinOptionErr(fmt.Errorf("siwe.WithNonceTTL(%v): the lifetime must be positive", d))
			return
		}
		p.nonceTTL = d
	}
}

// Origins replaces the sites a message may be for. Each is an origin,
// "https://app.example.com": a message's URI must have one of these
// origins, its domain must be that origin's host and port, and its scheme,
// when it names one, that origin's scheme. By default the sites are the
// core's trusted origins (auth.Auth.TrustsOrigin: the BaseURL's origin,
// auth.WithTrustedOrigins and their patterns). Origins() with none keeps
// the default.
func Origins(origins ...string) Option {
	return func(p *Plugin) {
		for _, o := range origins {
			if o == "" || auth.OriginOf(o) != o {
				p.optErrs.JoinOptionErr(fmt.Errorf("siwe.Origins(%q): not an origin such as https://app.example.com", o))
				return
			}
		}
		if len(origins) == 0 {
			return
		}
		p.origins = map[string]bool{}
		for _, o := range origins {
			p.origins[o] = true
		}
	}
}

// Chains limits sign-in to these EIP-155 chain ids (1 is Ethereum mainnet).
// By default any chain is accepted, since the same key controls the same
// address on every chain; an app whose wallets are contracts on one chain
// should name it. Chains() with none keeps the default.
func Chains(ids ...int64) Option {
	return func(p *Plugin) {
		for _, id := range ids {
			if id <= 0 {
				p.optErrs.JoinOptionErr(fmt.Errorf("siwe.Chains(%d): a chain id is positive", id))
				return
			}
		}
		if len(ids) == 0 {
			return
		}
		p.chains = map[int64]bool{}
		for _, id := range ids {
			p.chains[id] = true
		}
	}
}

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

// New builds the plugin: personal_sign verification, any chain, the core's
// trusted origins, and a wallet alone may create an account.
func New(opts ...Option) *Plugin {
	p := &Plugin{verifier: PersonalSign{}, nonceTTL: DefaultNonceTTL}
	for _, o := range opts {
		o(p)
	}
	p.nonce = auth.Define(auth.OpInfo{ID: EndpointNonce, Kind: auth.Mutation, Require: auth.Public, Path: pathNonce}, p.doNonce)
	p.verify = auth.Define(auth.OpInfo{ID: EndpointVerify, Kind: auth.Mutation, Require: auth.Public, Path: pathVerify, SignIn: true}, p.doVerify)
	p.link = auth.Define(auth.OpInfo{ID: EndpointLink, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: pathLink}, p.doLink)
	p.wallets = auth.Define(auth.OpInfo{ID: EndpointWallets, Kind: auth.Query, Require: auth.SignedIn, Path: pathWallets}, p.doWallets)
	p.unlink = auth.Define(auth.OpInfo{ID: EndpointUnlink, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: pathUnlink}, p.doUnlink)
	return p
}

// Name returns PluginName.
func (p *Plugin) Name() string { return PluginName }

// SignsIn reports that a wallet is a way in, so an app with SIWE alone
// passes the core's "someone can sign in" check, and a user's last wallet
// cannot be unlinked while it is their only way in.
func (p *Plugin) SignsIn() bool { return true }

// Tables declares auth_siwe_wallet, so auth.New refuses another owner.
func (p *Plugin) Tables() []sqlb.Table { return []sqlb.Table{TableWallet} }

// UserTables declares that wallet rows belong to the user in user_id, so
// DeleteUser removes them.
func (p *Plugin) UserTables() []auth.UserTable {
	return []auth.UserTable{{Table: TableWallet, Column: ColUserID}}
}

// Operations lists nonce, verify, link, wallets and unlink.
func (p *Plugin) Operations() []auth.Operation {
	return []auth.Operation{p.nonce, p.verify, p.link, p.wallets, p.unlink}
}

// RateLimits bounds the two anonymous operations per IP: nonce, which writes
// a row, and verify, which recovers a signature.
func (p *Plugin) RateLimits() []auth.RateRule {
	return []auth.RateRule{
		{Match: EndpointNonce, Key: auth.ByIP, Limit: nonceIPLimit, Window: nonceIPWindow},
		{Match: EndpointVerify, Key: auth.ByIP, Limit: verifyIPLimit, Window: verifyIPWindow},
	}
}

// Validate refuses a configuration no message could pass: no site to check
// the domain against, or RequireEmail without the email plugin.
func (p *Plugin) Validate(c *auth.Config) error {
	if p.origins == nil && c.BaseURL == "" {
		return ErrNoOrigin
	}
	if p.requireEmail && !c.HasIdentifier(email.KindEmail) {
		return ErrRequireEmailNoKind
	}
	return nil
}

// Init keeps the core for the table name and the clock.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	return nil
}

// TypedMigrations creates auth_siwe_wallet: (address, chain_id) is unique, so
// one wallet on one chain belongs to one user, and user_id is indexed for
// the list. MySQL has no CREATE INDEX IF NOT EXISTS, so there the index is
// declared inside CREATE TABLE.
func (p *Plugin) TypedMigrations(engine string, t auth.SQLTypes) ([]auth.Migration, error) {
	if err := auth.CheckEngine(engine); err != nil {
		return nil, err
	}
	table := p.core.TableName(TableWallet)
	indexUser := table + indexUserSuffix
	create := "CREATE TABLE IF NOT EXISTS " + table + " (" +
		ColID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
		ColUserID + " " + t.ID + " NOT NULL, " +
		ColAddress + " " + t.Key + " NOT NULL, " +
		ColChainID + " " + t.Int + " NOT NULL, " +
		ColPrimary + " " + t.Bool + " NOT NULL, " +
		ColCreatedAt + " " + t.Timestamp + " NOT NULL, " +
		ColLastUsed + " " + t.Timestamp + " NULL, " +
		"CONSTRAINT " + table + uniqueAddrSuffix + " UNIQUE (" + ColAddress + ", " + ColChainID + ")"
	var st []string
	if engine == auth.EngineMySQL {
		st = []string{create + ", INDEX " + indexUser + " (" + ColUserID + "))" + t.TableSuffix}
	} else {
		st = []string{create + ")" + t.TableSuffix, "CREATE INDEX IF NOT EXISTS " + indexUser + " ON " + table + " (" + ColUserID + ")"}
	}
	return []auth.Migration{{Owner: PluginName, Name: migrationWallet, Statements: st}}, nil
}

// NonceRequest names the wallet and chain the nonce is for (better-auth's
// field names).
type NonceRequest struct {
	WalletAddress string `json:"walletAddress"`
	ChainID       int64  `json:"chainId"`
}

// NonceResult carries the nonce to put in the message.
type NonceResult struct {
	Nonce string `json:"nonce"`
}

// VerifyRequest is the signed message. WalletAddress and ChainID are
// optional (better-auth sends them); when given they must match the message.
// Email is the new user's address under RequireEmail, and is ignored when
// the wallet already has a user: a sign-in is not a place to edit an account.
type VerifyRequest struct {
	Message       string `json:"message"`
	Signature     string `json:"signature"`
	WalletAddress string `json:"walletAddress,omitempty"`
	ChainID       int64  `json:"chainId,omitempty"`
	Email         string `json:"email,omitempty"`
}

// LinkRequest is a signed message for the signed-in user's new wallet.
type LinkRequest struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

// UnlinkRequest names the wallet row to remove.
type UnlinkRequest struct {
	ID string `json:"id"`
}

// Wallet is one linked wallet on one chain. Address is the EIP-55
// checksummed form, as wallets display it.
type Wallet struct {
	ID         string     `json:"id"`
	Address    string     `json:"address"`
	ChainID    int64      `json:"chainId"`
	Primary    bool       `json:"primary"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
}

// WalletsResult lists the signed-in user's wallets, oldest first.
type WalletsResult struct {
	Wallets []Wallet `json:"wallets"`
}

// SignInResult is the output of verify. Token is for Go callers and bearer
// transports, never encoded into JSON.
type SignInResult struct {
	User auth.UserView `json:"user"`
	// Wallet is the wallet that signed.
	Wallet Wallet `json:"wallet"`
	// Created is true when this sign-in created the user.
	Created              bool       `json:"created"`
	SecondFactorRequired bool       `json:"secondFactorRequired"`
	Token                auth.Token `json:"-"`
}

// Nonce asks for a nonce for address on chainID, the typed form of POST
// /siwe/nonce.
func (p *Plugin) Nonce(ctx context.Context, address string, chainID int64) (string, error) {
	out, err := p.nonce.Call(ctx, NonceRequest{WalletAddress: address, ChainID: chainID})
	return out.Nonce, err
}

// Verify checks a signed message and signs its wallet's user in, the typed
// form of POST /siwe/verify.
func (p *Plugin) Verify(ctx context.Context, in VerifyRequest) (SignInResult, error) {
	return p.verify.Call(ctx, in)
}

// Link adds a signed message's wallet to the signed-in user.
func (p *Plugin) Link(ctx context.Context, in LinkRequest) (Wallet, error) {
	return p.link.Call(ctx, in)
}

// Wallets lists the signed-in user's wallets.
func (p *Plugin) Wallets(ctx context.Context) ([]Wallet, error) {
	out, err := p.wallets.Call(ctx, struct{}{})
	return out.Wallets, err
}

// Unlink removes one of the signed-in user's wallets.
func (p *Plugin) Unlink(ctx context.Context, id string) error {
	_, err := p.unlink.Call(ctx, UnlinkRequest{ID: id})
	return err
}

func (p *Plugin) doNonce(ctx context.Context, c *auth.Call, in NonceRequest) (NonceResult, error) {
	addr, err := NormalizeAddress(in.WalletAddress)
	if err != nil {
		return NonceResult{}, ErrAddressInvalidInput
	}
	if !p.chainAllowed(in.ChainID) {
		return NonceResult{}, ErrChainInvalid
	}
	raw := make([]byte, nonceBytes)
	// Since Go 1.24 Read cannot fail: a system with no randomness crashes
	// the program, so there is no error to return and no weaker nonce to
	// fall back to.
	_, _ = rand.Read(raw)
	nonce := hex.EncodeToString(raw)
	if err := c.Auth.IssueVerificationToken(ctx, PurposeNonce, nonceIdentifier(addr, in.ChainID), auth.Token(nonce), p.nonceTTL, ""); err != nil {
		return NonceResult{}, err
	}
	return NonceResult{Nonce: nonce}, nil
}

func nonceIdentifier(addr string, chainID int64) string {
	return addr + nonceIdentifierSeparator + strconv.FormatInt(chainID, 10)
}

func (p *Plugin) chainAllowed(id int64) bool {
	if id <= 0 {
		return false
	}
	return p.chains == nil || p.chains[id]
}

// checked is a message that passed every check, with its normalized address.
type checked struct {
	msg  Message
	addr string
}

// check verifies everything about a signed message, in the order that
// spends nothing on a message that is wrong anyway: the grammar, the site,
// the chain and the time window, then the signature, and only then the
// nonce, which it consumes. A failure after the consumption rolls the
// operation's transaction back, so the nonce is spent only by a sign-in
// that happened.
func (p *Plugin) check(ctx context.Context, c *auth.Call, text, signature string) (checked, error) {
	if len(signature) > maxSignatureHexLength {
		return checked{}, ErrSignatureInvalid
	}
	msg, err := ParseMessage(text)
	if err != nil {
		return checked{}, ErrMessageInvalid
	}
	// ParseMessage refused an address that does not normalize, so this
	// cannot fail; the address is normalized here to compare it, not to
	// validate it.
	addr, _ := NormalizeAddress(msg.Address)
	if !p.siteAllowed(c.Auth, msg) {
		return checked{}, ErrDomainInvalid
	}
	if !p.chainAllowed(msg.ChainID) {
		return checked{}, ErrChainInvalid
	}
	if err := p.checkTimes(c.Auth.Now(), msg); err != nil {
		return checked{}, err
	}
	sig, err := DecodeSignature(signature)
	if err != nil {
		return checked{}, ErrSignatureInvalid
	}
	if err := p.verifier.VerifySignature(ctx, SignedMessage{Text: text, Message: msg, Signature: sig}); err != nil {
		if errors.Is(err, ErrSignatureMismatch) {
			return checked{}, ErrSignatureInvalid
		}
		return checked{}, err
	}
	v, err := c.Auth.ConsumeVerification(ctx, PurposeNonce, auth.Token(msg.Nonce))
	if errors.Is(err, auth.ErrTokenInvalid) {
		return checked{}, ErrNonceInvalid
	}
	if err != nil {
		return checked{}, err
	}
	if v.Identifier != nonceIdentifier(addr, msg.ChainID) {
		return checked{}, ErrNonceInvalid
	}
	return checked{msg: msg, addr: addr}, nil
}

// siteAllowed is the phishing check: the URI's origin is one of the app's
// sites, the domain is that origin's host and port, and a scheme, when the
// message names one, is that origin's. A page on another site can get a
// person to sign a message for this one, so this site's name must be in the
// signed text, not only in the request.
func (p *Plugin) siteAllowed(a *auth.Auth, m Message) bool {
	u, err := url.Parse(m.URI)
	if err != nil || u.Host == "" {
		return false
	}
	origin := auth.OriginOf(m.URI)
	trusted := a.TrustsOrigin(origin)
	if p.origins != nil {
		trusted = p.origins[origin]
	}
	if !trusted || !strings.EqualFold(u.Host, m.Domain) {
		return false
	}
	return m.Scheme == "" || strings.EqualFold(m.Scheme, u.Scheme)
}

// checkTimes is the message's time window: issued no later than ClockSkew
// from now and no earlier than the nonce's lifetime ago, before its
// Expiration Time (with ClockSkew) and not before its Not Before (with
// ClockSkew).
func (p *Plugin) checkTimes(now time.Time, m Message) error {
	switch {
	case m.IssuedAt.After(now.Add(ClockSkew)):
		return ErrMessageExpired
	case m.IssuedAt.Before(now.Add(-p.nonceTTL - ClockSkew)):
		return ErrMessageExpired
	case m.ExpirationTime != nil && !now.Before(m.ExpirationTime.Add(ClockSkew)):
		return ErrMessageExpired
	case m.NotBefore != nil && now.Add(ClockSkew).Before(*m.NotBefore):
		return ErrMessageExpired
	}
	return nil
}

func (p *Plugin) doVerify(ctx context.Context, c *auth.Call, in VerifyRequest) (SignInResult, error) {
	if in.Email != "" && !c.Auth.Config().HasIdentifier(email.KindEmail) {
		return SignInResult{}, ErrEmailNotAccepted
	}
	ck, err := p.check(ctx, c, in.Message, in.Signature)
	if err != nil {
		return SignInResult{}, err
	}
	if in.WalletAddress != "" {
		if a, err := NormalizeAddress(in.WalletAddress); err != nil || a != ck.addr {
			return SignInResult{}, ErrMessageInvalid
		}
	}
	if in.ChainID != 0 && in.ChainID != ck.msg.ChainID {
		return SignInResult{}, ErrMessageInvalid
	}
	w, userID, err := p.walletFor(ctx, ck)
	if err != nil {
		return SignInResult{}, err
	}
	out := SignInResult{}
	if userID == "" {
		if w, userID, err = p.signUp(ctx, c, ck, in.Email); err != nil {
			return SignInResult{}, err
		}
		out.Created = true
	}
	u, err := c.Auth.User(ctx, userID)
	if err != nil {
		return SignInResult{}, err
	}
	sess, tok, err := c.Auth.CreateSession(ctx, userID, c.Client)
	if err != nil {
		return SignInResult{}, err
	}
	c.Effects.IssueSessionOf(sess, tok)
	out.User, out.Wallet, out.Token, out.SecondFactorRequired = auth.ViewOf(u), w, tok, sess.SecondFactorPending
	return out, nil
}

// walletFor finds the user a verified message signs in. The row for this
// address and chain is the answer; failing that, the same address on
// another chain is the same key and the same user, and gets a row for this
// chain. userID "" means no user has this address yet.
func (p *Plugin) walletFor(ctx context.Context, ck checked) (Wallet, string, error) {
	rows, err := p.listWallets(ctx, sqlb.Eq(WalletAddress, ck.addr))
	if err != nil || len(rows) == 0 {
		return Wallet{}, "", err
	}
	for _, r := range rows {
		if r.ChainID == ck.msg.ChainID {
			return r.Wallet, r.userID, p.touch(ctx, r.ID)
		}
	}
	userID := rows[0].userID
	w, err := p.insert(ctx, userID, ck.addr, ck.msg.ChainID, false)
	return w, userID, err
}

// signUp creates the user for a wallet nobody has: with the resolved name
// when a NameResolver is set, and with the email unverified when one is
// given. A verified owner of that email is told, as password sign-up does,
// and this sign-up still succeeds as a separate account, so the answer says
// nothing about who has one.
func (p *Plugin) signUp(ctx context.Context, c *auth.Call, ck checked, mail string) (Wallet, string, error) {
	if p.noSignUp {
		return Wallet{}, "", ErrSignUpDisabled
	}
	if p.requireEmail && mail == "" {
		return Wallet{}, "", ErrEmailRequired
	}
	var name WalletName
	if p.names != nil {
		n, err := p.names.LookupName(ctx, ck.addr, ck.msg.ChainID)
		if err != nil {
			c.Auth.Logger().Warn("siwe: name lookup failed; creating the user without it", "address", ck.addr, "error", err)
		} else {
			name = n
		}
	}
	u, err := c.Auth.CreateUser(ctx, auth.NewUser{Name: name.Name, Image: name.Avatar})
	if err != nil {
		return Wallet{}, "", err
	}
	if mail != "" {
		owner, err := c.Auth.FindIdentity(ctx, email.KindEmail, mail, true)
		switch {
		case err == nil:
			if err := c.Auth.Deliver(ctx, owner, auth.Message{Purpose: auth.PurposeSignUpAttempt}); err != nil && !errors.Is(err, auth.ErrNoDeliverer) {
				return Wallet{}, "", err
			}
		case !errors.Is(err, auth.ErrIdentityNotFound):
			return Wallet{}, "", err
		}
		if _, err := c.Auth.CreateIdentity(ctx, auth.NewIdentity{UserID: u.ID, Kind: email.KindEmail, Raw: mail}); err != nil {
			return Wallet{}, "", err
		}
	}
	w, err := p.insert(ctx, u.ID, ck.addr, ck.msg.ChainID, true)
	return w, u.ID, err
}

// doLink adds the message's wallet to the signed-in user. A wallet the user
// already has on this chain is answered as it is; one another user has is
// ErrWalletLinkedElsewhere, never moved.
func (p *Plugin) doLink(ctx context.Context, c *auth.Call, in LinkRequest) (Wallet, error) {
	ck, err := p.check(ctx, c, in.Message, in.Signature)
	if err != nil {
		return Wallet{}, err
	}
	rows, err := p.listWallets(ctx, sqlb.Eq(WalletAddress, ck.addr))
	if err != nil {
		return Wallet{}, err
	}
	for _, r := range rows {
		if r.userID != c.User.ID {
			return Wallet{}, ErrWalletLinkedElsewhere
		}
	}
	for _, r := range rows {
		if r.ChainID == ck.msg.ChainID {
			return r.Wallet, nil
		}
	}
	mine, err := p.listWallets(ctx, sqlb.Eq(WalletUserID, c.User.ID))
	if err != nil {
		return Wallet{}, err
	}
	return p.insert(ctx, c.User.ID, ck.addr, ck.msg.ChainID, len(mine) == 0)
}

func (p *Plugin) doWallets(ctx context.Context, c *auth.Call, _ struct{}) (WalletsResult, error) {
	rows, err := p.listWallets(ctx, sqlb.Eq(WalletUserID, c.User.ID))
	if err != nil {
		return WalletsResult{}, err
	}
	out := WalletsResult{Wallets: make([]Wallet, 0, len(rows))}
	for _, r := range rows {
		out.Wallets = append(out.Wallets, r.Wallet)
	}
	return out, nil
}

// doUnlink removes one of the caller's wallets, unless it is their last way
// in (auth.ErrLastSignInMethod). Another user's wallet id answers
// ErrWalletNotFound, the same as an id that does not exist.
func (p *Plugin) doUnlink(ctx context.Context, c *auth.Call, in UnlinkRequest) (auth.Done, error) {
	rows, err := p.listWallets(ctx, sqlb.Eq(WalletID, in.ID), sqlb.Eq(WalletUserID, c.User.ID))
	if err != nil {
		return auth.Done{}, err
	}
	if len(rows) == 0 {
		return auth.Done{}, ErrWalletNotFound
	}
	if err := c.Auth.CheckRemovable(ctx, c.User.ID, "", in.ID); err != nil {
		return auth.Done{}, err
	}
	del := sqlb.NewDelete(p.core.Dialect()).From(TableWallet).Where(sqlb.Eq(WalletID, in.ID), sqlb.Eq(WalletUserID, c.User.ID))
	_, err = p.core.Exec(ctx, del)
	return auth.Done{OK: true}, err
}

// SignInCredentials counts userID's wallets, leaving out exceptID, for the
// core's last-sign-in-method check.
func (p *Plugin) SignInCredentials(ctx context.Context, userID, exceptID string) (int, error) {
	rows, err := p.listWallets(ctx, sqlb.Eq(WalletUserID, userID))
	n := 0
	for _, r := range rows {
		if r.ID != exceptID {
			n++
		}
	}
	return n, err
}

// walletRow is a Wallet with its owner, which the API never returns.
type walletRow struct {
	Wallet
	userID string
}

// listWallets returns the rows matching where, oldest first.
func (p *Plugin) listWallets(ctx context.Context, where ...sqlb.Predicate) ([]walletRow, error) {
	var row walletRow
	var addr string
	sel := p.core.Select().Columns(
		sqlb.Bind(WalletID, &row.ID), sqlb.Bind(WalletUserID, &row.userID), sqlb.Bind(WalletAddress, &addr),
		sqlb.Bind(WalletChainID, &row.ChainID), sqlb.Bind(WalletPrimary, &row.Primary),
		sqlb.Bind(WalletCreatedAt, &row.CreatedAt), sqlb.Bind(WalletLastUsed, &row.LastUsedAt),
	).From(TableWallet).Where(where...).Order(sqlb.OrderBy(WalletCreatedAt, sqlb.SortAsc), sqlb.OrderBy(WalletID, sqlb.SortAsc))
	var out []walletRow
	err := p.core.Each(ctx, sel, func() error {
		r := row
		r.Address = ChecksumAddress(addr)
		out = append(out, r)
		return nil
	})
	return out, err
}

// insert stores a wallet row. A concurrent sign-in that inserted the same
// (address, chain) first is ErrWalletLinkedElsewhere: the unique key decided.
func (p *Plugin) insert(ctx context.Context, userID, addr string, chainID int64, primary bool) (Wallet, error) {
	id, err := p.core.NewID(idPrefix)
	if err != nil {
		return Wallet{}, err
	}
	now := p.core.Now()
	ins := sqlb.NewInsert(p.core.Dialect()).Into(TableWallet).Row(
		sqlb.Set(WalletID, id), sqlb.Set(WalletUserID, userID), sqlb.Set(WalletAddress, addr),
		sqlb.Set(WalletChainID, chainID), sqlb.Set(WalletPrimary, primary), sqlb.Set(WalletCreatedAt, now),
		sqlb.Set(WalletLastUsed, &now),
	)
	if _, err := p.core.Exec(ctx, ins); err != nil {
		if auth.IsUniqueViolation(err) {
			return Wallet{}, ErrWalletLinkedElsewhere
		}
		return Wallet{}, err
	}
	return Wallet{ID: id, Address: ChecksumAddress(addr), ChainID: chainID, Primary: primary, CreatedAt: now, LastUsedAt: &now}, nil
}

// touch records a sign-in's time on the wallet row.
func (p *Plugin) touch(ctx context.Context, id string) error {
	now := p.core.Now()
	upd := sqlb.NewUpdate(p.core.Dialect()).Table(TableWallet).Set(sqlb.Set(WalletLastUsed, &now)).Where(sqlb.Eq(WalletID, id))
	_, err := p.core.Exec(ctx, upd)
	return err
}
