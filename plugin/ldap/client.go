package ldap

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
)

// URL schemes the Client dials.
const (
	SchemeLDAP  = "ldap"
	SchemeLDAPS = "ldaps"
)

// UsernamePlaceholder is replaced in Config.UserFilter by the username,
// escaped for a filter (RFC 4515), so a username such as "*" or "a)(uid=*"
// matches only itself.
const UsernamePlaceholder = "{username}"

// DefaultUserFilter finds a person by uid, the attribute OpenLDAP, 389-DS,
// FreeIPA and lldap use for the login name. Active Directory uses
// "(&(objectClass=user)(sAMAccountName={username}))".
const DefaultUserFilter = "(&(objectClass=person)(uid=" + UsernamePlaceholder + "))"

// DefaultTimeout bounds each directory call (dial, bind, search). A sign-in
// that waits longer has failed for the person anyway, and an unbounded call
// would let a hung server pile up requests.
const DefaultTimeout = 10 * time.Second

// DefaultAttributes are read from the user's entry: every user attribute,
// and entryUUID, the stable id OpenLDAP and lldap keep as an operational
// attribute, which "*" leaves out.
var DefaultAttributes = []string{"*", "entryUUID"}

// Errors NewClient returns for a configuration that could never sign anyone
// in safely.
var (
	ErrConfigURL = errors.New("ldap: Config.URL must be ldap://host[:port] or ldaps://host[:port]")
	// ErrInsecure refuses a plain ldap:// URL without StartTLS: the password
	// would cross the network in clear text. AllowInsecure accepts it, for a
	// test server on the same machine.
	ErrInsecure = errors.New("ldap: ldap:// without StartTLS sends passwords in clear text; use ldaps://, set StartTLS, or set AllowInsecure for a local test server")
	// ErrConfigTLS is StartTLS on an ldaps:// URL, which is already TLS.
	ErrConfigTLS    = errors.New("ldap: StartTLS is for ldap:// URLs; ldaps:// is TLS from the start")
	ErrConfigBaseDN = errors.New("ldap: Config.BaseDN is required")
	ErrConfigFilter = errors.New("ldap: Config.UserFilter must contain " + UsernamePlaceholder)
	// ErrConfigBindPassword is a BindDN without a password: an
	// unauthenticated bind, which most servers accept and which then
	// searches as nobody.
	ErrConfigBindPassword = errors.New("ldap: Config.BindDN needs BindPassword; leave both empty to search anonymously")
)

// Config configures the Client.
type Config struct {
	// URL is the server: ldaps://ldap.example.com (port 636) or
	// ldap://ldap.example.com (port 389) with StartTLS.
	URL string
	// StartTLS upgrades an ldap:// connection to TLS before anything is
	// sent. Required for ldap:// unless AllowInsecure.
	StartTLS bool
	// TLS is the TLS configuration for ldaps:// and StartTLS. Nil means the
	// system roots, the URL's host as the server name, and TLS 1.2 or later.
	// Set RootCAs here for a directory with a private CA; never
	// InsecureSkipVerify outside a test.
	TLS *tls.Config
	// AllowInsecure accepts ldap:// without StartTLS. Only for a test server
	// on the same machine: the password crosses the wire in clear text.
	AllowInsecure bool
	// BindDN and BindPassword are the service account that searches for the
	// user. Empty searches anonymously, which many directories refuse.
	BindDN       string
	BindPassword string
	// BaseDN is where the user search starts, such as
	// "ou=people,dc=example,dc=com". Required.
	BaseDN string
	// UserFilter finds the user; UsernamePlaceholder is replaced by the
	// escaped username. Empty means DefaultUserFilter. Put access rules here
	// too: "(&(uid={username})(memberOf=cn=staff,ou=groups,dc=example,dc=com))"
	// lets only staff sign in, and everyone else gets the same answer as a
	// wrong password.
	UserFilter string
	// Attributes are read from the user's entry. Nil means
	// DefaultAttributes.
	Attributes []string
	// Timeout bounds each call; zero means DefaultTimeout.
	Timeout time.Duration
}

// Client is the default Directory, over github.com/go-ldap/ldap. Each
// Authenticate opens a connection, upgrades it to TLS, binds the service
// account, searches for the user, binds as the user, and closes: no pool
// and no state between sign-ins, so a password change or a disabled account
// takes effect at the next sign-in. An app that signs in many users a
// second can put its own pooled Directory in its place.
type Client struct {
	cfg    Config
	tls    *tls.Config
	dialer func(ctx context.Context) (conn, error)
}

var _ Directory = (*Client)(nil)

// conn is the part of *goldap.Conn the Client uses; tests replace it.
type conn interface {
	StartTLS(*tls.Config) error
	Bind(username, password string) error
	Search(*goldap.SearchRequest) (*goldap.SearchResult, error)
	Close() error
}

// NewClient checks cfg and returns the Client. TLS is required unless
// AllowInsecure: an ldaps:// URL, or ldap:// with StartTLS.
func NewClient(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Hostname() == "" || (u.Scheme != SchemeLDAP && u.Scheme != SchemeLDAPS) || (u.Path != "" && u.Path != "/") {
		return nil, ErrConfigURL
	}
	switch {
	case u.Scheme == SchemeLDAPS && cfg.StartTLS:
		return nil, ErrConfigTLS
	case u.Scheme == SchemeLDAP && !cfg.StartTLS && !cfg.AllowInsecure:
		return nil, ErrInsecure
	case strings.TrimSpace(cfg.BaseDN) == "":
		return nil, ErrConfigBaseDN
	case cfg.BindDN != "" && cfg.BindPassword == "":
		return nil, ErrConfigBindPassword
	}
	if cfg.UserFilter == "" {
		cfg.UserFilter = DefaultUserFilter
	}
	if !strings.Contains(cfg.UserFilter, UsernamePlaceholder) {
		return nil, ErrConfigFilter
	}
	if cfg.Attributes == nil {
		cfg.Attributes = DefaultAttributes
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	tc := cfg.TLS
	if tc == nil {
		tc = &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}
	}
	c := &Client{cfg: cfg, tls: tc}
	c.dialer = c.dial
	return c, nil
}

// dial opens a go-ldap connection with the configured timeout, TLS from
// the start for ldaps://.
func (c *Client) dial(ctx context.Context) (conn, error) {
	d := &net.Dialer{Timeout: c.cfg.Timeout}
	lc, err := goldap.DialURL(c.cfg.URL, goldap.DialWithDialer(d), goldap.DialWithTLSConfig(c.tls))
	if err != nil {
		return nil, err
	}
	lc.SetTimeout(c.cfg.Timeout)
	return lc, nil
}

// decoyRDNBytes of randomness name the decoy entry an unknown user's
// password is bound against, so no real entry can be hit.
const decoyRDNBytes = 16

// searchSizeLimit is 2: one entry is the user, a second proves the filter
// ambiguous, and more would be work for nothing.
const searchSizeLimit = 2

// Authenticate checks the password with a bind as the user's entry and
// returns the entry. See Directory for the contract it keeps: an unknown
// user binds a decoy DN under BaseDN with the password, so it costs the
// same search and bind as a wrong password and answers the same
// ErrInvalidCredentials.
func (c *Client) Authenticate(ctx context.Context, username, password string) (Entry, error) {
	if password == "" || username == "" {
		return Entry{}, ErrInvalidCredentials
	}
	lc, err := c.dialer(ctx)
	if err != nil {
		return Entry{}, fmt.Errorf("ldap: dial: %w", err)
	}
	defer lc.Close()
	// A request cancelled mid-call closes the connection, which fails the
	// call in progress instead of waiting out the timeout.
	stop := context.AfterFunc(ctx, func() { _ = lc.Close() })
	defer stop()

	if c.cfg.StartTLS {
		if err := lc.StartTLS(c.tls); err != nil {
			return Entry{}, fmt.Errorf("ldap: start TLS: %w", err)
		}
	}
	if c.cfg.BindDN != "" {
		if err := lc.Bind(c.cfg.BindDN, c.cfg.BindPassword); err != nil {
			return Entry{}, fmt.Errorf("ldap: service account bind: %w", err)
		}
	}
	filter := strings.ReplaceAll(c.cfg.UserFilter, UsernamePlaceholder, goldap.EscapeFilter(username))
	req := goldap.NewSearchRequest(c.cfg.BaseDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases, searchSizeLimit, int(c.cfg.Timeout/time.Second), false, filter, c.cfg.Attributes, nil)
	res, err := lc.Search(req)
	ambiguous := goldap.IsErrorWithCode(err, goldap.LDAPResultSizeLimitExceeded)
	if err != nil && !ambiguous {
		return Entry{}, fmt.Errorf("ldap: search: %w", err)
	}
	if ambiguous || res == nil || len(res.Entries) != 1 {
		c.decoyBind(lc, password)
		if ambiguous || (res != nil && len(res.Entries) > 1) {
			return Entry{}, ErrAmbiguousUser
		}
		return Entry{}, ErrInvalidCredentials
	}
	found := res.Entries[0]
	if err := lc.Bind(found.DN, password); err != nil {
		if goldap.IsErrorWithCode(err, goldap.LDAPResultInvalidCredentials) {
			return Entry{}, ErrInvalidCredentials
		}
		return Entry{}, fmt.Errorf("ldap: user bind: %w", err)
	}
	return entryOf(found), nil
}

// decoyBind binds a random DN under BaseDN with the password and ignores the
// answer: the round trip an unknown user would otherwise skip, so its
// sign-in takes as long as a wrong password's.
func (c *Client) decoyBind(lc conn, password string) {
	raw := make([]byte, decoyRDNBytes)
	_, _ = rand.Read(raw)
	_ = lc.Bind("cn="+hex.EncodeToString(raw)+","+c.cfg.BaseDN, password)
}

// entryOf copies a go-ldap entry into the module's Entry.
func entryOf(e *goldap.Entry) Entry {
	out := Entry{DN: e.DN, Attributes: make(map[string][]string, len(e.Attributes))}
	for _, a := range e.Attributes {
		out.Attributes[a.Name] = append([]string(nil), a.Values...)
	}
	return out
}
