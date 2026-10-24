package oauthprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// CIMD (OAuth Client ID Metadata Document): a client_id that is an https
// URL names a JSON document the client publishes about itself. The
// provider fetches it on first use, keeps it as a client row, and fetches
// it again when it is older than the revalidation interval.
const (
	// discoveryCIMD marks a client row created from a metadata document.
	discoveryCIMD = "cimd"
	// DefaultCIMDRevalidate is how long a fetched document is trusted
	// before it is fetched again.
	//ds:def id=oauthprovider-defaultcimdrevalidate-h3w8kq5n owner=@khanakia stability=stable
	DefaultCIMDRevalidate = time.Hour
	// cimdTimeout bounds one fetch.
	cimdTimeout = 5 * time.Second
	// cimdMaxBytes is the largest document accepted, 5 KB.
	cimdMaxBytes = 5 << 10
	// mediaTypeJSON and mediaSuffixJSON are the accepted content types:
	// application/json and application/*+json.
	mediaTypeJSON   = "application/json"
	mediaSuffixJSON = "+json"
	mediaPrefixApp  = "application/"
)

// ErrCIMDFetch is a metadata document that could not be fetched or is not
// acceptable; every such failure is answered invalid_client.
var ErrCIMDFetch = errors.New("oauthprovider: client metadata document refused")

// cimdForbidden are members a document may not set: they are the server's
// to decide, so a document claiming one is refused rather than trusted.
var cimdForbidden = []string{
	"client_secret", "client_secret_expires_at", "client_id_issued_at", "skip_consent", "enable_end_session",
	"require_pkce", "reference_id", "user_id", "resources", "introspect_any", "backchannel_logout_uri",
	"backchannel_logout_session_required",
	// The camel-case spellings of the same members: a document written for a
	// camel-case server must not slip one past.
	"clientSecret", "clientSecretExpiresAt", "clientIdIssuedAt", "skipConsent", "enableEndSession",
	"requirePkce", "requirePKCE", "referenceId", "userId", "introspectAny", "backchannelLogoutUri",
	"backchannelLogoutSessionRequired", "client_credentials_scopes", "clientCredentialsScopes",
}

// CIMDFetcher fetches a metadata document's bytes. The default refuses
// every address that is not public (RFC 6890 special-purpose ranges),
// dials the address it checked rather than resolving twice, follows no
// redirect, gives up after 5 seconds, and reads at most 5 KB of an exactly
// 200 application/json answer. Replace it only for tests, or for an
// egress proxy that enforces the same rules.
type CIMDFetcher func(ctx context.Context, rawURL string) ([]byte, error)

type cimdConfig struct {
	// optErrs collects the CIMD options given nil (auth.ErrNilOption);
	// ClientIDMetadataDocuments passes them to the plugin's OptionErr.
	optErrs auth.OptionErrors
	// originFields are CIMDOriginBoundFields; nil is the default pair.
	originFields []string
	transport    func(ctx context.Context, rawURL string, conditional http.Header) (CIMDResponse, error)
	revalidate   time.Duration
	allow        func(clientID string) bool
	mcpProfile   bool
	policy       CIMDFetchPolicy
	maxEntries   int
	onCreated    func(ctx context.Context, c Client, document json.RawMessage)
	onRefreshed  func(ctx context.Context, c, previous Client, document json.RawMessage)
	gov          governor
}

// CIMDOption configures ClientIDMetadataDocuments.
type CIMDOption func(*cimdConfig)

// CIMDRevalidate overrides DefaultCIMDRevalidate.
func CIMDRevalidate(d time.Duration) CIMDOption { return func(c *cimdConfig) { c.revalidate = d } }

// CIMDFetch replaces the fetcher; see CIMDFetcher.
func CIMDFetch(f CIMDFetcher) CIMDOption {
	return func(c *cimdConfig) {
		if c.optErrs.RefuseNil("oauthprovider.CIMDFetch", f) {
			return
		}
		c.transport = byteTransport(f)
	}
}

// CIMDAllow is a policy gate run before any fetch: false refuses the
// client_id (invalid_client).
func CIMDAllow(fn func(clientID string) bool) CIMDOption {
	return func(c *cimdConfig) {
		if c.optErrs.RefuseNil("oauthprovider.CIMDAllow", fn) {
			return
		}
		c.allow = fn
	}
}

// CIMDProfileMCP requires client_name and redirect_uris, as the MCP
// specification's pinned CIMD draft (2026-07-28) does.
func CIMDProfileMCP() CIMDOption { return func(c *cimdConfig) { c.mcpProfile = true } }

// CIMD origin-bound fields: the document members CIMDOriginBoundFields may
// name.
const (
	CIMDFieldClientURI      = "client_uri"
	CIMDFieldLogoURI        = "logo_uri"
	CIMDFieldTosURI         = "tos_uri"
	CIMDFieldPolicyURI      = "policy_uri"
	CIMDFieldRedirectURIs   = "redirect_uris"
	CIMDFieldPostLogoutURIs = "post_logout_redirect_uris"
)

// DefaultCIMDOriginBoundFields are the default origin-bound fields:
// redirect URIs are left out because exact matching at authorize already
// binds them, and native clients redirect to another origin than their
// document's.
var DefaultCIMDOriginBoundFields = []string{CIMDFieldPostLogoutURIs, CIMDFieldClientURI}

// cimdOriginFieldNames are every field CIMDOriginBoundFields accepts.
var cimdOriginFieldNames = []string{CIMDFieldClientURI, CIMDFieldLogoURI, CIMDFieldTosURI, CIMDFieldPolicyURI, CIMDFieldRedirectURIs, CIMDFieldPostLogoutURIs}

// ErrBadCIMDField is a CIMDOriginBoundFields name that is not one of the
// CIMDField constants; auth.New fails with it.
var ErrBadCIMDField = errors.New("oauthprovider: CIMDOriginBoundFields names a field that is not a URL member of a client metadata document")

// CIMDOriginBoundFields replaces DefaultCIMDOriginBoundFields: every URL in
// these members must be on the client_id's origin (a loopback host and a
// private-use scheme are allowed in the two redirect fields). No fields turns
// origin binding off, which lets a document claim another site's pages; the
// jwks_uri is bound whatever this says.
func CIMDOriginBoundFields(fields ...string) CIMDOption {
	return func(c *cimdConfig) { c.originFields = append([]string{}, fields...) }
}

// ClientIDMetadataDocuments accepts client ids that are https URLs of
// client metadata documents. Off by default: it makes the provider fetch
// URLs a caller chooses, which the default fetcher confines to public
// addresses.
func ClientIDMetadataDocuments(opts ...CIMDOption) Option {
	return func(p *Plugin) {
		if auth.RefuseNilEach(&p.optErrs, "oauthprovider.ClientIDMetadataDocuments", opts) {
			return
		}
		c := &cimdConfig{transport: fetchPublic, revalidate: DefaultCIMDRevalidate,
			gov: governor{perOrigin: map[string]int{}, originWin: map[string][]time.Time{}, lastFailed: map[string]time.Time{}, flights: map[string]*flight{}}}
		for _, o := range opts {
			o(c)
		}
		p.optErrs.JoinOptionErr(c.optErrs.OptionErr())
		p.cimd = c
	}
}

// isCIMDCandidate reports whether a client_id is shaped like a metadata
// document URL; generated client ids never are, so a registered client is
// never taken over by a document.
func isCIMDCandidate(id string) bool { return strings.HasPrefix(id, schemeHTTPS+"://") }

// validClientIDURL applies the CIMD section 3 rules: https, a host, a path
// other than "/", no dot segments, no fragment, no user information.
func validClientIDURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != schemeHTTPS || u.Host == "" || u.User != nil || u.Fragment != "" || strings.Contains(raw, "#") {
		return false
	}
	if u.Path == "" || u.Path == "/" {
		return false
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// cimdClient returns the client a document URL names. A stored document
// that is still fresh (its HTTP lifetime, capped by the revalidation
// interval) is used as is and spends no fetch budget; otherwise it is
// fetched, conditionally when validators are stored. Requests for a URL
// already being fetched join that fetch. A failed fetch refuses the request
// (fail closed) and leaves any stored row as it was.
func (p *Plugin) cimdClient(ctx context.Context, id string, existing *clientRow) (clientRow, error) {
	now := p.core.Now()
	if existing != nil && existing.cimdExpires != nil && now.Before(*existing.cimdExpires) {
		return *existing, nil
	}
	if !validClientIDURL(id) || (p.cimd.allow != nil && !p.cimd.allow(id)) {
		return clientRow{}, ErrClientNotFound
	}
	g := &p.cimd.gov
	g.mu.Lock()
	if f, ok := g.flights[id]; ok {
		g.mu.Unlock()
		select {
		case <-f.done:
			return f.row, f.err
		case <-ctx.Done():
			return clientRow{}, ctx.Err()
		}
	}
	f := &flight{done: make(chan struct{})}
	g.flights[id] = f
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		delete(g.flights, id)
		g.mu.Unlock()
		close(f.done)
	}()
	f.row, f.err = p.fetchCIMD(ctx, id, existing)
	return f.row, f.err
}

// fetchCIMD fetches (or revalidates) a document under the governor and
// stores the result.
func (p *Plugin) fetchCIMD(ctx context.Context, id string, existing *clientRow) (clientRow, error) {
	release, err := p.admit(id)
	if err != nil {
		return clientRow{}, err
	}
	failed := true
	defer func() { release(failed) }()
	res, err := p.cimd.transport(ctx, id, conditional(existing))
	if err != nil {
		p.core.Logger().Warn("oauthprovider: client metadata document", "client_id", id, "error", err)
		return clientRow{}, ErrClientNotFound
	}
	now := p.core.Now()
	exp := now.Add(freshness(res.Header, p.cimd.revalidate, now))
	etag, lastMod := optional(res.Header.Get(headerETag)), optional(res.Header.Get(headerLastModified))
	if res.Status == http.StatusNotModified {
		// A 304 is accepted only for a stored document that had validators.
		if existing == nil || (deref(existing.cimdETag) == "" && deref(existing.cimdLastMod) == "") {
			return clientRow{}, ErrClientNotFound
		}
		if etag == nil {
			etag = existing.cimdETag
		}
		if lastMod == nil {
			lastMod = existing.cimdLastMod
		}
		if err := p.stampCIMD(ctx, id, now, exp, etag, lastMod); err != nil {
			return clientRow{}, err
		}
		failed = false
		return p.loadCIMDRow(ctx, id)
	}
	body, err := checkDocument(res)
	if err != nil {
		p.core.Logger().Warn("oauthprovider: client metadata document", "client_id", id, "error", err)
		return clientRow{}, ErrClientNotFound
	}
	m, err := p.parseCIMD(id, body)
	if err != nil {
		p.core.Logger().Warn("oauthprovider: client metadata document refused", "client_id", id, "error", err)
		return clientRow{}, ErrClientNotFound
	}
	var previous Client
	if existing == nil {
		_, err = p.insertClient(ctx, ClientSpec{ClientMetadata: m, id: id, discovery: discoveryCIMD, fetchedAt: &now})
		if err != nil && !auth.IsUniqueViolation(err) {
			return clientRow{}, err
		}
	} else {
		previous = existing.client()
		if err := p.refreshCIMD(ctx, id, m, now); err != nil {
			return clientRow{}, err
		}
	}
	if err := p.stampCIMD(ctx, id, now, exp, etag, lastMod); err != nil {
		return clientRow{}, err
	}
	r, err := p.loadCIMDRow(ctx, id)
	if err != nil {
		return clientRow{}, err
	}
	failed = false
	doc := json.RawMessage(body)
	if existing == nil && p.cimd.onCreated != nil {
		p.safeHook("onClientCreated", func() { p.cimd.onCreated(ctx, r.client(), doc) })
	}
	if existing != nil && p.cimd.onRefreshed != nil {
		p.safeHook("onClientRefreshed", func() { p.cimd.onRefreshed(ctx, r.client(), previous, doc) })
	}
	return r, nil
}

// stampCIMD records when a document was fetched, until when it is fresh,
// and its validators.
func (p *Plugin) stampCIMD(ctx context.Context, id string, now, exp time.Time, etag, lastMod *string) error {
	_, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableClient).Set(
		sqlb.Set(ClientFetchedAt, &now), sqlb.Set(ClientCIMDExpires, &exp), sqlb.Set(ClientCIMDETag, etag), sqlb.Set(ClientCIMDLastMod, lastMod),
	).Where(sqlb.Eq(ClientIDCol, id), sqlb.Eq(ClientDiscovery, optional(discoveryCIMD))))
	return err
}

func (p *Plugin) loadCIMDRow(ctx context.Context, id string) (clientRow, error) {
	var r clientRow
	err := p.core.One(ctx, p.core.Select().Columns(r.bindings()...).From(TableClient).Where(sqlb.Eq(ClientIDCol, id)))
	return r, err
}

// refreshCIMD replaces a document client's metadata with the fetched one.
func (p *Plugin) refreshCIMD(ctx context.Context, id string, m ClientMetadata, now time.Time) error {
	return p.refreshDiscovered(ctx, id, discoveryCIMD, m, now)
}

// refreshDiscovered replaces a discovered client's metadata (kind is its
// discovery) with a newly resolved one.
func (p *Plugin) refreshDiscovered(ctx context.Context, id, kind string, m ClientMetadata, now time.Time) error {
	checked, err := p.checkMetadata(m)
	if err != nil {
		return ErrClientNotFound
	}
	_, err = p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableClient).Set(
		sqlb.Set(ClientName, checked.Name), sqlb.Set(ClientRedirs, strings.Join(checked.RedirectURIs, redirectSeparator)),
		sqlb.Set(ClientScopes, checked.Scope), sqlb.Set(ClientGrants, strings.Join(checked.GrantTypes, listSeparator)),
		sqlb.Set(ClientMethod, checked.AuthMethod), sqlb.Set(ClientURI, optional(checked.ClientURI)), sqlb.Set(ClientLogo, optional(checked.LogoURI)),
		sqlb.Set(ClientContact, optional(strings.Join(checked.Contacts, listSeparator))), sqlb.Set(ClientTos, optional(checked.TosURI)),
		sqlb.Set(ClientPolicy, optional(checked.PolicyURI)), sqlb.Set(ClientPostLogout, optional(strings.Join(checked.PostLogoutRedirectURIs, redirectSeparator))),
		sqlb.Set(ClientJWKS, optional(string(checked.JWKS))), sqlb.Set(ClientJWKSURI, optional(checked.JWKSURI)), sqlb.Set(ClientUpdated, now), sqlb.Set(ClientFetchedAt, &now),
	).Where(sqlb.Eq(ClientIDCol, id), sqlb.Eq(ClientDiscovery, optional(kind))))
	return err
}

// parseCIMD validates a document: a JSON object whose client_id is exactly
// the URL it was fetched from, with no server-controlled member, a public
// authentication method (none, or private_key_jwt with inline jwks), and
// URLs that belong to the client: client_uri and post-logout URIs on the
// client_id's origin (loopback allowed for post-logout). Unknown members
// are ignored.
func (p *Plugin) parseCIMD(id string, body []byte) (ClientMetadata, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return ClientMetadata{}, fmt.Errorf("%w: not a JSON object", ErrCIMDFetch)
	}
	for _, f := range cimdForbidden {
		if _, ok := raw[f]; ok {
			return ClientMetadata{}, fmt.Errorf("%w: member %q is the server's", ErrCIMDFetch, f)
		}
	}
	var doc struct {
		ClientID string `json:"client_id"`
		ClientMetadata
	}
	if err := json.Unmarshal(body, &doc); err != nil || doc.ClientID != id {
		return ClientMetadata{}, fmt.Errorf("%w: client_id does not equal the document URL", ErrCIMDFetch)
	}
	m := doc.ClientMetadata
	if m.ApplicationType == "" {
		// A document without a type is held to the union of web
		// and native redirect forms, which is the native rules.
		m.ApplicationType = appTypeNative
	}
	if m.AuthMethod == "" {
		m.AuthMethod = AuthMethodNone
	}
	if m.AuthMethod != AuthMethodNone && m.AuthMethod != AuthMethodPrivateKeyJWT {
		return ClientMetadata{}, fmt.Errorf("%w: a document client cannot hold a shared secret", ErrCIMDFetch)
	}
	if p.cimd.mcpProfile && (strings.TrimSpace(m.Name) == "" || len(m.RedirectURIs) == 0) {
		return ClientMetadata{}, fmt.Errorf("%w: client_name and redirect_uris are required", ErrCIMDFetch)
	}
	origin := originOfURL(id)
	m.cimdOrigin = origin
	if err := p.checkOriginBound(m, origin); err != nil {
		return ClientMetadata{}, err
	}
	return p.cimdGrants(m)
}

// cimdFieldValues are the URLs of one origin-bound field.
func cimdFieldValues(m ClientMetadata, field string) []string {
	switch field {
	case CIMDFieldRedirectURIs:
		return m.RedirectURIs
	case CIMDFieldPostLogoutURIs:
		return m.PostLogoutRedirectURIs
	}
	one := map[string]string{CIMDFieldClientURI: m.ClientURI, CIMDFieldLogoURI: m.LogoURI, CIMDFieldTosURI: m.TosURI, CIMDFieldPolicyURI: m.PolicyURI}[field]
	if one == "" {
		return nil
	}
	return []string{one}
}

// checkOriginBound holds the origin-bound fields to the client_id's origin.
func (p *Plugin) checkOriginBound(m ClientMetadata, origin string) error {
	fields := p.cimd.originFields
	if fields == nil {
		fields = DefaultCIMDOriginBoundFields
	}
	for _, f := range fields {
		redirect := f == CIMDFieldRedirectURIs || f == CIMDFieldPostLogoutURIs
		for _, u := range cimdFieldValues(m, f) {
			pu, err := url.Parse(u)
			if redirect && err == nil && pu.Scheme == schemeHTTP && isLoopback(pu.Hostname()) {
				continue
			}
			if redirect && err == nil && pu.Scheme != schemeHTTPS && pu.Scheme != schemeHTTP {
				continue // a private-use scheme names no origin
			}
			if originOfURL(u) != origin {
				return fmt.Errorf("%w: %s is on another origin", ErrCIMDFetch, f)
			}
		}
	}
	return nil
}

// redirectGrants are the grants that end at a redirect URI; refreshOnly is
// the one that only continues one of them.
var (
	redirectGrants = []string{GrantAuthorizationCode, GrantRefreshToken}
	refreshOnly    = []string{GrantRefreshToken}
)

// cimdGrants applies the grant union to a document: the grants
// it declares that this provider serves (one is enough), and, outside the
// MCP profile, a document with no redirect URIs keeps only the grants that
// need none, since it can never complete an authorization.
func (p *Plugin) cimdGrants(m ClientMetadata) (ClientMetadata, error) {
	declared := m.GrantTypes
	if len(declared) == 0 {
		declared = []string{GrantAuthorizationCode, GrantRefreshToken}
	}
	served := p.servedGrants()
	var kept []string
	for _, g := range declared {
		needsRedirect := slices.Contains(redirectGrants, g)
		if slices.Contains(served, g) && (len(m.RedirectURIs) > 0 || !needsRedirect) {
			kept = append(kept, g)
		}
	}
	if slices.Contains(kept, GrantRefreshToken) && !slices.Contains(kept, GrantAuthorizationCode) {
		kept = slices.DeleteFunc(kept, func(g string) bool { return slices.Contains(refreshOnly, g) })
	}
	if len(kept) == 0 {
		return ClientMetadata{}, fmt.Errorf("%w: no grant this provider serves", ErrCIMDFetch)
	}
	m.GrantTypes = kept
	return m, nil
}

// IsCIMDClientID reports whether a client_id is shaped like a client
// metadata document URL: an https URL. Generated client ids never are.
func IsCIMDClientID(id string) bool { return isCIMDCandidate(id) }

// ValidCIMDClientID applies CIMD section 3's client_id URL rules (https, a
// host, a path other than "/", no dot segments, fragment or user
// information).
func ValidCIMDClientID(raw string) bool { return validClientIDURL(raw) }

// ValidateCIMDDocument checks a client metadata document fetched from
// clientID with this provider's CIMD rules: the client registration it would
// make, or an ErrCIMDFetch error naming the rule. Without
// ClientIDMetadataDocuments it is ErrCIMDFetch.
func (p *Plugin) ValidateCIMDDocument(clientID string, document []byte) (ClientMetadata, error) {
	if p.cimd == nil || !validClientIDURL(clientID) {
		return ClientMetadata{}, ErrCIMDFetch
	}
	m, err := p.parseCIMD(clientID, document)
	if err != nil {
		return ClientMetadata{}, err
	}
	return p.checkMetadata(m)
}

func originOfURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// fetchPublic is the default CIMDFetcher.
func fetchPublic(ctx context.Context, rawURL string, cond http.Header) (CIMDResponse, error) {
	return fetchPublicLimit(ctx, rawURL, cond, cimdMaxBytes)
}

// fetchPublicLimit GETs an https URL from a public address only, reading at
// most limit+1 bytes so the caller can tell an oversized answer.
func fetchPublicLimit(ctx context.Context, rawURL string, cond http.Header, limit int64) (CIMDResponse, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != schemeHTTPS {
		return CIMDResponse{}, fmt.Errorf("%w: not https", ErrCIMDFetch)
	}
	dialer := &net.Dialer{Timeout: cimdTimeout}
	transport := &http.Transport{
		// Resolve once, check every address, then dial the checked one: a
		// second resolution could answer a private address (DNS rebinding).
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if err != nil || len(ips) == 0 {
				return nil, fmt.Errorf("%w: resolve %s", ErrCIMDFetch, host)
			}
			for _, ip := range ips {
				if !isPublicAddr(ip) {
					return nil, fmt.Errorf("%w: %s resolves to a non-public address", ErrCIMDFetch, host)
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
		},
		TLSHandshakeTimeout: cimdTimeout, DisableKeepAlives: true, Proxy: nil,
	}
	client := &http.Client{
		Transport: transport, Timeout: cimdTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return CIMDResponse{}, err
	}
	req.Header.Set("Accept", mediaTypeJSON)
	for k, v := range cond {
		req.Header[k] = v
	}
	res, err := client.Do(req)
	if err != nil {
		return CIMDResponse{}, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		return CIMDResponse{}, err
	}
	return CIMDResponse{Status: res.StatusCode, Body: b, Header: res.Header}, nil
}

// checkDocument accepts exactly a 200 answer of a JSON media type, at most
// cimdMaxBytes long.
func checkDocument(res CIMDResponse) ([]byte, error) {
	if res.Status != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", ErrCIMDFetch, res.Status)
	}
	mt, _, err := mime.ParseMediaType(res.Header.Get(headerContentType))
	if err != nil || (mt != mediaTypeJSON && !(strings.HasPrefix(mt, mediaPrefixApp) && strings.HasSuffix(mt, mediaSuffixJSON))) {
		return nil, fmt.Errorf("%w: media type %q", ErrCIMDFetch, res.Header.Get(headerContentType))
	}
	if len(res.Body) > cimdMaxBytes {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrCIMDFetch, cimdMaxBytes)
	}
	return res.Body, nil
}

// nonPublic are the RFC 6890 special-purpose ranges a fetch may not reach,
// beyond what netip's own predicates cover.
var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("100::/64"), netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"),
}

// isPublicAddr reports whether a fetch may reach ip: not loopback, private,
// link-local, multicast, unspecified, or another special-purpose range.
func isPublicAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}
