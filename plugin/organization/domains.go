package organization

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/access"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/sqlb"
)

// Verified domains (Clerk's organization domains): an organization claims an
// email domain such as acme.com, proves it owns it, and picks what happens to
// a user whose email at that domain is verified: nothing, an invitation, a
// suggestion they can turn into a membership request, or membership outright.
//
// The security core, in one place: enrollment fires only from a VERIFIED
// email identity (the identity data hooks see verified_at being set, or an
// identity created verified), and only for a domain the organization has
// proved it owns (verified_domain is set only by verify-domain or
// MarkDomainVerified). An unverified address, or a claimed but unproved
// domain, enrolls nobody. verified_domain is UNIQUE, so one domain belongs to
// at most one organization; several may claim it while unproved, so a
// squatter who adds a domain they cannot prove blocks no one.

// Tables of verified domains, declared only when Domains is on.
const (
	TableNameDomain        = "auth_org_domain"
	TableNameDomainRequest = "auth_org_domain_request"

	TableAliasDomain        = "odm"
	TableAliasDomainRequest = "odr"
)

// Columns of auth_org_domain.
const (
	ColDomainID         = "id"
	ColDomainOrgID      = "org_id"
	ColDomainName       = "domain"
	ColDomainVerified   = "verified_domain"
	ColDomainEnrollment = "enrollment"
	ColDomainRole       = "role"
	ColDomainToken      = "token"
	ColDomainCreatedBy  = "created_by"
	ColDomainVerifiedAt = "verified_at"
	ColDomainCreatedAt  = "created_at"
)

// Columns of auth_org_domain_request.
const (
	ColRequestID        = "id"
	ColRequestOrgID     = "org_id"
	ColRequestUserID    = "user_id"
	ColRequestDomainID  = "domain_id"
	ColRequestStatus    = "status"
	ColRequestCreatedAt = "created_at"
	ColRequestDecidedAt = "decided_at"
	ColRequestDecidedBy = "decided_by"
)

// Domain tables and typed columns, for an app that joins them; reads are
// open, writes go through the operations.
var (
	TableDomain        = sqlb.Table{Name: TableNameDomain, Alias: TableAliasDomain}
	TableDomainRequest = sqlb.Table{Name: TableNameDomainRequest, Alias: TableAliasDomainRequest}

	DomainID         = sqlb.Col[string](TableDomain, ColDomainID)
	DomainOrgID      = sqlb.Col[string](TableDomain, ColDomainOrgID)
	DomainName       = sqlb.Col[string](TableDomain, ColDomainName)
	DomainVerified   = sqlb.Col[*string](TableDomain, ColDomainVerified)
	DomainEnrollment = sqlb.Col[EnrollmentMode](TableDomain, ColDomainEnrollment)
	DomainRole       = sqlb.Col[Role](TableDomain, ColDomainRole)
	DomainToken      = sqlb.Col[string](TableDomain, ColDomainToken)
	DomainCreatedBy  = sqlb.Col[string](TableDomain, ColDomainCreatedBy)
	DomainVerifiedAt = sqlb.Col[*time.Time](TableDomain, ColDomainVerifiedAt)
	DomainCreatedAt  = sqlb.Col[time.Time](TableDomain, ColDomainCreatedAt)

	RequestID        = sqlb.Col[string](TableDomainRequest, ColRequestID)
	RequestOrgID     = sqlb.Col[string](TableDomainRequest, ColRequestOrgID)
	RequestUserID    = sqlb.Col[string](TableDomainRequest, ColRequestUserID)
	RequestDomainID  = sqlb.Col[string](TableDomainRequest, ColRequestDomainID)
	RequestStatusCol = sqlb.Col[RequestStatus](TableDomainRequest, ColRequestStatus)
	RequestCreatedAt = sqlb.Col[time.Time](TableDomainRequest, ColRequestCreatedAt)
	RequestDecidedAt = sqlb.Col[*time.Time](TableDomainRequest, ColRequestDecidedAt)
	RequestDecidedBy = sqlb.Col[*string](TableDomainRequest, ColRequestDecidedBy)

	// verifiedKey compares the nullable verified_domain with a plain string
	// argument, as activeOrgKey does; NULL never equals it.
	verifiedKey = sqlb.Col[string](TableDomain, ColDomainVerified)
)

// EnrollmentMode is what a verified domain does for a user whose email at
// the domain is verified. The names are Clerk's, plus automatic_join.
// ds:def id=enrollmentmode-3c3jpwcb owner=@khanakia stability=stable
type EnrollmentMode string

// Enrollment modes.
const (
	// EnrollManual does nothing automatically: members are invited by hand.
	// The default, so adding a domain changes nobody's access by itself.
	EnrollManual EnrollmentMode = "manual_invitation"
	// EnrollInvitation creates a pending invitation (organization.invites),
	// which the user accepts as any other.
	EnrollInvitation EnrollmentMode = "automatic_invitation"
	// EnrollSuggestion lists the organization among the user's
	// domain-suggestions; accepting one asks to join, and an admin approves.
	EnrollSuggestion EnrollmentMode = "automatic_suggestion"
	// EnrollJoin makes the user a member with the domain's role.
	EnrollJoin EnrollmentMode = "automatic_join"
)

// EnrollmentModeValues is every EnrollmentMode.
var EnrollmentModeValues = []EnrollmentMode{EnrollManual, EnrollInvitation, EnrollSuggestion, EnrollJoin}

// RequestStatus is the state of a membership request made from a suggestion.
type RequestStatus string

// Membership request states.
const (
	RequestPending  RequestStatus = "pending"
	RequestApproved RequestStatus = "approved"
	RequestRejected RequestStatus = "rejected"
)

// Operation ids of verified domains, permanent like the others.
const (
	EndpointAddDomain      auth.EndpointID = "organization.add-domain"
	EndpointListDomains    auth.EndpointID = "organization.list-domains"
	EndpointVerifyDomain   auth.EndpointID = "organization.verify-domain"
	EndpointUpdateDomain   auth.EndpointID = "organization.update-domain"
	EndpointRemoveDomain   auth.EndpointID = "organization.remove-domain"
	EndpointSuggestions    auth.EndpointID = "organization.domain-suggestions"
	EndpointAcceptSuggest  auth.EndpointID = "organization.accept-suggestion"
	EndpointListRequests   auth.EndpointID = "organization.list-membership-requests"
	EndpointApproveRequest auth.EndpointID = "organization.approve-membership-request"
	EndpointRejectRequest  auth.EndpointID = "organization.reject-membership-request"
)

const (
	// migrationDomains is the ledger name of the domain tables; it never
	// changes once shipped.
	migrationDomains = "0007_organization_domains"
	// idPrefixDomain and idPrefixRequest make an id's kind readable in logs.
	idPrefixDomain  = "odom"
	idPrefixRequest = "oreq"
	// domainUniqueSuffix and requestUniqueSuffix name the composite unique
	// constraints after their table's real name, so two prefixed instances
	// never collide.
	domainUniqueSuffix  = "_org_domain_uq"
	requestUniqueSuffix = "_org_user_uq"
	// recordValueSep joins DomainRecordValuePrefix and the token.
	recordValueSep = "="
)

const (
	// DefaultDomainRecordPrefix is the label the TXT record lives under:
	// _auth-verification.acme.com. An underscore label is never a host name,
	// so the record cannot collide with a real one.
	DefaultDomainRecordPrefix = "_auth-verification"
	// DomainRecordValuePrefix starts the TXT record's value, so a person
	// reading the zone knows what the record is for.
	DomainRecordValuePrefix = "auth-domain-verification"
	// DefaultMaxDomains caps the domains of one organization (Clerk's limit):
	// enough for a company with a few brands, and a cap so one admin cannot
	// fill the table. DomainsConfig.MaxDomains changes it.
	DefaultMaxDomains = 10
	// DefaultVerifyLimit and DefaultVerifyWindow bound verify-domain per
	// client address: each call is a DNS lookup, and 10 a minute is plenty for
	// someone waiting on propagation.
	DefaultVerifyLimit  = 10
	DefaultVerifyWindow = time.Minute
	// verifyTimeout bounds one verifier call: verify-domain runs inside a
	// transaction, and a resolver that never answers must not hold it open.
	verifyTimeout = 10 * time.Second
	// maxDomainLength and maxLabelLength are DNS's limits (RFC 1035).
	maxDomainLength = 253
	maxLabelLength  = 63
)

// Errors of verified domains.
var (
	// ErrDomainNotFound is an unknown domain id, or one of an organization
	// the caller is not in; one error for both, so a guessed id says nothing.
	ErrDomainNotFound = auth.NewError("organization.domain_not_found", http.StatusNotFound, "Not found.")
	// ErrBadDomain is a value that is not a domain name.
	ErrBadDomain = auth.NewError("organization.bad_domain", http.StatusBadRequest, "Enter a domain such as example.com.")
	// ErrPublicDomain is a domain anyone can get an address at (gmail.com),
	// which would let every stranger with such an address enroll.
	ErrPublicDomain = auth.NewError("organization.public_domain", http.StatusBadRequest, "This is a public email domain and cannot belong to an organization.")
	// ErrDomainTaken is a domain another organization has verified, or one
	// this organization has already added.
	ErrDomainTaken = auth.NewError("organization.domain_taken", http.StatusConflict, "This domain is already in use.")
	// ErrDomainsLimit is an organization with MaxDomains domains.
	ErrDomainsLimit = auth.NewError("organization.domains_limit", http.StatusConflict, "This organization has reached the number of domains it can add.")
	// ErrDomainNotVerified answers verify-domain when the record is not
	// found yet, and an enrollment mode set on a domain not verified.
	ErrDomainNotVerified = auth.NewError("organization.domain_not_verified", http.StatusConflict, "The domain is not verified yet. Publish the TXT record and try again.")
	// ErrDomainCheckFailed is a verifier that failed (a DNS outage), as
	// distinct from one that looked and found no record.
	ErrDomainCheckFailed = auth.NewError("organization.domain_check_failed", http.StatusServiceUnavailable, "The domain could not be checked. Try again later.")
	// ErrBadEnrollment is an EnrollmentMode outside EnrollmentModeValues.
	ErrBadEnrollment = auth.NewError("organization.bad_enrollment", http.StatusBadRequest, "This enrollment mode does not exist.")
	// ErrDomainRole is the creator role given to a domain: nobody becomes an
	// owner because of the address they sign up with.
	ErrDomainRole = auth.NewError("organization.domain_role", http.StatusBadRequest, "A domain cannot grant this role.")
	// ErrRequestInvalid is a membership request or suggestion that is
	// unknown, not the caller's to act on, decided already, or whose domain
	// or address is no longer verified.
	ErrRequestInvalid = auth.NewError("organization.request_invalid", http.StatusNotFound, "This request is not valid any more.")
)

// DomainChallenge is what a DomainVerifier checks: that RecordName has a TXT
// record whose value is RecordValue.
type DomainChallenge struct {
	Domain      string
	RecordName  string
	RecordValue string
}

// DomainVerifier decides whether an organization controls a domain. The
// default is DNSVerifier; an app replaces it (DomainsConfig.Verifier) to
// check an HTTP file, ask its registrar's API, or use a fake in tests. It
// answers false with no error when the proof is not there yet, and an error
// only when it could not look.
// ds:def id=domainverifier-xyngwy9v owner=@khanakia stability=api
type DomainVerifier interface {
	VerifyDomain(ctx context.Context, ch DomainChallenge) (bool, error)
}

// DomainVerifierFunc adapts a function to DomainVerifier.
type DomainVerifierFunc func(ctx context.Context, ch DomainChallenge) (bool, error)

// VerifyDomain calls f.
func (f DomainVerifierFunc) VerifyDomain(ctx context.Context, ch DomainChallenge) (bool, error) {
	return f(ctx, ch)
}

// TXTResolver looks up TXT records; *net.Resolver is one.
type TXTResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// DNSVerifier is the default DomainVerifier: the challenge's TXT record must
// hold its value exactly. Resolver is net.DefaultResolver when nil.
type DNSVerifier struct {
	Resolver TXTResolver
}

// VerifyDomain looks the record up. A name that does not exist is "not yet",
// not an error, since that is the state before the admin publishes it.
func (v DNSVerifier) VerifyDomain(ctx context.Context, ch DomainChallenge) (bool, error) {
	var r TXTResolver = net.DefaultResolver
	if v.Resolver != nil {
		r = v.Resolver
	}
	records, err := r.LookupTXT(ctx, ch.RecordName)
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	want := []byte(ch.RecordValue)
	found := 0
	for _, rec := range records {
		found |= subtle.ConstantTimeCompare([]byte(strings.TrimSpace(rec)), want)
	}
	return found == 1, nil
}

// DomainsConfig configures verified domains (Domains). Every field is
// optional.
type DomainsConfig struct {
	// Verifier proves ownership; DNSVerifier{} when nil.
	Verifier DomainVerifier
	// RecordPrefix is the TXT record's label, DefaultDomainRecordPrefix when
	// empty. It must start with an underscore.
	RecordPrefix string
	// TrustVerifiedEmail verifies a domain without DNS when the admin who
	// adds or verifies it holds a verified email at exactly that domain.
	// Off by default: it lets any employee with a work address claim the
	// company's domain for an organization they created, which DNS does not.
	TrustVerifiedEmail bool
	// IsPublicDomain reports a domain that no organization may add, because
	// anyone can get an address there; IsDefaultPublicDomain when nil.
	IsPublicDomain func(domain string) bool
	// MaxDomains caps the domains of one organization; DefaultMaxDomains
	// when zero. Negative is refused.
	MaxDomains int
}

// Domains turns verified domains on: the domain operations, their tables and
// the enrollment of users whose verified email is at a verified domain.
func Domains(cfg DomainsConfig) Option { return func(p *Plugin) { p.domains = &cfg } }

// DefaultPublicDomains are the free mail providers IsDefaultPublicDomain
// refuses. It is a starting list, not a complete one: an app that serves a
// region with other providers passes its own DomainsConfig.IsPublicDomain.
var DefaultPublicDomains = []string{
	"gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "yahoo.co.in", "ymail.com", "rocketmail.com",
	"outlook.com", "hotmail.com", "hotmail.co.uk", "live.com", "msn.com", "icloud.com", "me.com", "mac.com",
	"aol.com", "proton.me", "protonmail.com", "pm.me", "gmx.com", "gmx.de", "gmx.net", "web.de", "mail.com",
	"yandex.com", "yandex.ru", "mail.ru", "zoho.com", "qq.com", "163.com", "126.com", "fastmail.com",
	"hey.com", "tutanota.com", "tuta.io", "rediffmail.com", "naver.com", "hanmail.net", "libero.it", "orange.fr",
}

// IsDefaultPublicDomain reports whether domain, normalized, is in
// DefaultPublicDomains.
func IsDefaultPublicDomain(domain string) bool { return slices.Contains(DefaultPublicDomains, domain) }

// labelPattern is one DNS label as stored: lowercase letters, digits and
// inner dashes (punycode "xn--" labels included). recordPrefixPattern is a
// RecordPrefix: an underscore label.
var (
	labelPattern        = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	recordPrefixPattern = regexp.MustCompile(`^_[a-z0-9_-]{1,62}$`)
)

// NormalizeDomain returns the stored form of a domain: trimmed, lowercased,
// without a leading "@" or a trailing dot. It refuses anything that is not a
// name of two or more labels with a non-numeric top label, so an IP address
// or a bare TLD never becomes a domain. Unicode names are given in punycode.
func NormalizeDomain(raw string) (string, error) {
	d := strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(raw)), "@"), ".")
	if d == "" || len(d) > maxDomainLength {
		return "", ErrBadDomain
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", ErrBadDomain
	}
	for _, l := range labels {
		if len(l) > maxLabelLength || !labelPattern.MatchString(l) {
			return "", ErrBadDomain
		}
	}
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return "", ErrBadDomain
	}
	return d, nil
}

// EmailDomain returns the domain of a normalized email address, the part
// after its last "@", in NormalizeDomain's form; "" when it has none.
func EmailDomain(addr string) string {
	i := strings.LastIndexByte(addr, '@')
	if i < 0 {
		return ""
	}
	d, err := NormalizeDomain(addr[i+1:])
	if err != nil {
		return ""
	}
	return d
}

// OrgDomain is a domain of an organization. RecordName and RecordValue are
// the TXT record to publish; they stay meaningful after verification, which
// keeps a later re-check possible.
type OrgDomain struct {
	ID          string         `json:"id"`
	OrgID       string         `json:"orgId"`
	Domain      string         `json:"domain"`
	Enrollment  EnrollmentMode `json:"enrollmentMode"`
	Role        Role           `json:"role"`
	Verified    bool           `json:"verified"`
	VerifiedAt  *time.Time     `json:"verifiedAt,omitempty"`
	RecordName  string         `json:"recordName"`
	RecordValue string         `json:"recordValue"`
	CreatedAt   time.Time      `json:"createdAt"`
	// token is the stored challenge token; RecordValue is built from it.
	token string
	// createdBy is the admin who added the domain; automatic invitations
	// name them as the inviter.
	createdBy string
}

// AddDomainRequest is the input of add-domain; an empty OrgID means the
// active organization. Enrollment is EnrollManual and Role RoleMember when
// empty.
type AddDomainRequest struct {
	OrgID      string         `json:"orgId,omitempty"`
	Domain     string         `json:"domain"`
	Enrollment EnrollmentMode `json:"enrollmentMode,omitempty"`
	Role       Role           `json:"role,omitempty"`
}

// DomainsRequest names an organization, as the input of list-domains and
// list-membership-requests; empty means the active one.
type DomainsRequest struct {
	OrgID string `json:"orgId,omitempty"`
}

// DomainRequest names a domain, as the input of verify-domain,
// remove-domain and accept-suggestion.
type DomainRequest struct {
	DomainID string `json:"domainId"`
}

// UpdateDomainRequest is the input of update-domain; nil fields stay.
type UpdateDomainRequest struct {
	DomainID   string          `json:"domainId"`
	Enrollment *EnrollmentMode `json:"enrollmentMode,omitempty"`
	Role       *Role           `json:"role,omitempty"`
}

// DomainsResult is the output of list-domains.
type DomainsResult struct {
	Domains []OrgDomain `json:"domains"`
}

// DomainSuggestion is an organization the caller may ask to join, because
// it verified the domain of one of the caller's verified emails.
type DomainSuggestion struct {
	DomainID string `json:"domainId"`
	OrgID    string `json:"orgId"`
	OrgName  string `json:"orgName"`
	OrgSlug  string `json:"orgSlug"`
	Domain   string `json:"domain"`
	// Requested is true once the caller asked to join and an admin has not
	// decided yet.
	Requested bool `json:"requested"`
}

// SuggestionsResult is the output of domain-suggestions.
type SuggestionsResult struct {
	Suggestions []DomainSuggestion `json:"suggestions"`
}

// RequestIDRequest names a membership request, as the input of
// approve-membership-request and reject-membership-request.
type RequestIDRequest struct {
	RequestID string `json:"requestId"`
}

// MembershipRequest is a user's request to join, made from a suggestion.
type MembershipRequest struct {
	ID        string        `json:"id"`
	OrgID     string        `json:"orgId"`
	DomainID  string        `json:"domainId"`
	Domain    string        `json:"domain"`
	User      auth.UserView `json:"user"`
	Status    RequestStatus `json:"status"`
	CreatedAt time.Time     `json:"createdAt"`
}

// MembershipRequestsResult is the output of list-membership-requests.
type MembershipRequestsResult struct {
	Requests []MembershipRequest `json:"requests"`
}

// AddDomain adds a domain to an organization, as a member with
// organization:update. It is unverified until VerifyDomain, unless
// TrustVerifiedEmail and the caller's verified email prove it at once.
func (p *Plugin) AddDomain(ctx context.Context, in AddDomainRequest) (OrgDomain, error) {
	return p.addDomain.Call(ctx, in)
}

// ListDomains lists an organization's domains, as a member.
func (p *Plugin) ListDomains(ctx context.Context, orgID string) ([]OrgDomain, error) {
	r, err := p.listDomains.Call(ctx, DomainsRequest{OrgID: orgID})
	return r.Domains, err
}

// VerifyDomain checks a domain's proof, as a member with organization:update.
func (p *Plugin) VerifyDomain(ctx context.Context, domainID string) (OrgDomain, error) {
	return p.verifyDomain.Call(ctx, DomainRequest{DomainID: domainID})
}

// UpdateDomain changes a domain's enrollment mode or role, as a member with
// organization:update.
func (p *Plugin) UpdateDomain(ctx context.Context, in UpdateDomainRequest) (OrgDomain, error) {
	return p.updateDomain.Call(ctx, in)
}

// RemoveDomain removes a domain and its pending membership requests, as a
// member with organization:update. Invitations it created stay, as any
// invitation does, until canceled or expired.
func (p *Plugin) RemoveDomain(ctx context.Context, domainID string) error {
	_, err := p.removeDomain.Call(ctx, DomainRequest{DomainID: domainID})
	return err
}

// DomainSuggestions lists the organizations the signed-in user may ask to
// join through a verified domain in EnrollSuggestion mode.
func (p *Plugin) DomainSuggestions(ctx context.Context) ([]DomainSuggestion, error) {
	r, err := p.suggestions.Call(ctx, struct{}{})
	return r.Suggestions, err
}

// AcceptSuggestion asks to join the organization of a suggested domain; an
// admin approves the request.
func (p *Plugin) AcceptSuggestion(ctx context.Context, domainID string) (MembershipRequest, error) {
	return p.acceptSuggestion.Call(ctx, DomainRequest{DomainID: domainID})
}

// ListMembershipRequests lists an organization's pending requests, as a
// member with member:create.
func (p *Plugin) ListMembershipRequests(ctx context.Context, orgID string) ([]MembershipRequest, error) {
	r, err := p.listRequests.Call(ctx, DomainsRequest{OrgID: orgID})
	return r.Requests, err
}

// ApproveMembershipRequest makes the requester a member with the domain's
// role, as a member with member:create.
func (p *Plugin) ApproveMembershipRequest(ctx context.Context, requestID string) error {
	_, err := p.approveRequest.Call(ctx, RequestIDRequest{RequestID: requestID})
	return err
}

// RejectMembershipRequest declines a request, as a member with
// member:create; the organization is not suggested to that user again.
func (p *Plugin) RejectMembershipRequest(ctx context.Context, requestID string) error {
	_, err := p.rejectRequest.Call(ctx, RequestIDRequest{RequestID: requestID})
	return err
}

// MarkDomainVerified verifies a domain from the server, with no proof and no
// caller: for an operator who checked ownership another way. It is a Go
// API only, never a route. The domain must not be verified by another
// organization.
func (p *Plugin) MarkDomainVerified(ctx context.Context, domainID string) (OrgDomain, error) {
	if p.domains == nil {
		return OrgDomain{}, ErrDomainNotFound
	}
	var out OrgDomain
	err := p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		d, err := p.domainByID(ctx, domainID)
		if err != nil {
			return err
		}
		out, err = p.markVerified(ctx, d)
		return err
	})
	return out, err
}

// defineDomainOps builds the domain operations; New calls it.
func (p *Plugin) defineDomainOps(signedIn func(auth.EndpointID, auth.OpKind, string) auth.OpInfo) {
	p.addDomain = auth.Define(signedIn(EndpointAddDomain, auth.Mutation, "/add-domain"), p.doAddDomain)
	p.listDomains = auth.Define(signedIn(EndpointListDomains, auth.Query, "/list-domains"), p.doListDomains)
	p.verifyDomain = auth.Define(signedIn(EndpointVerifyDomain, auth.Mutation, "/verify-domain"), p.doVerifyDomain)
	p.updateDomain = auth.Define(signedIn(EndpointUpdateDomain, auth.Mutation, "/update-domain"), p.doUpdateDomain)
	p.removeDomain = auth.Define(signedIn(EndpointRemoveDomain, auth.Mutation, "/remove-domain"), p.doRemoveDomain)
	p.suggestions = auth.Define(signedIn(EndpointSuggestions, auth.Query, "/domain-suggestions"), p.doSuggestions)
	p.acceptSuggestion = auth.Define(signedIn(EndpointAcceptSuggest, auth.Mutation, "/accept-suggestion"), p.doAcceptSuggestion)
	p.listRequests = auth.Define(signedIn(EndpointListRequests, auth.Query, "/list-membership-requests"), p.doListRequests)
	p.approveRequest = auth.Define(signedIn(EndpointApproveRequest, auth.Mutation, "/approve-membership-request"), p.doApproveRequest)
	p.rejectRequest = auth.Define(signedIn(EndpointRejectRequest, auth.Mutation, "/reject-membership-request"), p.doRejectRequest)
}

// domainOps lists the domain operations for Operations.
func (p *Plugin) domainOps() []auth.Operation {
	return []auth.Operation{p.addDomain, p.listDomains, p.verifyDomain, p.updateDomain, p.removeDomain, p.suggestions, p.acceptSuggestion, p.listRequests, p.approveRequest, p.rejectRequest}
}

// validateDomains checks DomainsConfig.
func (p *Plugin) validateDomains() error {
	cfg := p.domains
	if cfg.MaxDomains < 0 {
		return errors.New("organization: DomainsConfig.MaxDomains cannot be negative")
	}
	if cfg.RecordPrefix != "" && !recordPrefixPattern.MatchString(cfg.RecordPrefix) {
		return fmt.Errorf("organization: DomainsConfig.RecordPrefix %q must be one DNS label starting with an underscore", cfg.RecordPrefix)
	}
	return nil
}

// verifier, isPublic, recordPrefix and maxDomains read DomainsConfig with
// its defaults.
func (p *Plugin) verifier() DomainVerifier {
	if p.domains.Verifier != nil {
		return p.domains.Verifier
	}
	return DNSVerifier{}
}

func (p *Plugin) isPublic(d string) bool {
	if p.domains.IsPublicDomain != nil {
		return p.domains.IsPublicDomain(d)
	}
	return IsDefaultPublicDomain(d)
}

func (p *Plugin) recordPrefix() string {
	if p.domains.RecordPrefix != "" {
		return p.domains.RecordPrefix
	}
	return DefaultDomainRecordPrefix
}

func (p *Plugin) maxDomains() int {
	if p.domains.MaxDomains > 0 {
		return p.domains.MaxDomains
	}
	return DefaultMaxDomains
}

// domainMigration creates the two tables. verified_domain is UNIQUE and NULL
// until verified: every engine allows many NULLs under a unique constraint,
// so many organizations may claim a domain and only the first to prove it
// gets it.
func (p *Plugin) domainMigration(t auth.SQLTypes) auth.Migration {
	dom := p.core.TableName(TableDomain)
	req := p.core.TableName(TableDomainRequest)
	return auth.Migration{Owner: PluginName, Name: migrationDomains, Statements: []string{
		"CREATE TABLE IF NOT EXISTS " + dom + " (" +
			ColDomainID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
			ColDomainOrgID + " " + t.ID + " NOT NULL, " +
			ColDomainName + " " + t.Value + " NOT NULL, " +
			ColDomainVerified + " " + t.Value + " NULL UNIQUE, " +
			ColDomainEnrollment + " " + t.Key + " NOT NULL, " +
			ColDomainRole + " " + t.Key + " NOT NULL, " +
			ColDomainToken + " " + t.Key + " NOT NULL, " +
			ColDomainCreatedBy + " " + t.ID + " NOT NULL, " +
			ColDomainVerifiedAt + " " + t.Timestamp + " NULL, " +
			ColDomainCreatedAt + " " + t.Timestamp + " NOT NULL, " +
			"CONSTRAINT " + dom + domainUniqueSuffix + " UNIQUE (" + ColDomainOrgID + ", " + ColDomainName + "))" + t.TableSuffix,
		"CREATE TABLE IF NOT EXISTS " + req + " (" +
			ColRequestID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
			ColRequestOrgID + " " + t.ID + " NOT NULL, " +
			ColRequestUserID + " " + t.ID + " NOT NULL, " +
			ColRequestDomainID + " " + t.ID + " NOT NULL, " +
			ColRequestStatus + " " + t.Key + " NOT NULL, " +
			ColRequestCreatedAt + " " + t.Timestamp + " NOT NULL, " +
			ColRequestDecidedAt + " " + t.Timestamp + " NULL, " +
			ColRequestDecidedBy + " " + t.ID + " NULL, " +
			"CONSTRAINT " + req + requestUniqueSuffix + " UNIQUE (" + ColRequestOrgID + ", " + ColRequestUserID + "))" + t.TableSuffix,
	}}
}

// domainCols binds every column of auth_org_domain into d.
func domainCols(d *OrgDomain) []sqlb.Binding {
	return []sqlb.Binding{
		sqlb.Bind(DomainID, &d.ID), sqlb.Bind(DomainOrgID, &d.OrgID), sqlb.Bind(DomainName, &d.Domain),
		sqlb.Bind(DomainEnrollment, &d.Enrollment), sqlb.Bind(DomainRole, &d.Role), sqlb.Bind(DomainToken, &d.token),
		sqlb.Bind(DomainCreatedBy, &d.createdBy), sqlb.Bind(DomainVerifiedAt, &d.VerifiedAt), sqlb.Bind(DomainCreatedAt, &d.CreatedAt),
	}
}

// finish fills what is derived from the stored columns.
func (p *Plugin) finish(d OrgDomain) OrgDomain {
	d.Verified = d.VerifiedAt != nil
	d.RecordName = p.recordPrefix() + "." + d.Domain
	d.RecordValue = DomainRecordValuePrefix + recordValueSep + d.token
	return d
}

// domains reads the domains matching where, oldest first.
func (p *Plugin) domainsWhere(ctx context.Context, where ...sqlb.Predicate) ([]OrgDomain, error) {
	var row OrgDomain
	out := []OrgDomain{}
	q := p.core.Select().Columns(domainCols(&row)...).From(TableDomain).Where(where...).
		Order(sqlb.OrderBy(DomainCreatedAt, sqlb.SortAsc), sqlb.OrderBy(DomainID, sqlb.SortAsc))
	err := p.core.Each(ctx, q, func() error { out = append(out, p.finish(row)); return nil })
	return out, err
}

// domainByID reads one domain, or ErrDomainNotFound.
func (p *Plugin) domainByID(ctx context.Context, id string) (OrgDomain, error) {
	list, err := p.domainsWhere(ctx, sqlb.Eq(DomainID, id))
	if err != nil {
		return OrgDomain{}, err
	}
	if len(list) == 0 {
		return OrgDomain{}, ErrDomainNotFound
	}
	return list[0], nil
}

// adminDomain reads a domain the caller may manage: a member of its
// organization (a stranger gets ErrDomainNotFound) holding
// organization:update.
func (p *Plugin) adminDomain(ctx context.Context, c *auth.Call, id string) (OrgDomain, Role, error) {
	d, err := p.domainByID(ctx, id)
	if err != nil {
		return OrgDomain{}, "", err
	}
	mine, err := p.RoleOf(ctx, d.OrgID, c.User.ID)
	if errors.Is(err, ErrNotMember) {
		return OrgDomain{}, "", ErrDomainNotFound
	}
	if err != nil {
		return OrgDomain{}, "", err
	}
	c.Annotate(auth.AnnotationOrganization, d.OrgID)
	if err := p.authorize(ctx, c, d.OrgID, mine, access.Request{ResourceOrganization: access.All(ActionUpdate)}); err != nil {
		return OrgDomain{}, "", err
	}
	return d, mine, nil
}

// checkEnrollment validates a mode and a role for a domain of orgID set by a
// caller whose role is mine.
func (p *Plugin) checkEnrollment(ctx context.Context, orgID string, mode EnrollmentMode, role, mine Role) error {
	if !slices.Contains(EnrollmentModeValues, mode) {
		return ErrBadEnrollment
	}
	if err := p.checkRole(ctx, orgID, role); err != nil {
		return err
	}
	if role.Has(p.creatorRole) {
		return ErrDomainRole
	}
	return p.guardCreator(mine, role)
}

func (p *Plugin) doAddDomain(ctx context.Context, c *auth.Call, in AddDomainRequest) (OrgDomain, error) {
	orgID, err := p.resolveOrg(ctx, c, in.OrgID)
	if err != nil {
		return OrgDomain{}, err
	}
	mine, err := p.RoleOf(ctx, orgID, c.User.ID)
	if err != nil {
		return OrgDomain{}, err
	}
	if err := p.authorize(ctx, c, orgID, mine, access.Request{ResourceOrganization: access.All(ActionUpdate)}); err != nil {
		return OrgDomain{}, err
	}
	name, err := NormalizeDomain(in.Domain)
	if err != nil {
		return OrgDomain{}, err
	}
	if p.isPublic(name) {
		return OrgDomain{}, ErrPublicDomain
	}
	mode, role := in.Enrollment, in.Role
	if mode == "" {
		mode = EnrollManual
	}
	if role == "" {
		role = RoleMember
	}
	if err := p.checkEnrollment(ctx, orgID, mode, role, mine); err != nil {
		return OrgDomain{}, err
	}
	// A domain another organization proved has no constraint to hit on this
	// insert (the claim is unverified), so it is checked first; the same
	// domain twice in this organization is the unique (org_id, domain)
	// constraint's answer, mapped below.
	taken, err := p.domainsWhere(ctx, sqlb.Eq(verifiedKey, name))
	if err != nil {
		return OrgDomain{}, err
	}
	if len(taken) > 0 {
		return OrgDomain{}, ErrDomainTaken
	}
	var n int64
	if err := p.core.One(ctx, p.core.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(TableDomain).Where(sqlb.Eq(DomainOrgID, orgID))); err != nil {
		return OrgDomain{}, err
	}
	if n >= int64(p.maxDomains()) {
		return OrgDomain{}, ErrDomainsLimit
	}
	id, err := c.Auth.NewID(idPrefixDomain)
	if err != nil {
		return OrgDomain{}, err
	}
	d := OrgDomain{ID: id, OrgID: orgID, Domain: name, Enrollment: mode, Role: JoinRoles(role), CreatedAt: c.Auth.Now(), token: string(auth.NewToken()), createdBy: c.User.ID}
	q := sqlb.NewInsert(c.Auth.Dialect()).Into(TableDomain).Row(
		sqlb.Set(DomainID, d.ID), sqlb.Set(DomainOrgID, d.OrgID), sqlb.Set(DomainName, d.Domain),
		sqlb.Set(DomainEnrollment, d.Enrollment), sqlb.Set(DomainRole, d.Role), sqlb.Set(DomainToken, d.token),
		sqlb.Set(DomainCreatedBy, d.createdBy), sqlb.Set(DomainCreatedAt, d.CreatedAt),
	)
	if _, err := p.core.Exec(ctx, q); err != nil {
		if auth.IsUniqueViolation(err) {
			return OrgDomain{}, ErrDomainTaken
		}
		return OrgDomain{}, err
	}
	d = p.finish(d)
	if ok, err := p.emailProves(ctx, c.User.ID, name); err != nil || !ok {
		return d, err
	}
	return p.markVerified(ctx, d)
}

// emailProves reports whether TrustVerifiedEmail is on and userID holds a
// VERIFIED email at exactly domain.
func (p *Plugin) emailProves(ctx context.Context, userID, domain string) (bool, error) {
	if !p.domains.TrustVerifiedEmail {
		return false, nil
	}
	ids, err := p.core.VerifiedIdentities(ctx, userID, email.KindEmail)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(ids, func(i auth.Identity) bool { return EmailDomain(i.Value) == domain }), nil
}

// markVerified records d as proved. Another organization that proved it
// first wins through the unique verified_domain column, the one rule for a
// sequential and a concurrent attempt alike. The failed write ends the
// operation, whose transaction rolls back, so Postgres aborting the
// transaction on it costs nothing.
func (p *Plugin) markVerified(ctx context.Context, d OrgDomain) (OrgDomain, error) {
	if d.Verified {
		return d, nil
	}
	now := p.core.Now()
	upd := sqlb.NewUpdate(p.core.Dialect()).Table(TableDomain).
		Set(sqlb.Set(DomainVerified, &d.Domain), sqlb.Set(DomainVerifiedAt, &now)).Where(sqlb.Eq(DomainID, d.ID))
	if _, err := p.core.Exec(ctx, upd); err != nil {
		if auth.IsUniqueViolation(err) {
			return OrgDomain{}, ErrDomainTaken
		}
		return OrgDomain{}, err
	}
	d.VerifiedAt = &now
	return p.finish(d), nil
}

func (p *Plugin) doListDomains(ctx context.Context, c *auth.Call, in DomainsRequest) (DomainsResult, error) {
	orgID, err := p.resolveOrg(ctx, c, in.OrgID)
	if err != nil {
		return DomainsResult{}, err
	}
	if _, err := p.RoleOf(ctx, orgID, c.User.ID); err != nil {
		return DomainsResult{}, err
	}
	list, err := p.domainsWhere(ctx, sqlb.Eq(DomainOrgID, orgID))
	return DomainsResult{Domains: list}, err
}

// doVerifyDomain asks the verifier, or accepts the caller's verified email
// under TrustVerifiedEmail. A verifier error is ErrDomainCheckFailed, never
// a pass.
func (p *Plugin) doVerifyDomain(ctx context.Context, c *auth.Call, in DomainRequest) (OrgDomain, error) {
	d, _, err := p.adminDomain(ctx, c, in.DomainID)
	if err != nil || d.Verified {
		return d, err
	}
	ok, err := p.emailProves(ctx, c.User.ID, d.Domain)
	if err != nil {
		return OrgDomain{}, err
	}
	if !ok {
		vctx, cancel := context.WithTimeout(ctx, verifyTimeout)
		defer cancel()
		found, err := p.verifier().VerifyDomain(vctx, DomainChallenge{Domain: d.Domain, RecordName: d.RecordName, RecordValue: d.RecordValue})
		if err != nil {
			c.Auth.Logger().WarnContext(ctx, "organization: domain verifier failed", "domain", d.Domain, "error", err)
			return OrgDomain{}, ErrDomainCheckFailed
		}
		if !found {
			return OrgDomain{}, ErrDomainNotVerified
		}
	}
	return p.markVerified(ctx, d)
}

func (p *Plugin) doUpdateDomain(ctx context.Context, c *auth.Call, in UpdateDomainRequest) (OrgDomain, error) {
	d, mine, err := p.adminDomain(ctx, c, in.DomainID)
	if err != nil {
		return OrgDomain{}, err
	}
	if in.Enrollment != nil {
		d.Enrollment = *in.Enrollment
	}
	if in.Role != nil {
		d.Role = JoinRoles(*in.Role)
	}
	if err := p.checkEnrollment(ctx, d.OrgID, d.Enrollment, d.Role, mine); err != nil {
		return OrgDomain{}, err
	}
	upd := sqlb.NewUpdate(c.Auth.Dialect()).Table(TableDomain).
		Set(sqlb.Set(DomainEnrollment, d.Enrollment), sqlb.Set(DomainRole, d.Role)).Where(sqlb.Eq(DomainID, d.ID))
	if _, err := p.core.Exec(ctx, upd); err != nil {
		return OrgDomain{}, err
	}
	return d, nil
}

func (p *Plugin) doRemoveDomain(ctx context.Context, c *auth.Call, in DomainRequest) (auth.Done, error) {
	d, _, err := p.adminDomain(ctx, c, in.DomainID)
	if err != nil {
		return auth.Done{}, err
	}
	dl := c.Auth.Dialect()
	for _, del := range []auth.Statement{
		sqlb.NewDelete(dl).From(TableDomainRequest).Where(sqlb.Eq(RequestDomainID, d.ID), sqlb.Eq(RequestStatusCol, RequestPending)),
		sqlb.NewDelete(dl).From(TableDomain).Where(sqlb.Eq(DomainID, d.ID)),
	} {
		if _, err := p.core.Exec(ctx, del); err != nil {
			return auth.Done{}, err
		}
	}
	return auth.Done{OK: true}, nil
}

// verifiedDomainsFor returns the verified domains, in mode, matching the
// domains of userID's VERIFIED emails. This is the only way a user is
// matched to a domain: an unverified email matches nothing.
func (p *Plugin) verifiedDomainsFor(ctx context.Context, userID string, mode EnrollmentMode) ([]OrgDomain, error) {
	names, err := p.emailDomains(ctx, userID)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, nil
	}
	return p.domainsWhere(ctx, sqlb.In(verifiedKey, names...), sqlb.Eq(DomainEnrollment, mode))
}

// emailDomains returns the distinct domains of userID's VERIFIED emails.
func (p *Plugin) emailDomains(ctx context.Context, userID string) ([]string, error) {
	ids, err := p.core.VerifiedIdentities(ctx, userID, email.KindEmail)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, i := range ids {
		if d := EmailDomain(i.Value); d != "" && !slices.Contains(names, d) {
			names = append(names, d)
		}
	}
	return names, nil
}

// requestOf returns userID's request to orgID, if any.
func (p *Plugin) requestOf(ctx context.Context, orgID, userID string) (*MembershipRequest, error) {
	var r MembershipRequest
	q := p.core.Select().Columns(sqlb.Bind(RequestID, &r.ID), sqlb.Bind(RequestStatusCol, &r.Status), sqlb.Bind(RequestDomainID, &r.DomainID)).
		From(TableDomainRequest).Where(sqlb.Eq(RequestOrgID, orgID), sqlb.Eq(RequestUserID, userID)).Limit(1)
	if err := p.core.One(ctx, q); err != nil {
		if errors.Is(err, sqlb.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &r, nil
}

// doSuggestions lists the suggestion-mode domains of the caller's verified
// emails, without the organizations they are in and those that rejected
// them.
func (p *Plugin) doSuggestions(ctx context.Context, c *auth.Call, _ struct{}) (SuggestionsResult, error) {
	out := SuggestionsResult{Suggestions: []DomainSuggestion{}}
	list, err := p.verifiedDomainsFor(ctx, c.User.ID, EnrollSuggestion)
	if err != nil {
		return out, err
	}
	for _, d := range list {
		s, ok, err := p.suggestion(ctx, c.User.ID, d)
		if err != nil {
			return SuggestionsResult{}, err
		}
		if ok {
			out.Suggestions = append(out.Suggestions, s)
		}
	}
	return out, nil
}

// suggestion builds d's suggestion for userID; false when they are a member
// or were rejected.
func (p *Plugin) suggestion(ctx context.Context, userID string, d OrgDomain) (DomainSuggestion, bool, error) {
	switch _, err := p.RoleOf(ctx, d.OrgID, userID); {
	case err == nil:
		return DomainSuggestion{}, false, nil
	case !errors.Is(err, ErrNotMember):
		return DomainSuggestion{}, false, err
	}
	r, err := p.requestOf(ctx, d.OrgID, userID)
	if err != nil || (r != nil && r.Status == RequestRejected) {
		return DomainSuggestion{}, false, err
	}
	o, err := p.org(ctx, d.OrgID)
	if err != nil {
		return DomainSuggestion{}, false, err
	}
	return DomainSuggestion{DomainID: d.ID, OrgID: d.OrgID, OrgName: o.Name, OrgSlug: o.Slug, Domain: d.Domain, Requested: r != nil && r.Status == RequestPending}, true, nil
}

// doAcceptSuggestion turns one of the caller's suggestions into a pending
// request. The domain is found through the caller's verified emails, so a
// guessed domain id of another domain is ErrRequestInvalid.
func (p *Plugin) doAcceptSuggestion(ctx context.Context, c *auth.Call, in DomainRequest) (MembershipRequest, error) {
	d, err := p.suggestedDomain(ctx, c.User.ID, in.DomainID)
	if err != nil {
		return MembershipRequest{}, err
	}
	c.Annotate(auth.AnnotationOrganization, d.OrgID)
	s, ok, err := p.suggestion(ctx, c.User.ID, d)
	switch {
	case err != nil:
		return MembershipRequest{}, err
	case !ok:
		return MembershipRequest{}, ErrRequestInvalid
	}
	prev, err := p.requestOf(ctx, d.OrgID, c.User.ID)
	if err != nil {
		return MembershipRequest{}, err
	}
	if s.Requested {
		return MembershipRequest{ID: prev.ID, OrgID: d.OrgID, DomainID: d.ID, Domain: d.Domain, User: auth.ViewOf(*c.User), Status: RequestPending}, nil
	}
	if prev != nil {
		// An approved request of someone who left since: a new one replaces
		// it, so the unique (org, user) pair stays one row.
		if _, err := p.core.Exec(ctx, sqlb.NewDelete(c.Auth.Dialect()).From(TableDomainRequest).Where(sqlb.Eq(RequestID, prev.ID))); err != nil {
			return MembershipRequest{}, err
		}
	}
	id, err := c.Auth.NewID(idPrefixRequest)
	if err != nil {
		return MembershipRequest{}, err
	}
	r := MembershipRequest{ID: id, OrgID: d.OrgID, DomainID: d.ID, Domain: d.Domain, User: auth.ViewOf(*c.User), Status: RequestPending, CreatedAt: c.Auth.Now()}
	q := sqlb.NewInsert(c.Auth.Dialect()).Into(TableDomainRequest).Row(
		sqlb.Set(RequestID, r.ID), sqlb.Set(RequestOrgID, r.OrgID), sqlb.Set(RequestUserID, c.User.ID),
		sqlb.Set(RequestDomainID, r.DomainID), sqlb.Set(RequestStatusCol, r.Status), sqlb.Set(RequestCreatedAt, r.CreatedAt),
	)
	_, err = p.core.Exec(ctx, q)
	return r, err
}

// suggestedDomain finds domainID among userID's suggestion-mode domains.
func (p *Plugin) suggestedDomain(ctx context.Context, userID, domainID string) (OrgDomain, error) {
	list, err := p.verifiedDomainsFor(ctx, userID, EnrollSuggestion)
	if err != nil {
		return OrgDomain{}, err
	}
	for _, d := range list {
		if d.ID == domainID {
			return d, nil
		}
	}
	return OrgDomain{}, ErrRequestInvalid
}

// requestAdmin resolves orgID and checks the caller holds member:create.
func (p *Plugin) requestAdmin(ctx context.Context, c *auth.Call, orgID string) (Role, error) {
	mine, err := p.RoleOf(ctx, orgID, c.User.ID)
	if err != nil {
		return "", err
	}
	return mine, p.authorize(ctx, c, orgID, mine, access.Request{ResourceMember: access.All(ActionCreate)})
}

func (p *Plugin) doListRequests(ctx context.Context, c *auth.Call, in DomainsRequest) (MembershipRequestsResult, error) {
	orgID, err := p.resolveOrg(ctx, c, in.OrgID)
	if err != nil {
		return MembershipRequestsResult{}, err
	}
	if _, err := p.requestAdmin(ctx, c, orgID); err != nil {
		return MembershipRequestsResult{}, err
	}
	var r MembershipRequest
	q := p.core.Select().Columns(
		sqlb.Bind(RequestID, &r.ID), sqlb.Bind(RequestOrgID, &r.OrgID), sqlb.Bind(RequestDomainID, &r.DomainID),
		sqlb.Bind(DomainName, &r.Domain), sqlb.Bind(RequestStatusCol, &r.Status), sqlb.Bind(RequestCreatedAt, &r.CreatedAt),
		sqlb.Bind(auth.UserID, &r.User.ID), sqlb.Bind(auth.UserName, &r.User.Name), sqlb.Bind(auth.UserImage, &r.User.Image),
	).From(TableDomainRequest).Join(
		sqlb.Join{Type: sqlb.JoinInner, Table: TableDomain, On: []sqlb.Predicate{sqlb.EqExpr(DomainID, RequestDomainID)}},
		sqlb.Join{Type: sqlb.JoinInner, Table: auth.TableUser, On: []sqlb.Predicate{sqlb.EqExpr(auth.UserID, RequestUserID)}},
	).Where(sqlb.Eq(RequestOrgID, orgID), sqlb.Eq(RequestStatusCol, RequestPending)).
		Order(sqlb.OrderBy(RequestCreatedAt, sqlb.SortAsc), sqlb.OrderBy(RequestID, sqlb.SortAsc))
	out := MembershipRequestsResult{Requests: []MembershipRequest{}}
	err = p.core.Each(ctx, q, func() error { out.Requests = append(out.Requests, r); return nil })
	return out, err
}

// pendingRequest reads a pending request the caller may decide: a stranger
// to its organization, and a decided request, get ErrRequestInvalid.
func (p *Plugin) pendingRequest(ctx context.Context, c *auth.Call, id string) (MembershipRequest, string, Role, error) {
	var r MembershipRequest
	var userID string
	q := p.core.Select().Columns(sqlb.Bind(RequestID, &r.ID), sqlb.Bind(RequestOrgID, &r.OrgID), sqlb.Bind(RequestDomainID, &r.DomainID), sqlb.Bind(RequestUserID, &userID), sqlb.Bind(RequestStatusCol, &r.Status)).
		From(TableDomainRequest).Where(sqlb.Eq(RequestID, id)).Limit(1)
	if err := p.core.One(ctx, q); err != nil {
		return r, "", "", errIsNoRows(err, ErrRequestInvalid)
	}
	mine, err := p.requestAdmin(ctx, c, r.OrgID)
	if errors.Is(err, ErrNotMember) {
		return r, "", "", ErrRequestInvalid
	}
	if err != nil {
		return r, "", "", err
	}
	c.Annotate(auth.AnnotationOrganization, r.OrgID)
	if r.Status != RequestPending {
		return r, "", "", ErrRequestInvalid
	}
	return r, userID, mine, nil
}

// doApproveRequest joins the requester with the domain's role, after
// checking again that the domain is still verified and the requester still
// holds a verified email at it: either may have changed since the request.
func (p *Plugin) doApproveRequest(ctx context.Context, c *auth.Call, in RequestIDRequest) (auth.Done, error) {
	r, userID, mine, err := p.pendingRequest(ctx, c, in.RequestID)
	if err != nil {
		return auth.Done{}, err
	}
	doms, err := p.domainsWhere(ctx, sqlb.Eq(DomainID, r.DomainID))
	if err != nil {
		return auth.Done{}, err
	}
	names, err := p.emailDomains(ctx, userID)
	if err != nil {
		return auth.Done{}, err
	}
	// The domain is gone, unproved, or no longer matches a verified email of
	// the requester: one answer for all three.
	i := slices.IndexFunc(doms, func(o OrgDomain) bool { return o.Verified && slices.Contains(names, o.Domain) })
	if i < 0 {
		return auth.Done{}, ErrRequestInvalid
	}
	d := doms[i]
	if err := p.guardCreator(mine, d.Role); err != nil {
		return auth.Done{}, err
	}
	if err := p.join(ctx, d.OrgID, userID, d.Role, nil); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, p.decideRequest(ctx, c, r.ID, RequestApproved)
}

func (p *Plugin) doRejectRequest(ctx context.Context, c *auth.Call, in RequestIDRequest) (auth.Done, error) {
	r, _, _, err := p.pendingRequest(ctx, c, in.RequestID)
	if err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, p.decideRequest(ctx, c, r.ID, RequestRejected)
}

// decideRequest records a decision on a pending request.
func (p *Plugin) decideRequest(ctx context.Context, c *auth.Call, id string, status RequestStatus) error {
	now := c.Auth.Now()
	upd := sqlb.NewUpdate(c.Auth.Dialect()).Table(TableDomainRequest).
		Set(sqlb.Set(RequestStatusCol, status), sqlb.Set(RequestDecidedAt, &now), sqlb.Set(RequestDecidedBy, &c.User.ID)).
		Where(sqlb.Eq(RequestID, id), sqlb.Eq(RequestStatusCol, RequestPending))
	n, err := p.core.Exec(ctx, upd)
	if err == nil && n != 1 {
		return ErrRequestInvalid // decided by a concurrent request
	}
	return err
}

// DataHooks enroll a user when one of their emails becomes verified: an
// identity created verified (a sign-up through a provider that vouches for
// the address) or one whose verified_at is set. Nothing else enrolls, so an
// unverified address never does. Off unless Domains is on.
func (p *Plugin) DataHooks() auth.DataHooks {
	if p.domains == nil {
		return auth.DataHooks{}
	}
	return auth.DataHooks{Identity: auth.TableHooks[auth.Identity]{
		AfterCreate: func(ctx context.Context, _ sqlb.DBTX, idn *auth.Identity) error {
			return p.enroll(ctx, *idn)
		},
		AfterUpdate: func(ctx context.Context, _ sqlb.DBTX, old, idn *auth.Identity) error {
			if old.VerifiedAt != nil {
				return nil // verified before: enrolled then
			}
			return p.enroll(ctx, *idn)
		},
	}}
}

// enroll applies the verified domain of idn, a just-verified email, inside
// the verifying transaction. verified_domain is unique, so at most one
// organization matches. A refusal the organization's own rules make
// (MaxMembers, a member hook, a role deleted since) is logged and skipped:
// it must not fail the user's own verification. A database error fails it.
func (p *Plugin) enroll(ctx context.Context, idn auth.Identity) error {
	if idn.Kind != email.KindEmail || idn.VerifiedAt == nil {
		return nil
	}
	name := EmailDomain(idn.Value)
	if name == "" {
		return nil
	}
	list, err := p.domainsWhere(ctx, sqlb.Eq(verifiedKey, name))
	if err != nil || len(list) == 0 {
		return err
	}
	d := list[0]
	if err := p.checkRole(ctx, d.OrgID, d.Role); err != nil {
		return p.skipEnroll(ctx, d, idn.UserID, err)
	}
	switch d.Enrollment {
	case EnrollJoin:
		return p.skipEnroll(ctx, d, idn.UserID, p.join(ctx, d.OrgID, idn.UserID, d.Role, nil))
	case EnrollInvitation:
		return p.skipEnroll(ctx, d, idn.UserID, p.autoInvite(ctx, d, idn))
	}
	return nil // manual: nothing; suggestion: computed when listed
}

// skipEnroll logs a refusal and drops it; any other error is returned.
func (p *Plugin) skipEnroll(ctx context.Context, d OrgDomain, userID string, err error) error {
	var refusal *auth.Error
	if !errors.As(err, &refusal) {
		return err
	}
	p.core.Logger().InfoContext(ctx, "organization: domain enrollment skipped", "domain", d.Domain, "org", d.OrgID, "user", userID, "code", refusal.Code)
	return nil
}

// autoInvite creates a pending invitation to idn's address from d, unless
// the user is a member or the address already has one. No mail is sent: the
// user is signed in and verifying right now, so the app shows it in-app
// (organization.invites). The inviter is the admin who added the domain.
func (p *Plugin) autoInvite(ctx context.Context, d OrgDomain, idn auth.Identity) error {
	switch _, err := p.RoleOf(ctx, d.OrgID, idn.UserID); {
	case err == nil:
		return nil
	case !errors.Is(err, ErrNotMember):
		return err
	}
	now := p.core.Now()
	open, err := p.invitations(ctx, d.OrgID, sqlb.Eq(InviteKind, email.KindEmail), sqlb.Eq(InviteIdent, idn.Value), sqlb.Eq(InviteStatusCol, StatusPending), sqlb.Greater(InviteExpiresAt, now))
	if err != nil || len(open) > 0 {
		return err
	}
	id, err := p.core.NewID(idPrefixInvite)
	if err != nil {
		return err
	}
	q := sqlb.NewInsert(p.core.Dialect()).Into(TableInvite).Row(
		sqlb.Set(InviteID, id), sqlb.Set(InviteOrgID, d.OrgID), sqlb.Set(InviteEmail, idn.Value), sqlb.Set(InviteKind, email.KindEmail),
		sqlb.Set(InviteIdent, idn.Value), sqlb.Set(InviteRole, d.Role), sqlb.Set(InviteInvitedBy, d.createdBy),
		sqlb.Set(InviteExpiresAt, now.Add(p.inviteTTL)), sqlb.Set(InviteCreatedAt, now), sqlb.Set(InviteStatusCol, StatusPending),
	)
	_, err = p.core.Exec(ctx, q)
	return err
}
