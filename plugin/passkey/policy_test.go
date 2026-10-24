package passkey

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/ubgo/auth"
)

// The 1Password and YubiKey 5 AAGUIDs, as the registry lists them.
const (
	onePassword = "bada5566-a7aa-401f-bd96-45619a55120d"
	yubiKey5    = "cb69481e-8ff7-4039-93ec-0a2729a154a8"
)

// noMetadata is a metadata provider that checks nothing on the library's
// side; entries, when set, are what GetEntry answers by AAGUID, which is all
// the plugin's own chain check reads.
type noMetadata struct{ entries map[uuid.UUID]*metadata.Entry }

func (m noMetadata) GetEntry(_ context.Context, id uuid.UUID) (*metadata.Entry, error) {
	return m.entries[id], nil
}
func (noMetadata) GetValidateEntry(context.Context) bool                 { return false }
func (noMetadata) GetValidateEntryPermitZeroAAGUID(context.Context) bool { return true }
func (noMetadata) GetValidateTrustAnchor(context.Context) bool           { return false }
func (noMetadata) GetValidateStatus(context.Context) bool                { return false }
func (noMetadata) GetValidateAttestationTypes(context.Context) bool      { return false }
func (noMetadata) ValidateStatusReports(context.Context, []metadata.StatusReport) error {
	return nil
}

// TestValidatePolicy_RefusesWhatNoCeremonyCouldHonour: a malformed or zero
// AAGUID, both lists, an allow-list without metadata, and an unknown
// conveyance are refused by auth.New; a good list is normalized.
func TestValidatePolicy_RefusesWhatNoCeremonyCouldHonour(t *testing.T) {
	for name, opts := range map[string][]Option{
		"not a uuid":         {DenyAuthenticators("yubikey")},
		"zero aaguid":        {DenyAuthenticators("00000000-0000-0000-0000-000000000000")},
		"both lists":         {WithMetadata(noMetadata{}), AllowAuthenticators(yubiKey5), DenyAuthenticators(onePassword)},
		"allow, no metadata": {AllowAuthenticators(yubiKey5)},
		"unknown conveyance": {Attestation("full")},
	} {
		_, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(New(opts...)))
		if !errors.Is(err, ErrAuthenticatorPolicy) {
			t.Errorf("%s: err = %v, want ErrAuthenticatorPolicy", name, err)
		}
	}
	p := New(WithMetadata(noMetadata{}), AllowAuthenticators(" CB69481E8FF7403993EC0A2729A154A8 "))
	if err := p.validatePolicy(); err != nil || p.allowAAGUIDs[0] != yubiKey5 {
		t.Fatalf("normalized = %v, %v", p.allowAAGUIDs, err)
	}
}

// TestConveyancePreference_DefaultsFollowMetadata: none by default, direct
// under WithMetadata, and an explicit choice wins over both.
func TestConveyancePreference_DefaultsFollowMetadata(t *testing.T) {
	for _, tc := range []struct {
		p    *Plugin
		want Conveyance
	}{
		{New(), ConveyanceNone},
		{New(WithMetadata(noMetadata{})), ConveyanceDirect},
		{New(WithMetadata(noMetadata{}), Attestation(ConveyanceEnterprise)), ConveyanceEnterprise},
		{New(Attestation(ConveyanceIndirect)), ConveyanceIndirect},
	} {
		if got := tc.p.conveyancePreference(); got != tc.want {
			t.Errorf("conveyance = %s, want %s", got, tc.want)
		}
	}
	p := New(WithMetadata(noMetadata{}))
	if _, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(p)); err != nil {
		t.Fatal(err)
	}
	if got := p.wa.Config.AttestationPreference; got != "direct" || p.wa.Config.MDS == nil {
		t.Fatalf("library config: attestation %q, metadata %v", got, p.wa.Config.MDS)
	}
}

// certificate makes a P-256 certificate for cn signed by parent (self-signed
// when parent is nil), and returns it with its key.
func certificate(t *testing.T, cn string, ca bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: ca, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

// credOf is a verified credential from the authenticator model aaguid ("" for
// a hidden model), with attestation type typ and leaf as its x5c.
func credOf(t *testing.T, aaguid, typ string, leaf *x509.Certificate) *webauthn.Credential {
	t.Helper()
	c := &webauthn.Credential{AttestationType: typ}
	c.Authenticator.AAGUID = make([]byte, aaguidLen)
	if aaguid != "" {
		u := uuid.MustParse(aaguid)
		c.Authenticator.AAGUID = u[:]
	}
	stmt := map[string]any{}
	if leaf != nil {
		stmt["x5c"] = []any{leaf.Raw}
	}
	obj, err := webauthncbor.Marshal(map[string]any{"fmt": "packed", "attStmt": stmt, "authData": []byte{}})
	if err != nil {
		t.Fatal(err)
	}
	c.Attestation.Object = obj
	return c
}

// TestCheckAuthenticator_AllowAndDeny: an allow-list takes its models only
// with an attestation certificate that chains to the model's metadata root,
// and refuses another model, a hidden model, a "none" or self attestation, a
// certificate from another root (even one whose subject and issuer names
// match, the shortcut the library takes), and a model with no metadata entry.
// A deny-list refuses its models and lets a hidden model through; no list
// takes everything.
func TestCheckAuthenticator_AllowAndDeny(t *testing.T) {
	root, rootKey := certificate(t, "Yubico Root", true, nil, nil)
	leaf, _ := certificate(t, "YubiKey Attestation", false, root, rootKey)
	rogue, rogueKey := certificate(t, "Yubico Root", true, nil, nil)
	forged, _ := certificate(t, "Yubico Root", false, rogue, rogueKey)
	mds := noMetadata{entries: map[uuid.UUID]*metadata.Entry{
		uuid.MustParse(yubiKey5): {MetadataStatement: metadata.Statement{AttestationRootCertificates: []*x509.Certificate{root}}},
	}}
	allow := New(WithMetadata(mds), AllowAuthenticators(yubiKey5, onePassword))
	deny := New(DenyAuthenticators(onePassword))
	none := New()
	for _, p := range []*Plugin{allow, deny, none} {
		if _, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(p)); err != nil {
			t.Fatal(err)
		}
	}
	full := string(metadata.BasicFull)
	for _, tc := range []struct {
		name string
		p    *Plugin
		cred *webauthn.Credential
		want error
	}{
		{"allowed model, proven", allow, credOf(t, yubiKey5, full, leaf), nil},
		{"other model", allow, credOf(t, "ee882879-721c-4913-9775-3dfcce97072a", full, leaf), ErrAuthenticatorNotAllowed},
		{"hidden model", allow, credOf(t, "", full, leaf), ErrAuthenticatorNotAllowed},
		{"none attestation", allow, credOf(t, yubiKey5, "none", nil), ErrAuthenticatorNotAllowed},
		{"self attestation", allow, credOf(t, yubiKey5, string(metadata.BasicSurrogate), leaf), ErrAuthenticatorNotAllowed},
		{"no certificate", allow, credOf(t, yubiKey5, full, nil), ErrAuthenticatorNotAllowed},
		{"another root, same names", allow, credOf(t, yubiKey5, full, forged), ErrAuthenticatorNotAllowed},
		{"no metadata entry", allow, credOf(t, onePassword, full, leaf), ErrAuthenticatorNotAllowed},
		{"denied model", deny, credOf(t, onePassword, "none", nil), ErrAuthenticatorNotAllowed},
		{"other model, deny-list", deny, credOf(t, yubiKey5, "none", nil), nil},
		{"hidden model, deny-list", deny, credOf(t, "", "none", nil), nil},
		{"no policy", none, credOf(t, onePassword, "none", nil), nil},
	} {
		if err := tc.p.checkAuthenticator(context.Background(), tc.cred); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
}

// TestWellKnown_ListsTheOrigins: GET answers the plugin's origins as the
// Related Origin Requests document, HEAD the headers only, and any other
// method 405.
func TestWellKnown_ListsTheOrigins(t *testing.T) {
	p := New(RelyingParty("old.example.com", "https://old.example.com", "https://new.example.com"))
	if _, err := auth.New(auth.WithBaseURL("https://new.example.com"), auth.WithPlugins(p)); err != nil {
		t.Fatal(err)
	}
	h := p.WellKnown()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, WellKnownPath, nil))
	var doc wellKnown
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil || rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("GET = %d %q %v", rec.Code, rec.Body.String(), err)
	}
	if len(doc.Origins) != 2 || doc.Origins[1] != "https://new.example.com" {
		t.Fatalf("origins = %v", doc.Origins)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, WellKnownPath, nil))
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Fatalf("HEAD = %d, %d bytes", rec.Code, rec.Body.Len())
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, WellKnownPath, nil))
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST = %d, Allow %q", rec.Code, rec.Header().Get("Allow"))
	}
}

// downMetadata is a metadata provider that cannot be reached: GetEntry fails
// and counts its calls, so a test can tell the lookup ran.
type downMetadata struct {
	noMetadata
	calls *int
}

var errMetadataDown = errors.New("metadata service unreachable")

func (m downMetadata) GetEntry(context.Context, uuid.UUID) (*metadata.Entry, error) {
	*m.calls++
	return nil, errMetadataDown
}

// TestCheckAuthenticator_MetadataOutageRefuses: an allowed model whose
// certificate would chain is still refused while the metadata service
// fails, because nothing then vouches for the model; the refusal logs the
// service's error, so an outage reads as one and not as a rogue device.
func TestCheckAuthenticator_MetadataOutageRefuses(t *testing.T) {
	root, rootKey := certificate(t, "Yubico Root", true, nil, nil)
	leaf, _ := certificate(t, "YubiKey Attestation", false, root, rootKey)
	calls := 0
	p := New(WithMetadata(downMetadata{calls: &calls}), AllowAuthenticators(yubiKey5))
	var logs strings.Builder
	if _, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(p), auth.WithLogger(slog.New(slog.NewTextHandler(&logs, nil)))); err != nil {
		t.Fatal(err)
	}
	if err := p.checkAuthenticator(context.Background(), credOf(t, yubiKey5, string(metadata.BasicFull), leaf)); !errors.Is(err, ErrAuthenticatorNotAllowed) {
		t.Fatalf("err = %v, want ErrAuthenticatorNotAllowed", err)
	}
	if calls != 1 || !strings.Contains(logs.String(), errMetadataDown.Error()) {
		t.Fatalf("GetEntry called %d times; log %q does not name the outage", calls, logs.String())
	}
}
