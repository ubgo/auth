package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/csv"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/sso"
	"github.com/ubgo/auth/plugin/sso/ssotest"
)

const (
	testSecret = "an example secret of 32 bytes!!!"
	// adaID and adaEmail are the Supabase user import-users brought in, with
	// her verified address; she owns the providers.
	adaID    = "0b1f1c1e-0000-4000-8000-000000000001"
	adaEmail = "ada@example.com"
	// spEntity is the Supabase project's SP entity id, kept.
	spEntity = "https://abcdefghijklmnop.supabase.co/auth/v1/sso/saml/metadata"
)

// newWorld is a migrated database holding Ada, as import-users leaves it.
func newWorld(t *testing.T, opts ...sso.Option) (*auth.Auth, *sso.Plugin) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), dbFile))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	a, p, err := newAuth(db, baseURL, []byte(testSecret), opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	ctx := context.Background()
	if _, err := a.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	res, err := a.ImportUsers(ctx, []auth.ImportUser{{ID: adaID, Name: "Ada", Identities: []auth.ImportIdentity{
		{Kind: email.KindEmail, Value: adaEmail, Verified: true, Primary: true}}}})
	if err != nil || res[0].Err != nil {
		t.Fatalf("import Ada: %v %v", err, res)
	}
	return a, p
}

// TestImportSSO_Fixture imports the committed Supabase export: the provider
// with metadata XML lands under its resource_id with both domains, the
// Supabase SP entity id and the mapped attributes; the one Supabase knew
// only by metadata URL fails alone and says what to do.
func TestImportSSO_Fixture(t *testing.T) {
	a, p := newWorld(t)
	ctx := context.Background()
	rows, err := readSupabase("testdata/sso_providers.csv", "testdata/saml_providers.csv", "testdata/sso_domains.csv")
	if err != nil {
		t.Fatal(err)
	}
	res, err := importProviders(ctx, a, p, adaID, spEntity, rows)
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Err != nil || res[0].ProviderID != "example-okta" {
		t.Fatalf("first provider: %s %v", res[0].ProviderID, res[0].Err)
	}
	if len(res[0].Notes) != 1 || !strings.Contains(res[0].Notes[0], "department") {
		t.Fatalf("notes = %v, want the department attribute's second name", res[0].Notes)
	}
	if res[1].Err == nil || !strings.Contains(res[1].Err.Error(), "metadata_url") || res[1].ProviderID != supabaseIDPrefix+"5a1b2c3d-0000-4000-8000-00000000000b" {
		t.Fatalf("second provider: %s %v", res[1].ProviderID, res[1].Err)
	}
	pr, err := p.ProviderByID(ctx, "example-okta")
	if err != nil {
		t.Fatal(err)
	}
	if pr.Domain != "example.com,example.org" || pr.UserID != adaID || pr.SAML.SPMetadata.EntityID != spEntity ||
		pr.SAML.Mapping.Email != "mail" || pr.SAML.Mapping.Name != "displayName" || pr.SAML.Mapping.ExtraFields["department"] != "dept" {
		t.Fatalf("stored provider = %+v, SAML %+v", pr, pr.SAML)
	}
}

// TestImportSSO_ExistingUserSignsInThroughImportedProvider is the cutover:
// a provider imported from Supabase, trusted with sso.TrustProviders, signs
// Ada in through her IdP and lands on her imported account, not a new one.
// Without TrustProviders the same sign-in is refused (sso.account_exists),
// which is why the guide says to pass it.
func TestImportSSO_ExistingUserSignsInThroughImportedProvider(t *testing.T) {
	out, err := signInAfterImport(t, sso.TrustProviders("example-okta"))
	if err != nil {
		t.Fatal(err)
	}
	if out.User.ID != adaID || out.Created {
		t.Fatalf("SSO sign-in reached %s (created %v), want Ada's imported account %s", out.User.ID, out.Created, adaID)
	}
	if _, err := signInAfterImport(t); !errors.Is(err, sso.ErrAccountExists) {
		t.Fatalf("untrusted imported provider: %v, want sso.account_exists", err)
	}
}

// signInAfterImport imports one provider for ssotest's SAML IdP into a world
// built with opts, then runs Ada's SSO sign-in through it.
func signInAfterImport(t *testing.T, opts ...sso.Option) (sso.CallbackResult, error) {
	t.Helper()
	idp := ssotest.NewSAMLIdP(t, "https://idp.example.com/saml")
	a, p := newWorld(t, opts...)
	ctx := context.Background()
	dir := t.TempDir()
	writeCSV(t, dir, "p.csv", []string{"id", "resource_id"}, []string{"5a1b", "example-okta"})
	writeCSV(t, dir, "s.csv", []string{"sso_provider_id", "entity_id", "metadata_xml", "metadata_url", "attribute_mapping", "name_id_format"},
		[]string{"5a1b", idp.EntityID, metadataXML(idp), "", `{"keys":{"email":{"name":"mail"}}}`, sso.NameIDEmail})
	writeCSV(t, dir, "d.csv", []string{"sso_provider_id", "domain"}, []string{"5a1b", "example.com"})
	rows, err := readSupabase(filepath.Join(dir, "p.csv"), filepath.Join(dir, "s.csv"), filepath.Join(dir, "d.csv"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := importProviders(ctx, a, p, adaID, spEntity, rows)
	if err != nil || res[0].Err != nil {
		t.Fatalf("import: %v %v", err, res)
	}

	browser := a.WithRequest(ctx, auth.Request{Transport: auth.TransportHTTP, Client: auth.Client{Origin: baseURL}})
	start, err := p.SignIn(browser, sso.SignInRequest{Email: adaEmail, CallbackURL: "/home"})
	if err != nil {
		t.Fatal(err)
	}
	reqID, acs, relay := ssotest.AuthnRequest(t, start.URL)
	as := idp.Valid(acs, spEntity, reqID, adaEmail)
	as.Attributes = map[string][]string{"mail": {adaEmail}}
	return p.ACS(a.WithRequest(ctx, auth.Request{Transport: auth.TransportHTTP}), sso.ACSRequest{SAMLResponse: idp.Response(as), RelayState: relay})
}

// metadataXML is IdP metadata as Supabase stores it: entity id, signing
// certificate and SSO URL.
func metadataXML(idp *ssotest.SAMLIdP) string {
	return `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + idp.EntityID + `">` +
		`<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><KeyDescriptor use="signing">` +
		`<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>` + base64.StdEncoding.EncodeToString(idp.Cert.Raw) +
		`</X509Certificate></X509Data></KeyInfo></KeyDescriptor>` +
		`<SingleSignOnService Binding="` + sso.BindingRedirect + `" Location="` + idp.SSOURL + `"/></IDPSSODescriptor></EntityDescriptor>`
}

func writeCSV(t *testing.T, dir, name string, header []string, rows ...[]string) {
	t.Helper()
	f, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	w := csv.NewWriter(f)
	_ = w.Write(header)
	_ = w.WriteAll(rows)
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}
