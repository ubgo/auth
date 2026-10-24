package passkey

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
)

// TestInit_BaseURLWithoutAHostIsRefused: the relying party id is the BaseURL's
// host, so a BaseURL without one is a start-up error, not a ceremony that can
// never verify.
func TestInit_BaseURLWithoutAHostIsRefused(t *testing.T) {
	for _, base := range []string{"app.example.com", "https://%zz"} {
		if _, err := auth.New(auth.WithBaseURL(base), auth.WithPlugins(New())); err == nil {
			t.Errorf("BaseURL %q: want an error", base)
		}
	}
}

// TestInit_InvalidRelyingPartyIsRefused: the WebAuthn library refuses an id
// that is not a domain; its refusal surfaces at start-up, marked as the
// plugin's, rather than at the first ceremony.
func TestInit_InvalidRelyingPartyIsRefused(t *testing.T) {
	_, err := auth.New(auth.WithPlugins(New(RelyingParty("not a domain!", "https://app.example.com"))))
	if err == nil || !strings.Contains(err.Error(), "passkey: ") {
		t.Fatalf("invalid relying party id: %v", err)
	}
}

func TestMigrations_PerEngine(t *testing.T) {
	p := New()
	if _, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(p)); err != nil {
		t.Fatal(err)
	}
	indexUser := TableNamePasskey + indexUserSuffix
	if _, err := p.TypedMigrations("oracle", auth.TypesFor("oracle")); err == nil {
		t.Fatal("an unknown engine must be refused")
	}
	my, err := p.TypedMigrations(auth.EngineMySQL, auth.TypesFor(auth.EngineMySQL))
	if err != nil || len(my) != 2 || len(my[0].Statements) != 1 || !strings.Contains(my[0].Statements[0], "INDEX "+indexUser+" (") || len(my[1].Statements) != 1 {
		t.Fatalf("mysql declares the index inside CREATE TABLE: %+v, %v", my, err)
	}
	pg, err := p.TypedMigrations(auth.EnginePostgres, auth.TypesFor(auth.EnginePostgres))
	if err != nil || len(pg) != 2 || len(pg[0].Statements) != 2 || !strings.HasPrefix(pg[0].Statements[1], "CREATE INDEX IF NOT EXISTS "+indexUser) || len(pg[1].Statements) != 2 {
		t.Fatalf("postgres creates the index separately: %+v, %v", pg, err)
	}
}

// TestWAUser_AccountNameFallsBackToID: the AccountName result names the
// account and, for a user without a name, is also what the prompt shows; with
// no account name both fall back to the user id.
func TestWAUser_AccountNameFallsBackToID(t *testing.T) {
	named := &waUser{u: auth.User{ID: "usr_1"}, name: "pat@example.com"}
	if named.WebAuthnName() != "pat@example.com" || named.WebAuthnDisplayName() != "pat@example.com" {
		t.Fatalf("with an account name: %q %q", named.WebAuthnName(), named.WebAuthnDisplayName())
	}
}

func TestWAUser_DisplayNameFallsBackToID(t *testing.T) {
	if got := (&waUser{u: auth.User{ID: "usr_1"}}).WebAuthnDisplayName(); got != "usr_1" {
		t.Fatalf("no name: %q, want the id", got)
	}
	w := &waUser{u: auth.User{ID: "usr_1", Name: "Pat"}}
	if w.WebAuthnDisplayName() != "Pat" || w.WebAuthnName() != "usr_1" || string(w.WebAuthnID()) != "usr_1" {
		t.Fatalf("user = %q %q %q", w.WebAuthnDisplayName(), w.WebAuthnName(), w.WebAuthnID())
	}
}

// TestSignInCredentials_WithoutADatabaseIsAnError: the core's last-way-in
// check must see a failure, never a count of zero it would act on.
func TestSignInCredentials_WithoutADatabaseIsAnError(t *testing.T) {
	p := New()
	if _, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(p)); err != nil {
		t.Fatal(err)
	}
	if n, err := p.SignInCredentials(context.Background(), "usr_1", ""); !errors.Is(err, auth.ErrNoDatabase) || n != 0 {
		t.Fatalf("SignInCredentials = %d, %v; want ErrNoDatabase", n, err)
	}
}

func TestAAGUIDString(t *testing.T) {
	raw := []byte{0xba, 0xda, 0x55, 0x66, 0xa7, 0xaa, 0x40, 0x1f, 0xbd, 0x96, 0x45, 0x61, 0x9a, 0x55, 0x12, 0x0d}
	if got := aaguidString(raw); got != "bada5566-a7aa-401f-bd96-45619a55120d" {
		t.Fatalf("aaguid = %s", got)
	}
	if aaguidString(make([]byte, aaguidLen)) != "" || aaguidString([]byte{1, 2}) != "" || aaguidString(nil) != "" {
		t.Fatal("zero, short or missing AAGUIDs must be empty, never a guess")
	}
}

// TestAuthenticatorName_KnownAndUnknown: a known AAGUID has a name in any
// case; an unknown or empty one is "", so a page falls back to its own label.
func TestAuthenticatorName_KnownAndUnknown(t *testing.T) {
	if got := AuthenticatorName(" BADA5566-A7AA-401F-BD96-45619A55120D "); got != "1Password" {
		t.Fatalf("name = %q", got)
	}
	if AuthenticatorName("") != "" || AuthenticatorName("00000000-0000-0000-0000-000000000000") != "" || AuthenticatorName("not-an-aaguid") != "" {
		t.Fatal("unknown AAGUIDs must have no name")
	}
}

// TestOperations_IncludeRename: the rename operation exists and needs only a
// signed-in session, since a label is not a credential.
func TestOperations_IncludeRename(t *testing.T) {
	for _, op := range New().Operations() {
		if op.Info().ID == EndpointRename {
			if op.Info().Require != auth.SignedIn {
				t.Fatalf("rename requirement = %s", op.Info().Require)
			}
			return
		}
	}
	t.Fatal("rename operation missing")
}

// TestAuthenticatorSelection_Validated: a level or an attachment WebAuthn
// does not define fails auth.New; valid values reach the relying party, and
// empty fields keep the required defaults.
func TestAuthenticatorSelection_Validated(t *testing.T) {
	base := auth.WithBaseURL("https://app.example.com")
	for _, bad := range []Selection{{ResidentKey: "always"}, {UserVerification: "Required"}, {Attachment: "usb"}} {
		if _, err := auth.New(base, auth.WithPlugins(New(AuthenticatorSelection(bad)))); !errors.Is(err, ErrSelectionInvalid) {
			t.Errorf("%+v: err = %v", bad, err)
		}
	}
	p := New(AuthenticatorSelection(Selection{ResidentKey: RequirementDiscouraged, Attachment: AttachmentCrossPlatform}))
	if _, err := auth.New(base, auth.WithPlugins(p)); err != nil {
		t.Fatal(err)
	}
	sel := p.wa.Config.AuthenticatorSelection
	if string(sel.ResidentKey) != "discouraged" || *sel.RequireResidentKey || string(sel.UserVerification) != "required" || string(sel.AuthenticatorAttachment) != AttachmentCrossPlatform {
		t.Fatalf("selection = %+v", sel)
	}
	d := New()
	if _, err := auth.New(base, auth.WithPlugins(d)); err != nil {
		t.Fatal(err)
	}
	if sel := d.wa.Config.AuthenticatorSelection; string(sel.ResidentKey) != "required" || !*sel.RequireResidentKey {
		t.Fatalf("default selection = %+v", sel)
	}
}

// TestInit_SchemeOnlyBaseURLIsRefused: a BaseURL the core accepts but that
// names no host, a native app's own scheme, gives no relying party id, so
// start-up fails with ErrNoRelyingParty rather than every ceremony later.
func TestInit_SchemeOnlyBaseURLIsRefused(t *testing.T) {
	if _, err := auth.New(auth.WithBaseURL("myapp://"), auth.WithPlugins(New())); !errors.Is(err, ErrNoRelyingParty) {
		t.Fatalf("BaseURL myapp://: err = %v, want ErrNoRelyingParty", err)
	}
	if _, err := auth.New(auth.WithBaseURL("myapp://"), auth.WithPlugins(New(RelyingParty("app.example.com", "https://app.example.com")))); err != nil {
		t.Fatalf("an explicit relying party beside a scheme-only BaseURL: %v", err)
	}
}
