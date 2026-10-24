package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/phone"
	"github.com/ubgo/auth/plugin/username"
	"github.com/ubgo/sqlb"
)

// The passwords behind the bcrypt strings in testdata, so a test can prove an
// imported user signs in with the password they had.
const (
	adaPassword  = "correct horse battery"
	bobPassword  = "open sesame 42"
	totpSecret   = "JBSWY3DPEHPK3PXP"
	testTOTPKey  = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	argon2Prefix = "$argon2id$"
)

// TestImport_Auth0: an Auth0 export lands with ids and sign-up times kept,
// the bcrypt password signs the user in and is re-hashed, the Google account
// and the authenticator secret follow, a blocked user is listed for the
// admin, and a duplicate address fails alone. A second run imports nothing
// and changes nothing.
func TestImport_Auth0(t *testing.T) {
	a, d := newTestAuth(t, true)
	recs := readFixture(t, readAuth0, "auth0.ndjson", "", "")
	s := importRecords(context.Background(), a, d, recs, false)
	if s.Imported != 3 || s.Failed != 1 || s.Skipped != 0 {
		t.Fatalf("summary: %+v", s)
	}
	dup := s.Outcomes[3]
	if !errors.Is(dup.Err, auth.ErrIdentityTaken) || dup.UserID != "" {
		t.Fatalf("the duplicate address: %+v", dup)
	}
	// Carol was blocked in Auth0: a permanent ban here, with the reason.
	if c := adminColumns(t, a, "auth0|blocked0001"); c.BannedAt == nil || c.BanExpiresAt != nil || c.BanReason != auth0BlockedReason {
		t.Fatalf("Carol's ban: %+v", c)
	}

	ctx := context.Background()
	ada, err := a.User(ctx, "auth0|5f1a2b3c4d5e6f7a8b9c0d1e")
	if err != nil || ada.Name != "Ada Lovelace" || !ada.CreatedAt.Equal(time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC)) {
		t.Fatalf("Ada: %+v %v", ada, err)
	}
	ids := identitiesOf(t, a, ada.ID)
	if ids[email.KindEmail] != "ada@example.com verified primary" || ids[username.KindUsername] != "ada verified primary" {
		t.Fatalf("Ada's identities: %v", ids)
	}
	// The old password works once against the bcrypt string, and the row
	// then holds argon2id.
	if !strings.HasPrefix(storedHash(t, a, ada.ID), "$2a$") {
		t.Fatal("the bcrypt string was not stored as it was")
	}
	signIn(t, a, d.Password, "ada@example.com", adaPassword)
	if h := storedHash(t, a, ada.ID); !strings.HasPrefix(h, argon2Prefix) {
		t.Fatalf("after sign-in the hash is %q, want argon2id", h)
	}
	accounts, err := d.OAuth.Accounts(ctx, ada.ID)
	if err != nil || len(accounts) != 1 || accounts[0].Provider != "google" {
		t.Fatalf("Ada's accounts: %+v %v", accounts, err)
	}
	if on, err := d.TwoFactor.SecondFactorRequired(ctx, ada.ID); err != nil || !on {
		t.Fatalf("Ada's second factor: %v %v", on, err)
	}
	// Bob is a social-only account with a verified phone number.
	bob, err := a.User(ctx, "github|8675309")
	if err != nil {
		t.Fatal(err)
	}
	if ids := identitiesOf(t, a, bob.ID); ids[phone.KindPhone] != "+15555550100 verified primary" {
		t.Fatalf("Bob's identities: %v", ids)
	}
	if has, err := d.Password.HasPassword(ctx, bob.ID); err != nil || has {
		t.Fatalf("Bob has a password: %v %v", has, err)
	}
	// Run twice: every user exists, nothing is written, nothing is lost.
	again := importRecords(ctx, a, d, recs, false)
	if again.Imported != 0 || again.Failed != 4 {
		t.Fatalf("second run: %+v", again)
	}
	for _, o := range again.Outcomes[:3] {
		if !errors.Is(o.Err, auth.ErrUserExists) {
			t.Fatalf("second run should refuse the id: %v", o.Err)
		}
	}
	if h := storedHash(t, a, ada.ID); !strings.HasPrefix(h, argon2Prefix) {
		t.Fatalf("the second run touched Ada's hash: %q", h)
	}
}

// TestImport_Clerk: a Clerk CSV with several addresses per user, a bcrypt
// digest, a phone number and a TOTP secret; a digest in a hasher the plugin
// cannot verify is reported and the user has no password.
func TestImport_Clerk(t *testing.T) {
	a, d := newTestAuth(t, true)
	recs := readFixture(t, readClerk, "clerk.csv", "", "")
	s := importRecords(context.Background(), a, d, recs, false)
	if s.Imported != 2 || s.Failed != 0 {
		t.Fatalf("summary: %+v", s)
	}
	ctx := context.Background()
	ada := s.Outcomes[0].UserID
	all, err := a.Identities(ctx, ada)
	if err != nil {
		t.Fatal(err)
	}
	var verified, primary int
	for _, id := range all {
		if id.Kind == email.KindEmail && id.Verified() {
			verified++
		}
		if id.Kind == email.KindEmail && id.IsPrimary {
			primary++
			if id.Value != "ada@example.com" {
				t.Fatalf("primary address: %s", id.Value)
			}
		}
	}
	if verified != 2 || primary != 1 || len(all) != 5 { // 3 addresses, 1 number, 1 handle
		t.Fatalf("Ada's identities: verified %d primary %d of %d", verified, primary, len(all))
	}
	signIn(t, a, d.Password, "ada@example.com", bobPassword)
	if on, err := d.TwoFactor.SecondFactorRequired(ctx, ada); err != nil || !on {
		t.Fatalf("Ada's second factor: %v %v", on, err)
	}
	bob := s.Outcomes[1]
	if len(bob.Notes) != 1 || !strings.Contains(bob.Notes[0], "scrypt_firebase") {
		t.Fatalf("Bob's notes: %v", bob.Notes)
	}
	if has, err := d.Password.HasPassword(ctx, bob.UserID); err != nil || has {
		t.Fatalf("Bob has a password: %v %v", has, err)
	}
}

// TestImport_Supabase: users, identities and factors joined on the user id;
// the super admin is granted, the banned user listed, the anonymous and the
// deleted rows skipped, an unverified factor left behind.
func TestImport_Supabase(t *testing.T) {
	a, d := newTestAuth(t, true)
	recs := readFixture(t, readSupabase, "supabase-users.csv", "supabase-identities.csv", "supabase-factors.csv")
	s := importRecords(context.Background(), a, d, recs, false)
	if s.Imported != 3 || s.Failed != 0 || s.Skipped != 2 {
		t.Fatalf("summary: %+v", s)
	}
	if s.Outcomes[2].Record.Skip == "" || s.Outcomes[4].Record.Skip == "" {
		t.Fatalf("skips: %q %q", s.Outcomes[2].Record.Skip, s.Outcomes[4].Record.Skip)
	}
	ctx := context.Background()
	ada := "0b1f1c1e-0000-4000-8000-000000000001"
	if u, err := a.User(ctx, ada); err != nil || u.Name != "Ada Lovelace" || u.Image != "https://lh3.example/ada" {
		t.Fatalf("Ada: %+v %v", u, err)
	}
	if c := adminColumns(t, a, ada); c.AdminGrantedAt == nil {
		t.Fatalf("Ada is admin: %+v", c)
	}
	accounts, err := d.OAuth.Accounts(ctx, ada)
	if err != nil || len(accounts) != 1 || accounts[0].Provider != "google" || accounts[0].Email != "ada@gmail.example" {
		t.Fatalf("Ada's accounts: %+v %v", accounts, err)
	}
	if on, err := d.TwoFactor.SecondFactorRequired(ctx, ada); err != nil || !on {
		t.Fatalf("Ada's second factor: %v %v", on, err)
	}
	signIn(t, a, d.Password, "ada@example.com", adaPassword)
	bob := "0b1f1c1e-0000-4000-8000-000000000002"
	if ids := identitiesOf(t, a, bob); ids[phone.KindPhone] != "+15555550102 verified primary" || len(ids) != 1 {
		t.Fatalf("Bob's identities: %v", ids)
	}
	// Dave's ban carries its end; Ada, never banned, has no ban columns.
	dave := "0b1f1c1e-0000-4000-8000-000000000004"
	if c := adminColumns(t, a, dave); c.BannedAt == nil || c.BanExpiresAt == nil || !c.BanExpiresAt.Equal(time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)) || c.BanReason != sbBannedReason {
		t.Fatalf("Dave's ban: %+v", c)
	}
	if c := adminColumns(t, a, ada); c.BannedAt != nil {
		t.Fatalf("Ada is banned: %+v", c)
	}
	if on, err := d.TwoFactor.SecondFactorRequired(ctx, dave); err != nil || on {
		t.Fatalf("Dave's unverified factor was imported: %v %v", on, err)
	}
}

// TestImport_AuthJS: users and accounts arrays; an oidc account is linked, an
// email-provider account is not, and a null emailVerified is unverified.
func TestImport_AuthJS(t *testing.T) {
	a, d := newTestAuth(t, false)
	recs := readFixture(t, readAuthJS, "authjs-users.json", "authjs-accounts.json", "")
	s := importRecords(context.Background(), a, d, recs, false)
	if s.Imported != 2 || s.Failed != 0 {
		t.Fatalf("summary: %+v", s)
	}
	ctx := context.Background()
	accounts, err := d.OAuth.Accounts(ctx, "clu1ada")
	if err != nil || len(accounts) != 1 || accounts[0].Provider != "google" {
		t.Fatalf("Ada's accounts: %+v %v", accounts, err)
	}
	if accounts, err := d.OAuth.Accounts(ctx, "clu2bob"); err != nil || len(accounts) != 0 {
		t.Fatalf("Bob's accounts: %+v %v", accounts, err)
	}
	if ids := identitiesOf(t, a, "clu2bob"); ids[email.KindEmail] != "bob@example.com" {
		t.Fatalf("Bob's address should be unverified: %v", ids)
	}
}

// TestImport_WorkOS: the API's page envelope reads, every user arrives
// without a password and the summary says why.
func TestImport_WorkOS(t *testing.T) {
	a, d := newTestAuth(t, false)
	recs := readFixture(t, readWorkOS, "workos.json", "", "")
	s := importRecords(context.Background(), a, d, recs, false)
	if s.Imported != 2 || s.Failed != 0 {
		t.Fatalf("summary: %+v", s)
	}
	for _, o := range s.Outcomes {
		if len(o.Notes) != 1 || !strings.Contains(o.Notes[0], "forgot flow") {
			t.Fatalf("notes: %v", o.Notes)
		}
		if has, err := d.Password.HasPassword(context.Background(), o.UserID); err != nil || has {
			t.Fatalf("%s has a password: %v %v", o.UserID, has, err)
		}
	}
	if u, err := a.User(context.Background(), "user_01HXAMPLE0000000000000ADA"); err != nil || u.Name != "Ada Lovelace" {
		t.Fatalf("Ada: %+v %v", u, err)
	}
}

// TestImport_WithoutTOTPKey: with no key the twofactor plugin is not wired,
// the user still lands and the summary says the factor was not imported.
func TestImport_WithoutTOTPKey(t *testing.T) {
	a, d := newTestAuth(t, false)
	recs := readFixture(t, readAuth0, "auth0.ndjson", "", "")
	s := importRecords(context.Background(), a, d, recs[:1], false)
	if s.Imported != 1 || len(s.Outcomes[0].Notes) != 1 || !strings.Contains(s.Outcomes[0].Notes[0], "two-factor not imported") {
		t.Fatalf("summary: %+v", s)
	}
}

// TestImport_Run: the command end to end. A dry run writes nothing, not even
// the tables; a real run on the Auth0 fixture reports the failed row in its
// output and its exit.
func TestImport_Run(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "import.db")
	var out bytes.Buffer
	err := run(context.Background(), &out, sourceAuth0, filepath.Join("testdata", "auth0.ndjson"), "", "", dbPath, true, testTOTPKey)
	if err != nil || !strings.HasPrefix(out.String(), "would import 4 user(s), 0 failed, 0 skipped") {
		t.Fatalf("dry run: %v\n%s", err, out.String())
	}
	if tables := tableCount(t, dbPath); tables != 0 {
		t.Fatalf("a dry run created %d table(s)", tables)
	}
	out.Reset()
	err = run(context.Background(), &out, sourceAuth0, filepath.Join("testdata", "auth0.ndjson"), "", "", dbPath, false, testTOTPKey)
	if err == nil || !strings.Contains(err.Error(), "1 user(s) not imported") {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out.String(), "imported 3 user(s), 1 failed, 0 skipped") || !strings.Contains(out.String(), "FAILED ada@example.com") {
		t.Fatalf("report:\n%s", out.String())
	}
	// Bad arguments are refused before anything is opened.
	for name, args := range map[string][4]string{
		"source": {"okta", "x", "", testTOTPKey},
		"file":   {sourceAuth0, "", "", testTOTPKey},
		"key":    {sourceAuth0, filepath.Join("testdata", "auth0.ndjson"), "", "short"},
		"open":   {sourceAuth0, filepath.Join(dir, "missing.ndjson"), "", testTOTPKey},
	} {
		if err := run(context.Background(), &out, args[0], args[1], args[2], "", filepath.Join(dir, name+".db"), true, args[3]); err == nil {
			t.Fatalf("%s: no error", name)
		}
	}
	if err := run(context.Background(), &out, sourceSupabase, filepath.Join("testdata", "supabase-users.csv"), filepath.Join(dir, "missing.csv"), "", filepath.Join(dir, "sb.db"), true, ""); err == nil {
		t.Fatal("a missing identities file: no error")
	}
	if err := run(context.Background(), &out, sourceSupabase, filepath.Join("testdata", "supabase-users.csv"), filepath.Join("testdata", "supabase-identities.csv"), filepath.Join(dir, "missing.csv"), filepath.Join(dir, "sb2.db"), true, ""); err == nil {
		t.Fatal("a missing factors file: no error")
	}
}

// TestReaders_Malformed: each reader names the file and the line it could
// not read, and never panics on a short or odd input.
func TestReaders_Malformed(t *testing.T) {
	cases := map[string]struct {
		read reader
		in   input
	}{
		"auth0 json":         {readAuth0, input{Main: strings.NewReader("{not json\n")}},
		"clerk header":       {readClerk, input{Main: strings.NewReader("")}},
		"clerk row":          {readClerk, input{Main: strings.NewReader("id,first_name\n\"unterminated\n")}},
		"supabase header":    {readSupabase, input{Main: strings.NewReader("")}},
		"supabase ids":       {readSupabase, input{Main: strings.NewReader("id\nx\n"), Identities: strings.NewReader("")}},
		"supabase factors":   {readSupabase, input{Main: strings.NewReader("id\nx\n"), Factors: strings.NewReader("")}},
		"supabase bad row":   {readSupabase, input{Main: strings.NewReader("id\n\"unterminated\n")}},
		"authjs users":       {readAuthJS, input{Main: strings.NewReader("nope")}},
		"authjs accounts":    {readAuthJS, input{Main: strings.NewReader("[]"), Identities: strings.NewReader("nope")}},
		"workos not json":    {readWorkOS, input{Main: strings.NewReader("nope")}},
		"workos wrong shape": {readWorkOS, input{Main: strings.NewReader(`{"data": "x"}`)}},
	}
	for name, c := range cases {
		if _, err := c.read(c.in); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	// A short Clerk row reads missing cells as empty, and a Supabase user with
	// odd metadata keeps the row.
	recs, err := readClerk(input{Main: strings.NewReader("id,first_name,password_digest,password_hasher\nu1,Ada\n")})
	if err != nil || len(recs) != 1 || recs[0].Name != "Ada" || recs[0].PasswordHash != "" {
		t.Fatalf("short Clerk row: %+v %v", recs, err)
	}
	recs, err = readSupabase(input{Main: strings.NewReader("id,raw_user_meta_data\nu1,not-json\n")})
	if err != nil || len(recs) != 1 || recs[0].Name != "" {
		t.Fatalf("odd metadata: %+v %v", recs, err)
	}
	recs, err = readSupabase(input{Main: strings.NewReader("id\nu1\n"), Identities: strings.NewReader("user_id,provider,provider_id,identity_data\nu1,github,42,not-json\n")})
	if err != nil || len(recs) != 1 || len(recs[0].Accounts) != 1 || recs[0].Accounts[0].Email != "" {
		t.Fatalf("odd identity_data: %+v %v", recs, err)
	}
	// A WorkOS bare array reads too.
	recs, err = readWorkOS(input{Main: strings.NewReader(`[{"id":"u1","email":"a@example.com"}]`)})
	if err != nil || len(recs) != 1 || recs[0].ID != "u1" {
		t.Fatalf("bare array: %+v %v", recs, err)
	}
	// An Auth0 line too long for the buffer is an error, not a truncated user.
	if _, err := readAuth0(input{Main: strings.NewReader(`{"user_id":"` + strings.Repeat("x", scanBufferSize) + `"}` + "\n")}); err == nil {
		t.Fatal("an oversized line: no error")
	}
}

// TestHelpers: the pure functions that decide shape.
func TestHelpers(t *testing.T) {
	for in, want := range map[string]time.Time{
		"2021-03-04T05:06:07.000Z":          time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC),
		"2021-03-04 05:06:07.123456+00":     time.Date(2021, 3, 4, 5, 6, 7, 123456000, time.UTC),
		"2021-03-04 05:06:07+02:00":         time.Date(2021, 3, 4, 3, 6, 7, 0, time.UTC),
		"2021-03-04 05:06:07":               time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC),
		"":                                  {},
		"yesterday":                         {},
		"2021-03-04T05:06:07.000+01:00":     time.Date(2021, 3, 4, 4, 6, 7, 0, time.UTC),
		" 2021-03-04T05:06:07Z ":            time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC),
		"2021-03-04 05:06:07.5-07":          time.Date(2021, 3, 4, 12, 6, 7, 500000000, time.UTC),
		"2021-03-04T05:06:07.000Z trailing": {},
	} {
		if got := parseTime(in); !got.Equal(want) {
			t.Errorf("parseTime(%q) = %v, want %v", in, got, want)
		}
	}
	if got := splitList("a@x.example, b@x.example;c@x.example|d@x.example"); len(got) != 4 {
		t.Errorf("splitList: %v", got)
	}
	// The primary of a kind is the marked verified one, else the first
	// verified one, never an unverified one.
	ids := identities(email.KindEmail, []identifier{{Value: "a", Verified: false, Primary: true}, {Value: "b", Verified: true}, {Value: "c", Verified: true}})
	if ids[0].Primary || !ids[1].Primary || ids[2].Primary {
		t.Errorf("primary choice: %+v", ids)
	}
	ids = identities(email.KindEmail, []identifier{{Value: "a", Verified: true}, {Value: "b", Verified: true, Primary: true}})
	if ids[0].Primary || !ids[1].Primary {
		t.Errorf("marked primary: %+v", ids)
	}
	ids = identities(email.KindEmail, []identifier{{Value: "a"}})
	if ids[0].Primary {
		t.Errorf("an unverified only address is not primary: %+v", ids)
	}
	if (record{}).label() != "" || (record{ID: "x"}).label() != "x" || (record{Phones: []identifier{{Value: "+1"}}}).label() != "+1" {
		t.Error("label")
	}
	if names := sourceNames(); strings.Join(names, ",") != "auth0,authjs,clerk,supabase,workos" {
		t.Errorf("sourceNames: %v", names)
	}
	if _, err := totpKey("zz"); !errors.Is(err, errBadKey) {
		t.Errorf("totpKey(zz): %v", err)
	}
	if k, err := totpKey(""); err != nil || k != nil {
		t.Errorf("totpKey(): %v %v", k, err)
	}
	// Dry-run notes name every credential a wiring would drop.
	notes := planNotes(record{PasswordNote: "n", Accounts: []account{{}}, TOTPSecret: "s", Banned: true}, deps{})
	if len(notes) != 4 {
		t.Errorf("planNotes: %v", notes)
	}
	// A record with a hash but no password plugin fails rather than landing
	// without its password.
	a, _ := newTestAuth(t, false)
	s := importRecords(context.Background(), a, deps{}, []record{{ID: "u1", PasswordHash: "$2a$10$x", Emails: []identifier{{Value: "a@example.com", Verified: true}}}}, false)
	if s.Failed != 1 || !errors.Is(s.Outcomes[0].Err, errNoHasher) {
		t.Errorf("no hasher: %+v", s)
	}
	if _, err := a.User(context.Background(), "u1"); !errors.Is(err, auth.ErrUserNotFound) {
		t.Errorf("the failed row left a user: %v", err)
	}
	// Without the oauth, twofactor and admin plugins the user lands with notes.
	s = importRecords(context.Background(), a, deps{}, []record{{ID: "u2", Accounts: []account{{Provider: "google", AccountID: "1"}}, TOTPSecret: totpSecret, Admin: true, Banned: true}}, false)
	if s.Imported != 1 || len(s.Outcomes[0].Notes) != 3 {
		t.Errorf("notes without plugins: %+v", s.Outcomes[0])
	}
	// A Supabase ban that already lapsed is history, not a ban; one in force
	// is imported with its end. The clock is pinned so the fixture's dates
	// stay meaningful.
	now = func() time.Time { return time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { now = time.Now })
	recs, err := readSupabase(input{Main: strings.NewReader("id,banned_until\nu1,2020-01-01 00:00:00+00\nu2,2099-01-01 00:00:00+00\nu3,\n")})
	if err != nil || recs[0].Banned || !recs[1].Banned || recs[1].BannedUntil.Year() != 2099 || recs[2].Banned {
		t.Errorf("Supabase bans: %+v %v", recs, err)
	}
	// The mailer and the texter are loggers: they return nil.
	if err := (logMailer{}).Send(context.Background(), email.Mail{}); err != nil {
		t.Error(err)
	}
	if err := (logSMS{}).Send(context.Background(), "", ""); err != nil {
		t.Error(err)
	}
}

// TestImport_UnconfiguredProviderIsANote: an account for a provider the app
// does not offer is reported, not written, and the user still lands.
func TestImport_UnconfiguredProviderIsANote(t *testing.T) {
	a, d := newTestAuth(t, false)
	s := importRecords(context.Background(), a, d, []record{{ID: "u1", Accounts: []account{{Provider: "facebook", AccountID: "1"}, {Provider: "google", AccountID: "2"}}}}, false)
	if s.Imported != 1 || len(s.Outcomes[0].Notes) != 1 || !strings.Contains(s.Outcomes[0].Notes[0], "facebook") {
		t.Fatalf("summary: %+v", s.Outcomes[0])
	}
	if accounts, err := d.OAuth.Accounts(context.Background(), "u1"); err != nil || len(accounts) != 1 || accounts[0].Provider != "google" {
		t.Fatalf("accounts: %+v %v", accounts, err)
	}
}

// newTestAuth builds the importer's Auth on a fresh SQLite file, with or
// without the two-factor key.
func newTestAuth(t *testing.T, withTOTP bool) (*auth.Auth, deps) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	var key []byte
	if withTOTP {
		key, err = hex.DecodeString(testTOTPKey)
		if err != nil {
			t.Fatal(err)
		}
	}
	a, d, err := newAuth(db, logMailer{}, logSMS{}, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a, d
}

// readFixture reads testdata files through a reader.
func readFixture(t *testing.T, read reader, main, identities, factors string) []record {
	t.Helper()
	open := func(name string) *os.File {
		if name == "" {
			return nil
		}
		f, err := os.Open(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		return f
	}
	in := input{Main: open(main)}
	if f := open(identities); f != nil {
		in.Identities = f
	}
	if f := open(factors); f != nil {
		in.Factors = f
	}
	recs, err := read(in)
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

// signIn signs a user in through the password plugin's Go API as a browser
// on the app would, and fails the test when the password is refused.
func signIn(t *testing.T, a *auth.Auth, pw *password.Plugin, identifier, secret string) {
	t.Helper()
	ctx := a.WithRequest(context.Background(), auth.Request{
		Transport: auth.TransportHTTP,
		Client:    auth.Client{IP: "203.0.113.7", UserAgent: "test", Origin: baseURL},
	})
	if _, err := pw.SignIn(ctx, password.SignInRequest{Identifier: identifier, Password: password.Secret(secret)}); err != nil {
		t.Fatalf("sign in as %s with the imported password: %v", identifier, err)
	}
}

// storedHash reads a user's auth_password row.
func storedHash(t *testing.T, a *auth.Auth, userID string) string {
	t.Helper()
	var h string
	q := a.Select().Columns(sqlb.Bind(password.Hash, &h)).From(password.TablePassword).Where(sqlb.Eq(password.UserID, userID))
	if err := a.One(context.Background(), q); err != nil {
		t.Fatalf("hash of %s: %v", userID, err)
	}
	return h
}

// identitiesOf summarizes a user's identities as "kind: value [verified]
// [primary]", one entry per kind, for compact assertions.
func identitiesOf(t *testing.T, a *auth.Auth, userID string) map[auth.IdentifierKindName]string {
	t.Helper()
	all, err := a.Identities(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	out := map[auth.IdentifierKindName]string{}
	for _, id := range all {
		s := id.Value
		if id.Verified() {
			s += " verified"
		}
		if id.IsPrimary {
			s += " primary"
		}
		out[id.Kind] = s
	}
	return out
}

// adminColumns reads a user's admin plugin columns.
func adminColumns(t *testing.T, a *auth.Auth, userID string) admin.AdminColumns {
	t.Helper()
	var c admin.AdminColumns
	if err := a.LoadUserColumns(context.Background(), userID, admin.Bindings(&c)...); err != nil {
		t.Fatalf("admin columns of %s: %v", userID, err)
	}
	return c
}

// tableCount counts the tables in a SQLite file.
func tableCount(t *testing.T, path string) int {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type = 'table'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
