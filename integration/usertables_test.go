package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/anonymous"
	"github.com/ubgo/auth/plugin/apikey"
	"github.com/ubgo/auth/plugin/audit"
	"github.com/ubgo/auth/plugin/captcha"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/handoff"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/lastlogin"
	"github.com/ubgo/auth/plugin/magiclink"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/passkey"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/phone"
	"github.com/ubgo/auth/plugin/sessiondata"
	"github.com/ubgo/auth/plugin/terms"
	"github.com/ubgo/auth/plugin/twofactor"
	"github.com/ubgo/auth/plugin/username"
	"github.com/ubgo/sqlb"
)

// userColumn is the column name every library table that belongs to a user
// gives that column. The guard below treats a table with a column of this
// name as user-owned; a plugin that names its user column otherwise must
// still register it, and the dynamic test is what catches that one.
const userColumn = "user_id"

// everyPlugin wires every built-in plugin, so a guard over "every table a
// migration creates" sees every table the library can create.
func everyPlugin(t *testing.T, e *env) []auth.Plugin {
	t.Helper()
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, auth.SealKeySize)
	return []auth.Plugin{
		e.emailPlugin(email.Multiple(), email.SignInWithCode(), email.VerifyByCode()),
		e.phonePlugin(phone.Login(), phone.Recover(), phone.SignInWithCode()),
		username.New(username.Login()),
		e.passwordPlugin(),
		oauth.New(oauth.WithProviders(oauth.Google("id", "secret"), oauth.GitHub("id", "secret"))),
		twofactor.New(twofactor.WithEncryptionKey(key), twofactor.DeliveredCodes(), twofactor.TrustDevices(0)),
		passkey.New(passkey.WithSignUp()),
		magiclink.New(), admin.New(), audit.New(), apikey.New(apikey.Scopes("read")),
		jwt.New(jwt.WithSigningKey(signing)), terms.New(terms.Current("2026-01")), anonymous.New(), handoff.New(), lastlogin.New(), sessiondata.New(),
		captcha.New(captcha.Turnstile("secret")), organization.New(),
	}
}

// TestGuard_UserTablesAreDeleted is the generic check behind ADR-0002: with
// every plugin wired, every table a migration creates that has a user column
// is registered in a.UserTables (so DeleteUser clears it), and every
// registered table and column exist in the schema (so the registry names
// nothing imaginary). A plugin that adds a user-owned table without listing
// it fails here, whatever its name.
//
// Proven by breaking: removing a plugin's UserTables method fails this test
// naming the table.
func TestGuard_UserTablesAreDeleted(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a := e.newAuth(t, nil, everyPlugin(t, e)...)
		ms := must[[]auth.Migration](t)(a.Migrations())
		schema := auth.ExpectedSchema(ms)
		registered := map[string]bool{}
		for _, ut := range a.UserTables() {
			cols, ok := schema[a.TableName(ut.Table)]
			if !ok || !slices.Contains(cols, ut.Column) {
				t.Errorf("registered user table %s.%s is not in the schema the migrations create", ut.Table.Name, ut.Column)
			}
			registered[a.TableName(ut.Table)+"."+ut.Column] = true
		}
		for table, cols := range schema {
			if slices.Contains(cols, userColumn) && !registered[table+"."+userColumn] {
				t.Errorf("table %s has a %s column but no plugin registers it in UserTables; its rows would survive the user", table, userColumn)
			}
		}
		// The core's own user tables are in the list too.
		for _, want := range []string{a.TableName(auth.TableIdentity) + "." + auth.ColIdentityUserID, a.TableName(auth.TableSession) + "." + auth.ColSessionUserID} {
			if !registered[want] {
				t.Errorf("%s is not registered", want)
			}
		}
	})
}

// TestDeleteUser_RemovesEveryRowInGo: a user with a password, a verified
// address, sessions, an API key, an OAuth account, a two-factor enrolment
// and an organization membership is deleted, and no row of any registered
// user table, no identity, token, code or session is left; the user next to
// it keeps everything. No foreign key exists to do any of this.
func TestDeleteUser_RemovesEveryRowInGo(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		ak := apikey.New(apikey.Scopes("orders:read"))
		plain := &tokensProvider{name: "plain", profile: oauth.Profile{Subject: "p-1", Email: alice, EmailVerified: true}}
		oa := oauth.New(oauth.WithProviders(plain))
		tf := twofactor.New(twofactor.WithEncryptionKey([]byte(strings.Repeat("k", auth.SealKeySize))))
		org := organization.New()
		a := e.newAuth(t, nil, em, pw, ak, oa, tf, org)
		ctx := context.Background()

		up := signUpVerified(t, e, a, pw, em)
		uctx := request(a, up.Token)
		must[apikey.CreateResult](t)(ak.Create(uctx, apikey.CreateRequest{Name: "ci", Scopes: []string{"orders:read"}}))
		enr := must[twofactor.EnrollResult](t)(tf.Enroll(uctx))
		must[twofactor.RecoveryCodes](t)(tf.Confirm(uctx, totpAt(t, enr.Secret, e.clock.Now())))
		must[organization.Org](t)(org.Create(uctx, organization.CreateRequest{Name: "Acme", Slug: "acme"}))
		// The OAuth account links to the same address, so the user owns one.
		b := &tokensBrowser{a: a}
		tokensMust(t, b.start("plain", oauth.StartRequest{}))
		if _, err := b.finish("plain"); err != nil {
			t.Fatalf("link oauth: %v", err)
		}
		// A token and a code filed under the user's keys.
		must[auth.Token](t)(a.IssueVerification(ctx, "test.token", up.User.ID, time.Hour, ""))
		must[string](t)(a.IssueCode(ctx, "test.code", alice, time.Hour))

		// A second user keeps every row of its own.
		other := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: "bob@example.com", Password: secret}))
		must[apikey.CreateResult](t)(ak.Create(request(a, other.Token), apikey.CreateRequest{Name: "bob", Scopes: []string{"orders:read"}}))

		countOwned := func(ut auth.UserTable, id string) int64 {
			var n int64
			col := sqlb.Col[string](ut.Table, ut.Column)
			if err := a.One(ctx, a.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(ut.Table).Where(sqlb.Eq(col, id))); err != nil {
				t.Fatalf("count %s: %v", ut.Table.Name, err)
			}
			return n
		}
		populated := 0
		for _, ut := range a.UserTables() {
			populated += int(countOwned(ut, up.User.ID))
		}
		if populated < 6 {
			t.Fatalf("only %d rows belong to the user before deletion; the test populated too little", populated)
		}

		if err := a.DeleteUser(ctx, up.User.ID); err != nil {
			t.Fatalf("delete: %v", err)
		}
		for _, ut := range a.UserTables() {
			if n := countOwned(ut, up.User.ID); n != 0 {
				t.Errorf("%s: %d rows of the deleted user remain", ut.Table.Name, n)
			}
			if ut.Table.Name == apikey.TableNameKey {
				if n := countOwned(ut, other.User.ID); n != 1 {
					t.Errorf("the other user's key is gone: %d", n)
				}
			}
		}
		if _, err := a.User(ctx, up.User.ID); !errors.Is(err, auth.ErrUserNotFound) {
			t.Fatalf("user after delete: %v", err)
		}
		var n int64
		if err := a.One(ctx, a.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(auth.TableSession).Where(sqlb.Eq(auth.SessionUserID, up.User.ID))); err != nil || n != 0 {
			t.Fatalf("sessions left = %d %v", n, err)
		}
		if err := a.One(ctx, a.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(auth.TableVerification).Where(sqlb.Eq(auth.VerificationIdentifier, up.User.ID))); err != nil || n != 0 {
			t.Fatalf("tokens left = %d %v", n, err)
		}
		if err := a.CheckCode(ctx, "test.code", alice, "000000", 0); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("a code of the deleted user must be gone: %v", err)
		}
		if _, err := a.User(ctx, other.User.ID); err != nil {
			t.Fatalf("the other user must remain: %v", err)
		}
	})
}

// TestCreateSession_RefusesAnUnknownUser pins what the session table's
// foreign key used to guarantee and the core now does in Go (ADR-0002): a
// session is never created for a user id that has no row, in any session
// mode, so a store outside the database is held to the same rule.
func TestCreateSession_RefusesAnUnknownUser(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		for name, opts := range map[string][]auth.Option{
			"sql store": nil,
			"memory":    {auth.WithSessionStore(auth.NewMemorySessionStore())},
			"stateless": {auth.WithStatelessSessions([]byte(strings.Repeat("k", auth.SealKeySize)))},
		} {
			a := e.newAuth(t, opts, e.emailPlugin(), e.passwordPlugin())
			if _, _, err := a.CreateSession(ctx, "usr_missing", auth.Client{}); !errors.Is(err, auth.ErrUserNotFound) {
				t.Errorf("%s: CreateSession for an unknown user = %v, want ErrUserNotFound", name, err)
			}
			var n int64
			if err := a.One(ctx, a.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(auth.TableSession)); err != nil || n != 0 {
				t.Errorf("%s: %d session rows after a refused creation, %v", name, n, err)
			}
			_ = a.Close()
		}
	})
}
