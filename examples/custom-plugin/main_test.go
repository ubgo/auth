package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/examples/custom-plugin/referral"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
)

const (
	aliceEmail   = "alice@example.com"
	bobEmail     = "bob@example.com"
	testPassword = "correct horse battery staple"
)

// codeShape is what newCode produces: 8 characters of unpadded base32.
var codeShape = regexp.MustCompile(`^[A-Z2-7]{8}$`)

// TestReferral_EveryNewUserGetsACode signs two users up and reads their codes
// through the plugin's route and through the app's composite user.
func TestReferral_EveryNewUserGetsACode(t *testing.T) {
	a := newTestAuth(t)
	alice, bob := newBrowser(t, newHandler(a)), newBrowser(t, newHandler(a))

	get[errorAnswer](t, alice, "/auth/referral/code", http.StatusUnauthorized) // SignedIn is enforced by the pipeline

	post[none](t, alice, "/auth/password/sign-up", fields{"identifier": aliceEmail, "password": testPassword}, http.StatusOK)
	post[none](t, bob, "/auth/password/sign-up", fields{"identifier": bobEmail, "password": testPassword}, http.StatusOK)

	ac := get[referral.CodeResult](t, alice, "/auth/referral/code", http.StatusOK)
	bc := get[referral.CodeResult](t, bob, "/auth/referral/code", http.StatusOK)
	if !codeShape.MatchString(ac.Code) || !codeShape.MatchString(bc.Code) || ac.Code == bc.Code {
		t.Fatalf("codes = %q and %q, want two distinct 8-character codes", ac.Code, bc.Code)
	}

	me := get[meResponse](t, alice, "/me", http.StatusOK)
	if me.ReferralCode == nil || *me.ReferralCode != ac.Code {
		t.Fatalf("/me referral code = %v, want %q", me.ReferralCode, ac.Code)
	}
}

// errRefused is the failure refuser injects.
var errRefused = errors.New("refused by the test")

// refuser fails the creation of one address, after the user row and its
// referral code were already written in the same transaction.
type refuser struct{ address string }

// Name identifies the plugin.
func (refuser) Name() string { return "refuser" }

// DataHooks refuses the identity row for r.address.
func (r refuser) DataHooks() auth.DataHooks {
	return auth.DataHooks{Identity: auth.TableHooks[auth.Identity]{
		BeforeCreate: func(_ context.Context, _ sqlb.DBTX, idn *auth.Identity) error {
			if idn.Value == r.address {
				return errRefused
			}
			return nil
		},
	}}
}

// TestReferral_FailedSignUpLeavesNoCode: the hook runs inside the sign-up's
// transaction, so when a later step of the same sign-up fails, the user and
// the code the hook wrote are rolled back together.
//
//ds:def id=testreferral-failedsignupleavesnocode-wtf7tuzk
func TestReferral_FailedSignUpLeavesNoCode(t *testing.T) {
	a, err := auth.New(
		auth.WithDB(openTestDB(t), sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(email.MailerFunc(discard))), password.New(), referral.New(), refuser{address: bobEmail}),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	b := newBrowser(t, newHandler(a))
	post[none](t, b, "/auth/password/sign-up", fields{"identifier": aliceEmail, "password": testPassword}, http.StatusOK)
	post[errorAnswer](t, newBrowser(t, newHandler(a)), "/auth/password/sign-up", fields{"identifier": bobEmail, "password": testPassword}, http.StatusInternalServerError)

	var users, codes int64
	q, err := a.Select().Columns(sqlb.Bind(sqlb.Count(), &users), sqlb.Bind(sqlb.CountOf(referral.Code), &codes)).From(auth.TableUser).Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := sqlb.One(context.Background(), a.DB(), q); err != nil {
		t.Fatal(err)
	}
	if users != 1 || codes != 1 {
		t.Fatalf("%d users and %d codes after the failed sign-up, want 1 and 1", users, codes)
	}
}

// TestReferral_MigrationIsWrittenByTheCore: the plugin declares a column and
// the core writes the DDL for the engine, including the unique index.
//
//ds:def id=testreferral-migrationiswrittenbythecore-kz5natn3
func TestReferral_MigrationIsWrittenByTheCore(t *testing.T) {
	a := newTestAuth(t)
	ddl, err := a.MigrationSQL()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ALTER TABLE auth_user ADD COLUMN referral_code",
		"CREATE UNIQUE INDEX auth_user_referral_code_key ON auth_user (referral_code)",
	} {
		if !strings.Contains(ddl, want) {
			t.Fatalf("migration SQL lacks %q:\n%s", want, ddl)
		}
	}
}

// growth is a second plugin that claims the same column, as a plugin written
// by someone who never met the referral plugin's author might.
type growth struct{}

// Name identifies the plugin.
func (growth) Name() string { return "growth" }

// Columns claims referral_code, which referral already owns.
func (growth) Columns() []auth.ColumnExtension {
	return []auth.ColumnExtension{{Table: auth.TableNameUser, Name: referral.ColCode, Type: auth.ColumnText, Nullable: true}}
}

// TestReferral_TwoOwnersOfAColumnFailAtStartUp: a collision is refused by
// auth.New, instead of surfacing later as an ambiguous query.
func TestReferral_TwoOwnersOfAColumnFailAtStartUp(t *testing.T) {
	_, err := auth.New(
		auth.WithDB(openTestDB(t), sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(email.MailerFunc(discard))), password.New(), referral.New(), growth{}),
	)
	if !errors.Is(err, auth.ErrColumnConflict) {
		t.Fatalf("auth.New = %v, want ErrColumnConflict", err)
	}
	t.Logf("auth.New: %v", err)
}

// discard drops mail, for a test that never sends any.
func discard(context.Context, email.Mail) error { return nil }

// openTestDB opens a fresh SQLite file for one test.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// newTestAuth builds the app's Auth on a fresh SQLite file and migrates it.
func newTestAuth(t *testing.T) *auth.Auth {
	t.Helper()
	a, err := newAuth(openTestDB(t), email.MailerFunc(discard))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a
}

// browser is an HTTPS test server and a client with a cookie jar that sends
// the Origin a page of the app would, like a real browser on the app.
type browser struct {
	srv    *httptest.Server
	client *http.Client
	origin string
}

// newBrowser serves h over TLS, because the session cookie is __Host- and
// Secure, and a cookie jar keeps such a cookie only for an https URL.
func newBrowser(t *testing.T, h http.Handler) *browser {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := srv.Client()
	client.Jar = jar
	return &browser{srv: srv, client: client, origin: baseURL}
}

// fields is a JSON request body as a client writes it. The library's own
// request types are not used to send: their secrets (auth.Token) encode as
// "[redacted]" on purpose, so a logged struct never leaks one.
type fields map[string]string

// none is the request body of a route that takes no input, and the answer
// of a call whose body the test does not read.
type none struct{}

// errorAnswer is the JSON shape of every error the library answers.
type errorAnswer struct {
	Error auth.ErrorInfo `json:"error"`
}

// post sends in as JSON with the browser's Origin, checks the status and
// decodes the answer as Out.
func post[Out, In any](t *testing.T, b *browser, path string, in In, status int) Out {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, b.srv.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", b.origin)
	return do[Out](t, b, req, status)
}

// get fetches path, checks the status and decodes the answer as Out.
func get[Out any](t *testing.T, b *browser, path string, status int) Out {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, b.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return do[Out](t, b, req, status)
}

// do sends req, checks the status and decodes the answer as Out.
func do[Out any](t *testing.T, b *browser, req *http.Request, status int) Out {
	t.Helper()
	var out Out
	res, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(res.Body); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != status {
		t.Fatalf("%s %s: status %d, want %d: %s", req.Method, req.URL.Path, res.StatusCode, status, buf.String())
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("%s %s: decode %q: %v", req.Method, req.URL.Path, buf.String(), err)
	}
	return out
}
