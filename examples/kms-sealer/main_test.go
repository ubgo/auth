package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1" // RFC 6238 TOTP is HMAC-SHA1, the algorithm every authenticator app uses
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/twofactor"
)

const (
	aliceEmail   = "alice@example.com"
	bobEmail     = "bob@example.com"
	testPassword = "correct horse battery staple"
	// hotpModulus keeps six digits of the truncated HMAC (RFC 4226).
	hotpModulus = 1_000_000
)

// TestSecretIsSealedByTheKeyService: the stored TOTP secret is the key
// service's text, not the secret, and the factor still works because the
// plugin opens it through the same service.
func TestSecretIsSealedByTheKeyService(t *testing.T) {
	app := newTestApp(t)
	alice := app.browser(t)
	secret := alice.enrolAndConfirm(t, aliceEmail)

	stored := app.storedSecret(t, aliceEmail)
	if !strings.HasPrefix(stored, kmsPrefix+"1:") {
		t.Fatalf("stored secret = %q, want the key service's v1 text", stored)
	}
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, secret) || bytes.Contains([]byte(stored), raw) {
		t.Fatal("the stored row holds the secret in the clear")
	}
	if seals, opens := app.kms.calls(); seals == 0 || opens == 0 {
		t.Fatalf("the key service saw %d seals and %d opens", seals, opens)
	}
	alice.signInWithCode(t, aliceEmail, secret, http.StatusOK)
}

// TestRotationKeepsOldSecretsOpening: after the service rotates, new secrets
// are sealed under the new version and the old ones still open.
func TestRotationKeepsOldSecretsOpening(t *testing.T) {
	app := newTestApp(t)
	alice := app.browser(t)
	aliceSecret := alice.enrolAndConfirm(t, aliceEmail)
	if err := app.kms.Rotate(); err != nil {
		t.Fatal(err)
	}
	app.browser(t).enrolAndConfirm(t, bobEmail)
	if stored := app.storedSecret(t, bobEmail); !strings.HasPrefix(stored, kmsPrefix+"2:") {
		t.Fatalf("after rotation bob's secret = %q, want v2", stored)
	}
	alice.signInWithCode(t, aliceEmail, aliceSecret, http.StatusOK)
}

// TestSecretIsBoundToItsRow: a sealed secret copied into another user's row
// does not open there, so a database write cannot move a factor between
// accounts. The sign-in answers twofactor.secret_unreadable (503), never a
// pass.
func TestSecretIsBoundToItsRow(t *testing.T) {
	app := newTestApp(t)
	aliceSecret := app.browser(t).enrolAndConfirm(t, aliceEmail)
	bob := app.browser(t)
	bob.enrolAndConfirm(t, bobEmail)

	// The test plays an attacker with write access to the database.
	if _, err := app.db.Exec("UPDATE "+twofactor.TableNameFactor+" SET "+twofactor.ColSecret+" = ? WHERE "+twofactor.ColUserID+" = ?",
		app.storedSecret(t, aliceEmail), app.userID(t, bobEmail)); err != nil {
		t.Fatal(err)
	}
	bob.signInWithCode(t, bobEmail, aliceSecret, http.StatusServiceUnavailable)
}

// TestOutageFailsTheWrite: while the key service is down, enrolment fails
// instead of storing a secret unsealed or empty.
func TestOutageFailsTheWrite(t *testing.T) {
	app := newTestApp(t)
	b := app.browser(t)
	post[none](t, b, "/auth/password/sign-up", fields{"identifier": aliceEmail, "password": testPassword}, http.StatusOK)
	app.kms.setDown(true)
	post[none](t, b, "/auth/twofactor/enroll", none{}, http.StatusInternalServerError)
	var n int
	if err := app.db.QueryRow("SELECT count(*) FROM " + twofactor.TableNameFactor).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("an enrolment during the outage stored %d rows", n)
	}
}

// TestFakeKMSRefusesWhatItDidNotSeal pins the Sealer contract the fake keeps:
// another aad, a foreign value and an unknown version answer
// auth.ErrSealedCorrupt.
func TestFakeKMSRefusesWhatItDidNotSeal(t *testing.T) {
	k, err := newFakeKMS()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sealed, err := k.Seal(ctx, []byte("secret"), "row-1")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := k.Open(ctx, sealed, "row-1"); err != nil || string(got) != "secret" {
		t.Fatalf("Open = %q %v", got, err)
	}
	for _, bad := range []struct{ sealed, aad string }{
		{sealed, "row-2"},
		{"plain text", "row-1"},
		{kmsPrefix + "9:" + strings.TrimPrefix(sealed, kmsPrefix+"1:"), "row-1"},
	} {
		if _, err := k.Open(ctx, bad.sealed, bad.aad); !errors.Is(err, auth.ErrSealedCorrupt) {
			t.Fatalf("Open(%q, %q) = %v, want ErrSealedCorrupt", bad.sealed, bad.aad, err)
		}
	}
}

// testApp is the app wired as main wires it, with the fake key service.
type testApp struct {
	a   *auth.Auth
	db  *sql.DB
	kms *fakeKMS
}

// newTestApp builds and migrates the app on a fresh SQLite file.
func newTestApp(t *testing.T) *testApp {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	kms, err := newFakeKMS()
	if err != nil {
		t.Fatal(err)
	}
	a, err := newAuth(db, kms)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return &testApp{a: a, db: db, kms: kms}
}

// userID is the id of the user who owns addr.
func (app *testApp) userID(t *testing.T, addr string) string {
	t.Helper()
	var id string
	if err := app.db.QueryRow("SELECT user_id FROM "+auth.TableNameIdentity+" WHERE value = ?", addr).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// storedSecret reads the sealed TOTP secret of addr's factor straight from
// the table, as anyone with read access to the database could.
func (app *testApp) storedSecret(t *testing.T, addr string) string {
	t.Helper()
	var s string
	if err := app.db.QueryRow("SELECT "+twofactor.ColSecret+" FROM "+twofactor.TableNameFactor+" WHERE "+twofactor.ColUserID+" = ?", app.userID(t, addr)).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

// enrolAndConfirm signs addr up, enrols a TOTP factor and confirms it with
// the first code, returning the secret an authenticator app would hold.
func (b *browser) enrolAndConfirm(t *testing.T, addr string) string {
	t.Helper()
	post[none](t, b, "/auth/password/sign-up", fields{"identifier": addr, "password": testPassword}, http.StatusOK)
	enr := post[twofactor.EnrollResult](t, b, "/auth/twofactor/enroll", none{}, http.StatusOK)
	post[twofactor.RecoveryCodes](t, b, "/auth/twofactor/confirm", fields{"code": totp(t, enr.Secret, time.Now())}, http.StatusOK)
	post[none](t, b, "/auth/sign-out", none{}, http.StatusOK)
	return enr.Secret
}

// signInWithCode signs in with the password, which leaves a pending session,
// then answers the second factor with the code of secret one step ahead
// (the confirming code's step is spent), expecting status.
func (b *browser) signInWithCode(t *testing.T, addr, secret string, status int) {
	t.Helper()
	in := post[password.SignInResult](t, b, "/auth/password/sign-in", fields{"identifier": addr, "password": testPassword}, http.StatusOK)
	if !in.SecondFactorRequired {
		t.Fatalf("sign-in = %+v, want the second factor required", in)
	}
	post[none](t, b, "/auth/twofactor/verify", fields{"code": totp(t, secret, time.Now().Add(twofactor.Step))}, status)
}

// totp is an independent RFC 6238 implementation (HMAC-SHA1, 30-second
// steps, six digits): what an authenticator app computes from the secret.
func totp(t *testing.T, secretB32 string, at time.Time) string {
	t.Helper()
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretB32)
	if err != nil {
		t.Fatal(err)
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(at.Unix()/int64(twofactor.Step/time.Second)))
	m := hmac.New(sha1.New, secret)
	m.Write(counter[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%0*d", twofactor.Digits, (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%hotpModulus)
}

// fields is a JSON request body as a client writes it.
type fields map[string]string

// none is an answer whose body the test does not read.
type none struct{}

// browser is an HTTPS test server and a client with a cookie jar that sends
// the app's Origin, because the session cookie is __Host- and Secure.
type browser struct {
	srv    *httptest.Server
	client *http.Client
}

// browser serves the app to a new client with its own cookie jar.
func (app *testApp) browser(t *testing.T) *browser {
	t.Helper()
	srv := httptest.NewTLSServer(newHandler(app.a))
	t.Cleanup(srv.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := srv.Client()
	client.Jar = jar
	return &browser{srv: srv, client: client}
}

// post sends in as JSON, checks the status and decodes the answer as Out
// when the status is a success.
func post[Out, In any](t *testing.T, b *browser, path string, in In, status int) Out {
	t.Helper()
	var out Out
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, b.srv.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", baseURL)
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
		t.Fatalf("POST %s: status %d, want %d: %s", path, res.StatusCode, status, buf.String())
	}
	if status < http.StatusBadRequest {
		if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
			t.Fatalf("POST %s: decode %q: %v", path, buf.String(), err)
		}
	}
	return out
}
