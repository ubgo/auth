package main

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/passkey"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/twofactor"
	"github.com/ubgo/sqlb"
)

// The tests in this file walk the multi-factor input space the main test
// does not: a code factor added beside a key, a delivered code beside an
// authenticator app, removal of each kind of factor (and the promotion that
// follows), the refusals of the security-key store itself, and a database
// failure at every call each of those operations makes.

// worldConfig shapes a world's two-factor plugin.
type worldConfig struct {
	skipVerify bool
	noKeys     bool
	// wrap, when set, wraps the database connector, for a test that steps
	// into the middle of an operation (race_test.go).
	wrap func(driver.Connector) driver.Connector
	rule twofactor.EnrolmentRule
	// sealer seals TOTP secrets instead of the key derived from the app
	// secret; requirePassword is twofactor.RequirePassword.
	sealer          auth.Sealer
	requirePassword bool
	// deny refuses an authenticator model (passkey.DenyAuthenticators).
	deny string
	// ids replaces the core's id generator (auth.WithIDs).
	ids func(prefix string) (string, error)
}

// world is one app on its own SQLite file, reached through a database whose
// every call can be made to fail (authtest.Faults), in bearer mode.
type world struct {
	t      testing.TB
	srv    *httptest.Server
	a      *auth.Auth
	db     *sql.DB
	tf     *twofactor.Plugin
	pk     *passkey.Plugin
	clk    *clock
	faults *authtest.Faults

	mu   sync.Mutex
	mail map[string]string // the last code mailed to each address
}

// fastHash keeps the test's password hashing cheap; the hash's strength is
// not what these tests are about.
var fastHash = password.Argon2Params{Memory: 64, Time: 1, Threads: 1}

// codeInMail finds the code in a delivered second-factor message.
var codeInMail = regexp.MustCompile(`Your code is (\d+)`)

func newWorld(t testing.TB, cfg worldConfig) *world {
	t.Helper()
	w := &world{t: t, clk: newClock(), faults: authtest.NewFaults(), mail: map[string]string{}}
	dsn := sqliteDSN(filepath.Join(t.TempDir(), dbFile))
	probe, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	drv := probe.Driver()
	_ = probe.Close() // sql.Open connects lazily; the probe held nothing
	conn := w.faults.Connector(authtest.DSNConnector(drv, dsn))
	if cfg.wrap != nil {
		conn = cfg.wrap(conn)
	}
	w.db = sql.OpenDB(conn)
	t.Cleanup(func() { _ = w.db.Close() })
	mailer := email.MailerFunc(func(_ context.Context, m email.Mail) error {
		if c := codeInMail.FindStringSubmatch(m.Text); c != nil {
			w.mu.Lock()
			w.mail[m.To] = c[1]
			w.mu.Unlock()
		}
		return nil
	})
	pkOpts := []passkey.Option{passkey.DisplayName(appName), passkey.AccountName(func(context.Context, *auth.Auth, auth.User) string { return "account" })}
	if cfg.deny != "" {
		pkOpts = append(pkOpts, passkey.DenyAuthenticators(cfg.deny))
	}
	w.pk = passkey.New(pkOpts...)
	opts := []twofactor.Option{twofactor.Issuer(appName), twofactor.DeliveredCodes(), twofactor.ReadableTOTPURI()}
	if cfg.sealer != nil {
		opts = append(opts, twofactor.WithSealer(cfg.sealer))
	}
	if cfg.requirePassword {
		opts = append(opts, twofactor.RequirePassword())
	}
	if !cfg.noKeys {
		opts = append(opts, twofactor.WithSecurityKeys(w.pk.SecurityKeys()))
	}
	if cfg.skipVerify {
		opts = append(opts, twofactor.SkipVerificationOnEnable())
	}
	if cfg.rule != nil {
		opts = append(opts, twofactor.RequireEnrolment(cfg.rule))
	}
	w.tf = twofactor.New(opts...)
	aopts := []auth.Option{
		auth.WithDB(w.db, sqlb.SQLiteDialect{}), auth.WithBaseURL(baseURL), auth.WithSecret(testSecret), auth.WithClock(w.clk.Now),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(mailer)), password.New(password.Argon2(fastHash)), w.pk, w.tf),
	}
	if cfg.ids != nil {
		aopts = append(aopts, auth.WithIDs(cfg.ids))
	}
	w.a, err = auth.New(aopts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.a.Close() })
	if _, err := w.a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	w.srv = httptest.NewServer(newHandler(w.a))
	t.Cleanup(w.srv.Close)
	return w
}

// answer is one HTTP answer: status, body and the token it issued, if any.
type answer struct {
	status int
	body   []byte
	token  string
}

// code is the error code of an error answer, "" otherwise.
func (r answer) code() string {
	var e errorAnswer
	_ = json.Unmarshal(r.body, &e) // a non-error body leaves the code empty
	return e.Error.Code
}

// try sends a bearer-mode request and returns the answer without judging it.
func (w *world) try(method, path, tok string, body any) answer {
	w.t.Helper()
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			w.t.Fatal(err)
		}
	}
	req, err := http.NewRequest(method, w.srv.URL+path, bytes.NewReader(raw))
	if err != nil {
		w.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", baseURL)
	req.Header.Set(authhttp.TokenModeHeader, authhttp.TokenModeBearer)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	res, err := w.srv.Client().Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer res.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(res.Body); err != nil {
		w.t.Fatal(err)
	}
	return answer{status: res.StatusCode, body: buf.Bytes(), token: res.Header.Get(authhttp.SetTokenHeader)}
}

// must sends a request and fails the test unless it answers status.
func (w *world) must(method, path, tok string, body any, status int) answer {
	w.t.Helper()
	r := w.try(method, path, tok, body)
	if r.status != status {
		w.t.Fatalf("%s %s: status %d, want %d: %s", method, path, r.status, status, r.body)
	}
	return r
}

// refuse sends a request and wants the error code want.
func (w *world) refuse(method, path, tok string, body any, want string) {
	w.t.Helper()
	if r := w.try(method, path, tok, body); r.code() != want {
		w.t.Fatalf("%s %s = %d %s, want %s", method, path, r.status, r.body, want)
	}
}

// expect is the op a fault sweep runs: nil when the request answered status.
func (w *world) expect(method, path, tok string, body any, status int) error {
	r := w.try(method, path, tok, body)
	if r.status != status {
		return fmt.Errorf("%s %s: %d %s", method, path, r.status, r.body)
	}
	return nil
}

// person is a user of a world: their token, their security key, their
// authenticator secret and their recovery codes.
type person struct {
	email   string
	id      string
	tok     string
	key     *authenticator
	secret  string
	codes   []string
	keyID   string
	nextRec int
}

// signUp creates a user with a verified address, so delivered codes can
// reach them.
func (w *world) signUp(addr string) *person {
	w.t.Helper()
	r := w.must(http.MethodPost, "/auth/password/sign-up", "", fields{"identifier": addr, "password": testPassword}, http.StatusOK)
	var res password.SignInResult
	if err := json.Unmarshal(r.body, &res); err != nil {
		w.t.Fatal(err)
	}
	ids, err := w.a.Identities(context.Background(), res.User.ID)
	if err != nil || len(ids) != 1 {
		w.t.Fatalf("identities = %v, %v", ids, err)
	}
	if _, err := w.a.VerifyIdentity(context.Background(), ids[0].ID); err != nil {
		w.t.Fatal(err)
	}
	return &person{email: addr, id: res.User.ID, tok: r.token, key: newAuthenticator(w.t.(*testing.T))}
}

// recovery hands out the person's next unused recovery code.
func (u *person) recovery() string {
	c := u.codes[u.nextRec]
	u.nextRec++
	return c
}

// totpNow advances the clock one step and returns the person's current code,
// so every code is newer than the last one accepted.
func (w *world) totpNow(u *person) string {
	w.t.Helper()
	w.clk.Advance(twofactor.Step)
	return totp(w.t.(*testing.T), u.secret, w.clk.Now())
}

// enrolTOTP turns an authenticator app on as the person's first factor.
func (w *world) enrolTOTP(u *person) {
	w.t.Helper()
	var enr twofactor.EnrollResult
	mustJSON(w.t, w.must(http.MethodPost, "/auth/twofactor/enroll", u.tok, none{}, http.StatusOK), &enr)
	u.secret = enr.Secret
	var rc twofactor.RecoveryCodes
	mustJSON(w.t, w.must(http.MethodPost, "/auth/twofactor/confirm", u.tok, fields{"code": w.totpNow(u)}, http.StatusOK), &rc)
	u.codes = rc.Codes
}

// beginKey starts a key registration and returns the finish body.
func (w *world) beginKey(u *person, proof any) obj {
	w.t.Helper()
	var reg twofactor.SecurityKeyChallenge
	mustJSON(w.t, w.must(http.MethodPost, "/auth/twofactor/security-key/register-begin", u.tok, none{}, http.StatusOK), &reg)
	body := obj{"ceremony": reg.Ceremony, "credential": u.key.register(w.t.(*testing.T), reg.Options), "name": "Key"}
	if proof != nil {
		body["proof"] = proof
	}
	return body
}

// addKey registers the person's key; a first factor hands out the codes.
func (w *world) addKey(u *person, proof any) {
	w.t.Helper()
	var out twofactor.SecurityKeyRegistered
	mustJSON(w.t, w.must(http.MethodPost, "/auth/twofactor/security-key/register-finish", u.tok, w.beginKey(u, proof), http.StatusOK), &out)
	u.keyID = out.Key.ID
	if len(out.RecoveryCodes) > 0 {
		u.codes = out.RecoveryCodes
	}
}

// keyProof is a fresh assertion of the person's key, for a session in tok.
func (w *world) keyProof(u *person, tok string) obj {
	w.t.Helper()
	var ch twofactor.SecurityKeyChallenge
	mustJSON(w.t, w.must(http.MethodPost, "/auth/twofactor/security-key/challenge", tok, none{}, http.StatusOK), &ch)
	return obj{"ceremony": ch.Ceremony, "credential": u.key.assert(w.t.(*testing.T), ch.Options, "")}
}

// pending signs the person in with the password and returns the pending
// session's token.
func (w *world) pending(u *person) string {
	w.t.Helper()
	r := w.must(http.MethodPost, "/auth/password/sign-in", "", fields{"identifier": u.email, "password": testPassword}, http.StatusOK)
	var res password.SignInResult
	mustJSON(w.t, r, &res)
	if !res.SecondFactorRequired {
		w.t.Fatalf("sign-in of %s is not pending", u.email)
	}
	return r.token
}

// mailWait bounds how long lastMail waits for a message: delivery runs
// after the operation's transaction commits, so the answer can arrive
// before the mail does.
const mailWait = 2 * time.Second

// lastMail takes the code mailed to addr since the last call, waiting for
// the delivery; "" when none came.
func (w *world) lastMail(addr string) string {
	deadline := time.Now().Add(mailWait)
	for {
		w.mu.Lock()
		c, ok := w.mail[addr]
		delete(w.mail, addr)
		w.mu.Unlock()
		if ok || time.Now().After(deadline) {
			return c
		}
		time.Sleep(time.Millisecond)
	}
}

func mustJSON(t testing.TB, r answer, out any) {
	t.Helper()
	if err := json.Unmarshal(r.body, out); err != nil {
		t.Fatalf("decode %s: %v", r.body, err)
	}
}

func status(w *world, tok string) twofactor.Status {
	w.t.Helper()
	var st twofactor.Status
	mustJSON(w.t, w.must(http.MethodGet, "/auth/twofactor/status", tok, nil, http.StatusOK), &st)
	return st
}

// TestFactors_CodeFactorBesideAKey: a user whose first factor is a key adds
// an authenticator app (with a recovery code as proof), signs in with it,
// reads its URI back, and removing the key moves the app into the first
// factor's place.
func TestFactors_CodeFactorBesideAKey(t *testing.T) {
	w := newWorld(t, worldConfig{})
	bob := w.signUp(bob)
	w.addKey(bob, nil)
	if st := status(w, bob.tok); st.Method != twofactor.MethodSecurityKey || len(bob.codes) != twofactor.DefaultRecoveryCodes {
		t.Fatalf("key-only status = %+v", st)
	}
	// A challenge for a code the key-only user does not have.
	w.refuse(http.MethodPost, "/auth/twofactor/check", bob.tok, fields{"method": "totp", "code": "123456"}, twofactor.ErrFactorNotEnrolled.Code)
	w.refuse(http.MethodPost, "/auth/twofactor/enroll", bob.tok, obj{"method": "totp"}, twofactor.ErrProofRequired.Code)
	w.refuse(http.MethodPost, "/auth/twofactor/enroll", bob.tok, obj{"method": "totp", "proof": obj{"code": "AAAA-BBBB-CCCC-DDDD"}}, twofactor.ErrCodeInvalid.Code)
	var enr twofactor.EnrollResult
	mustJSON(t, w.must(http.MethodPost, "/auth/twofactor/enroll", bob.tok, obj{"method": "totp", "proof": obj{"code": bob.recovery()}}, http.StatusOK), &enr)
	bob.secret = enr.Secret
	if !strings.HasPrefix(enr.URL, "otpauth://totp/") || enr.Enabled {
		t.Fatalf("added enrolment = %+v", enr)
	}
	// Until it is confirmed it is no factor, and confirm checks the
	// method it names.
	w.refuse(http.MethodPost, "/auth/twofactor/confirm", bob.tok, fields{"method": "delivered", "code": "123456"}, twofactor.ErrAlreadyEnabled.Code)
	w.refuse(http.MethodPost, "/auth/twofactor/confirm", bob.tok, fields{"method": "totp", "code": "000000"}, twofactor.ErrCodeInvalid.Code)
	var rc twofactor.RecoveryCodes
	mustJSON(t, w.must(http.MethodPost, "/auth/twofactor/confirm", bob.tok, fields{"method": "totp", "code": w.totpNow(bob)}, http.StatusOK), &rc)
	if rc.Codes == nil || len(rc.Codes) != 0 {
		t.Fatalf("confirm of an added factor = %+v, want no new codes", rc)
	}
	w.refuse(http.MethodPost, "/auth/twofactor/enroll", bob.tok, obj{"method": "totp", "proof": obj{"code": bob.recovery()}}, twofactor.ErrAlreadyEnabled.Code)
	st := status(w, bob.tok)
	if len(st.Factors) != 2 || st.Factors[0].Method != twofactor.MethodTOTP || st.Factors[0].Primary || st.Factors[1].Method != twofactor.MethodSecurityKey {
		t.Fatalf("status = %+v", st)
	}
	var uri twofactor.TOTPURIResult
	mustJSON(t, w.must(http.MethodPost, "/auth/twofactor/totp-uri", bob.tok, fields{"password": testPassword}, http.StatusOK), &uri)
	if !strings.Contains(uri.URL, "secret="+bob.secret) {
		t.Fatalf("totp-uri of the added app = %s", uri.URL)
	}

	// Sign in with the added app: no method means the first code factor.
	ptok := w.pending(bob)
	code := w.totpNow(bob)
	w.must(http.MethodPost, "/auth/twofactor/verify", ptok, obj{"code": code, "disableSession": true}, http.StatusOK)
	w.refuse(http.MethodPost, "/auth/twofactor/verify", ptok, obj{"code": code}, twofactor.ErrCodeInvalid.Code)
	full := w.must(http.MethodPost, "/auth/twofactor/verify", ptok, obj{"method": "totp", "code": w.totpNow(bob)}, http.StatusOK).token

	// Removing the key leaves the app, which takes the first factor's row.
	left := w.must(http.MethodPost, "/auth/twofactor/remove-factor", full, obj{"method": "security_key", "id": bob.keyID, "proof": obj{"code": w.totpNow(bob)}}, http.StatusOK)
	if !strings.Contains(string(left.body), `"enabled":true`) {
		t.Fatalf("remove = %s", left.body)
	}
	if st := status(w, full); st.Method != twofactor.MethodTOTP || len(st.Factors) != 1 || !st.Factors[0].Primary {
		t.Fatalf("after the key went = %+v", st)
	}
	w.must(http.MethodPost, "/auth/twofactor/check", full, obj{"code": w.totpNow(bob)}, http.StatusOK)
}

// TestFactors_DeliveredBesideTOTP: an authenticator user adds codes by mail,
// signs in with one, removes it, and the remove refusals: an unknown
// method, a key that is not theirs, a method they no longer have.
func TestFactors_DeliveredBesideTOTP(t *testing.T) {
	w := newWorld(t, worldConfig{})
	al := w.signUp(alice)
	w.enrolTOTP(al)
	mustJSON(t, w.must(http.MethodPost, "/auth/twofactor/enroll", al.tok, obj{"method": "delivered", "proof": obj{"method": "totp", "code": w.totpNow(al)}}, http.StatusOK), &twofactor.EnrollResult{})
	first := w.lastMail(alice)
	if first == "" {
		t.Fatal("enrolling delivered codes mailed nothing")
	}
	w.must(http.MethodPost, "/auth/twofactor/confirm", al.tok, fields{"method": "delivered", "code": first}, http.StatusOK)

	ptok := w.pending(al)
	w.refuse(http.MethodPost, "/auth/twofactor/verify", ptok, fields{"method": "sms", "code": "123456"}, twofactor.ErrMethodInvalid.Code)
	w.refuse(http.MethodPost, "/auth/twofactor/verify", ptok, obj{"method": "security_key"}, twofactor.ErrSecurityKeyInvalid.Code)
	w.refuse(http.MethodPost, "/auth/twofactor/security-key/challenge", ptok, none{}, twofactor.ErrFactorNotEnrolled.Code)
	w.must(http.MethodPost, "/auth/twofactor/send", ptok, none{}, http.StatusOK)
	full := w.must(http.MethodPost, "/auth/twofactor/verify", ptok, fields{"method": "delivered", "code": w.lastMail(alice)}, http.StatusOK).token

	// Another user's key id, an empty id, an unknown method.
	bb := w.signUp(bob)
	w.addKey(bb, nil)
	w.refuse(http.MethodPost, "/auth/twofactor/remove-factor", full, obj{"method": "security_key", "id": bb.keyID, "proof": obj{"code": w.totpNow(al)}}, twofactor.ErrFactorNotFound.Code)
	w.refuse(http.MethodPost, "/auth/twofactor/remove-factor", full, obj{"method": "security_key", "proof": obj{"code": w.totpNow(al)}}, twofactor.ErrFactorNotFound.Code)
	w.refuse(http.MethodPost, "/auth/twofactor/remove-factor", full, obj{"method": "sms", "proof": obj{"code": w.totpNow(al)}}, twofactor.ErrMethodInvalid.Code)
	w.must(http.MethodPost, "/auth/twofactor/remove-factor", full, obj{"method": "delivered", "proof": obj{"code": w.totpNow(al)}}, http.StatusOK)
	w.refuse(http.MethodPost, "/auth/twofactor/remove-factor", full, obj{"method": "delivered", "proof": obj{"code": w.totpNow(al)}}, twofactor.ErrFactorNotFound.Code)
	w.refuse(http.MethodPost, "/auth/twofactor/send", full, none{}, twofactor.ErrNotCodeMethod.Code)

	// With a key beside it, removing the app leaves a key-only factor.
	w.addKey(al, obj{"code": w.totpNow(al)})
	w.must(http.MethodPost, "/auth/twofactor/remove-factor", full, obj{"method": "totp", "proof": obj{"code": w.totpNow(al)}}, http.StatusOK)
	if st := status(w, full); !st.Enabled || st.Method != twofactor.MethodSecurityKey || len(st.Factors) != 1 {
		t.Fatalf("key-only after the app went = %+v", st)
	}
	w.refuse(http.MethodPost, "/auth/twofactor/totp-uri", full, fields{"password": testPassword}, twofactor.ErrNotTOTP.Code)
	// The key is the only factor now, and disable removes it too.
	w.must(http.MethodPost, "/auth/twofactor/disable", full, obj{"method": "security_key", "securityKey": w.keyProof(al, full)}, http.StatusOK)
	if st := status(w, full); st.Enabled {
		t.Fatalf("after disable = %+v", st)
	}
	if keys, err := w.pk.SecurityKeys().SecurityKeys(context.Background(), al.id); err != nil || len(keys) != 0 {
		t.Fatalf("keys after disable = %v, %v", keys, err)
	}
}

// TestFactors_SkipVerificationAddsAtOnce: under SkipVerificationOnEnable an
// added method is on at enroll; a delivered one needs a verified address.
func TestFactors_SkipVerificationAddsAtOnce(t *testing.T) {
	w := newWorld(t, worldConfig{skipVerify: true})
	bb := w.signUp(bob)
	w.addKey(bb, nil)
	var enr twofactor.EnrollResult
	mustJSON(t, w.must(http.MethodPost, "/auth/twofactor/enroll", bb.tok, obj{"method": "delivered", "proof": obj{"code": bb.recovery()}}, http.StatusOK), &enr)
	if !enr.Enabled {
		t.Fatalf("skip-verified enrol = %+v", enr)
	}
	ptok := w.pending(bb)
	w.must(http.MethodPost, "/auth/twofactor/send", ptok, none{}, http.StatusOK)
	w.must(http.MethodPost, "/auth/twofactor/verify", ptok, fields{"method": "delivered", "code": w.lastMail(bob)}, http.StatusOK)
}

// TestFactors_LockoutCoversKeys: wrong codes lock the challenge and the key
// path too, and a refused key counts toward the lock.
func TestFactors_LockoutCoversKeys(t *testing.T) {
	w := newWorld(t, worldConfig{})
	al := w.signUp(alice)
	w.enrolTOTP(al)
	w.addKey(al, obj{"code": w.totpNow(al)})
	ptok := w.pending(al)
	held := w.keyProof(al, ptok)
	for range twofactor.MaxFailures {
		w.refuse(http.MethodPost, "/auth/twofactor/verify", ptok, fields{"code": "000000"}, twofactor.ErrCodeInvalid.Code)
	}
	w.refuse(http.MethodPost, "/auth/twofactor/security-key/challenge", ptok, none{}, twofactor.ErrLocked.Code)
	w.refuse(http.MethodPost, "/auth/twofactor/verify", ptok, obj{"method": "security_key", "securityKey": held}, twofactor.ErrLocked.Code)
}

// TestFactors_WithoutKeysTheMethodIsRefused: a security-key answer to a
// plugin without WithSecurityKeys is an unknown method.
func TestFactors_WithoutKeysTheMethodIsRefused(t *testing.T) {
	w := newWorld(t, worldConfig{noKeys: true})
	al := w.signUp(alice)
	w.enrolTOTP(al)
	w.refuse(http.MethodPost, "/auth/twofactor/check", al.tok, obj{"method": "security_key", "securityKey": obj{"ceremony": "x"}}, twofactor.ErrMethodInvalid.Code)
	w.refuse(http.MethodPost, "/auth/twofactor/remove-factor", al.tok, obj{"method": "security_key", "id": "pks_x", "proof": obj{"code": w.totpNow(al)}}, twofactor.ErrMethodInvalid.Code)
}

// TestFactors_RuleErrorRequiresEnrolment: an enrolment rule that cannot
// decide fails closed.
func TestFactors_RuleErrorRequiresEnrolment(t *testing.T) {
	w := newWorld(t, worldConfig{rule: func(context.Context, *auth.Auth, string) (bool, error) { return false, errors.New("policy store down") }})
	r := w.must(http.MethodPost, "/auth/password/sign-up", "", fields{"identifier": alice, "password": testPassword}, http.StatusOK)
	var s auth.SessionResult
	mustJSON(t, w.must(http.MethodGet, "/auth/session", r.token, nil, http.StatusOK), &s)
	if len(s.Tasks) != 1 || s.Tasks[0] != auth.TaskSetupMFA {
		t.Fatalf("tasks = %v", s.Tasks)
	}
	none := newWorld(t, worldConfig{rule: func(context.Context, *auth.Auth, string) (bool, error) { return false, nil }})
	r = none.must(http.MethodPost, "/auth/password/sign-up", "", fields{"identifier": alice, "password": testPassword}, http.StatusOK)
	var plain auth.SessionResult
	mustJSON(t, none.must(http.MethodGet, "/auth/session", r.token, nil, http.StatusOK), &plain)
	if len(plain.Tasks) != 0 {
		t.Fatalf("a user the rule does not name has tasks %v", plain.Tasks)
	}
}

// TestFactors_GoCallsNeedASession: the Go methods run the operations, so
// without a session in ctx they are refused like an anonymous request.
func TestFactors_GoCallsNeedASession(t *testing.T) {
	w := newWorld(t, worldConfig{})
	ctx := context.Background()
	if _, err := w.tf.SecurityKeyChallengeFor(ctx); !errors.Is(err, auth.ErrSignedOut) {
		t.Errorf("challenge: %v", err)
	}
	if _, err := w.tf.SecurityKeyRegisterBegin(ctx, twofactor.SecurityKeyRegisterBeginRequest{}); !errors.Is(err, auth.ErrSignedOut) {
		t.Errorf("register-begin: %v", err)
	}
	if _, err := w.tf.SecurityKeyRegisterFinish(ctx, twofactor.SecurityKeyRegisterFinishRequest{}); !errors.Is(err, auth.ErrSignedOut) {
		t.Errorf("register-finish: %v", err)
	}
	if _, err := w.tf.RemoveFactor(ctx, twofactor.RemoveFactorRequest{}); !errors.Is(err, auth.ErrSignedOut) {
		t.Errorf("remove-factor: %v", err)
	}
}

// TestSecurityKeyStore_Refusals calls the passkey plugin's store directly,
// with the inputs twofactor never sends but another caller of the interface
// could: a ceremony of another user, a credential that is not JSON, an
// attestation answering another challenge, one authenticator registered to
// two users, a cloned key, a stored credential that no longer decodes, and
// an attachment WebAuthn does not define.
func TestSecurityKeyStore_Refusals(t *testing.T) {
	w := newWorld(t, worldConfig{})
	ctx := context.Background()
	s := w.pk.SecurityKeys()
	al, bb := w.signUp(alice), w.signUp(bob)
	user := func(id string) auth.User {
		u, err := w.a.User(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}

	if _, err := s.BeginSecurityKeyRegistration(ctx, user(al.id), "usb"); !errors.Is(err, passkey.ErrAttachmentInvalid) {
		t.Errorf("attachment usb: %v", err)
	}
	if _, err := s.BeginSecurityKeyAssertion(ctx, al.id); !errors.Is(err, twofactor.ErrFactorNotEnrolled) {
		t.Errorf("assertion with no key: %v", err)
	}
	reg, err := s.BeginSecurityKeyRegistration(ctx, user(al.id), passkey.AttachmentPlatform)
	if err != nil || !bytes.Contains(reg.Options, []byte(`"authenticatorAttachment":"platform"`)) || !bytes.Contains(reg.Options, []byte(`"name":"account"`)) {
		t.Fatalf("platform registration = %s, %v", reg.Options, err)
	}
	// Bob cannot finish Alice's ceremony; a non-JSON credential and an
	// attestation of another challenge are refused.
	if _, err := s.FinishSecurityKeyRegistration(ctx, bb.id, twofactor.SecurityKeyRegistration{Ceremony: reg.Ceremony, Credential: al.key.register(t, reg.Options)}); !errors.Is(err, passkey.ErrCeremonyInvalid) {
		t.Errorf("another user's ceremony: %v", err)
	}
	reg, _ = s.BeginSecurityKeyRegistration(ctx, user(al.id), "")
	if _, err := s.FinishSecurityKeyRegistration(ctx, al.id, twofactor.SecurityKeyRegistration{Ceremony: reg.Ceremony, Credential: json.RawMessage(`"x"`)}); !errors.Is(err, passkey.ErrPasskeyInvalid) {
		t.Errorf("non-JSON credential: %v", err)
	}
	other, _ := s.BeginSecurityKeyRegistration(ctx, user(al.id), "")
	reg, _ = s.BeginSecurityKeyRegistration(ctx, user(al.id), "")
	if _, err := s.FinishSecurityKeyRegistration(ctx, al.id, twofactor.SecurityKeyRegistration{Ceremony: reg.Ceremony, Credential: al.key.register(t, other.Options)}); !errors.Is(err, passkey.ErrPasskeyInvalid) {
		t.Errorf("attestation of another challenge: %v", err)
	}
	reg, _ = s.BeginSecurityKeyRegistration(ctx, user(al.id), "")
	key, err := s.FinishSecurityKeyRegistration(ctx, al.id, twofactor.SecurityKeyRegistration{Ceremony: reg.Ceremony, Credential: al.key.register(t, reg.Options)})
	if err != nil {
		t.Fatal(err)
	}
	// A second key is registered with the first one excluded.
	second := newAuthenticator(t)
	reg, _ = s.BeginSecurityKeyRegistration(ctx, user(al.id), "")
	if !bytes.Contains(reg.Options, []byte(`"excludeCredentials"`)) {
		t.Errorf("second registration excludes nothing: %s", reg.Options)
	}
	if _, err := s.FinishSecurityKeyRegistration(ctx, al.id, twofactor.SecurityKeyRegistration{Ceremony: reg.Ceremony, Credential: second.register(t, reg.Options)}); err != nil {
		t.Fatal(err)
	}
	// The same authenticator for Bob is a credential id already stored.
	reg, _ = s.BeginSecurityKeyRegistration(ctx, user(bb.id), "")
	if _, err := s.FinishSecurityKeyRegistration(ctx, bb.id, twofactor.SecurityKeyRegistration{Ceremony: reg.Ceremony, Credential: al.key.register(t, reg.Options)}); !errors.Is(err, passkey.ErrPasskeyInvalid) {
		t.Errorf("one authenticator for two users: %v", err)
	}

	// Assertions: another user's ceremony, a non-JSON credential, a clone.
	ch, err := s.BeginSecurityKeyAssertion(ctx, al.id)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.FinishSecurityKeyAssertion(ctx, bb.id, twofactor.SecurityKeyResponse{Ceremony: ch.Ceremony, Credential: al.key.assert(t, ch.Options, "")}); !errors.Is(err, twofactor.ErrSecurityKeyInvalid) {
		t.Errorf("another user's ceremony: %v", err)
	}
	ch, _ = s.BeginSecurityKeyAssertion(ctx, al.id)
	if err := s.FinishSecurityKeyAssertion(ctx, al.id, twofactor.SecurityKeyResponse{Ceremony: ch.Ceremony, Credential: json.RawMessage(`"x"`)}); !errors.Is(err, twofactor.ErrSecurityKeyInvalid) {
		t.Errorf("non-JSON assertion: %v", err)
	}
	al.key.count = 10
	ch, _ = s.BeginSecurityKeyAssertion(ctx, al.id)
	if err := s.FinishSecurityKeyAssertion(ctx, al.id, twofactor.SecurityKeyResponse{Ceremony: ch.Ceremony, Credential: al.key.assert(t, ch.Options, "")}); err != nil {
		t.Fatalf("a good assertion: %v", err)
	}
	al.key.count = 1
	ch, _ = s.BeginSecurityKeyAssertion(ctx, al.id)
	if err := s.FinishSecurityKeyAssertion(ctx, al.id, twofactor.SecurityKeyResponse{Ceremony: ch.Ceremony, Credential: al.key.assert(t, ch.Options, "")}); !errors.Is(err, twofactor.ErrSecurityKeyInvalid) {
		t.Errorf("a sign count that went backwards: %v", err)
	}
	if err := s.RemoveSecurityKey(ctx, bb.id, key.ID); !errors.Is(err, twofactor.ErrFactorNotFound) {
		t.Errorf("remove another user's key: %v", err)
	}

	// A stored credential that does not decode is an error naming the row,
	// for the list and for a ceremony alike.
	if _, err := w.db.Exec("UPDATE "+passkey.TableNameSecurityKey+" SET "+passkey.ColCredential+" = '{' WHERE "+passkey.ColID+" = ?", key.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SecurityKeys(ctx, al.id); err == nil || !strings.Contains(err.Error(), key.ID) {
		t.Errorf("list with a broken row: %v", err)
	}
	if _, err := s.BeginSecurityKeyAssertion(ctx, al.id); err == nil || !strings.Contains(err.Error(), key.ID) {
		t.Errorf("assertion with a broken row: %v", err)
	}
}

// sweep runs op once per database call it makes, each time on a fresh world
// prepared by setup with a different call failing, and fails when a fault
// is swallowed (authtest.SweepFaults).
func sweep(t *testing.T, cfg worldConfig, setup func(w *world) func() error) {
	t.Helper()
	authtest.SweepFaults(t, func() (*world, *authtest.Faults) {
		w := newWorld(t, cfg)
		return w, w.faults
	}, func(w *world) func(context.Context) error {
		op := setup(w)
		return func(context.Context) error { return op() }
	})
}

// TestFactors_DatabaseFaults: every database call of the multi-factor
// operations surfaces its failure to the caller.
func TestFactors_DatabaseFaults(t *testing.T) {
	if testing.Short() {
		t.Skip("fault sweeps rebuild the app once per database call")
	}
	post := http.MethodPost
	t.Run("first key", func(t *testing.T) {
		sweep(t, worldConfig{}, func(w *world) func() error {
			b := w.signUp(bob)
			body := w.beginKey(b, nil)
			return func() error {
				return w.expect(post, "/auth/twofactor/security-key/register-finish", b.tok, body, http.StatusOK)
			}
		})
	})
	t.Run("key with proof", func(t *testing.T) {
		sweep(t, worldConfig{}, func(w *world) func() error {
			a := w.signUp(alice)
			w.enrolTOTP(a)
			body := w.beginKey(a, obj{"code": w.totpNow(a)})
			return func() error {
				return w.expect(post, "/auth/twofactor/security-key/register-finish", a.tok, body, http.StatusOK)
			}
		})
	})
	t.Run("key over a paused factor", func(t *testing.T) {
		sweep(t, worldConfig{}, func(w *world) func() error {
			a := w.signUp(alice)
			w.enrolTOTP(a)
			if err := w.tf.DisableFor(context.Background(), a.id); err != nil {
				w.t.Fatal(err)
			}
			body := w.beginKey(a, nil)
			return func() error {
				return w.expect(post, "/auth/twofactor/security-key/register-finish", a.tok, body, http.StatusOK)
			}
		})
	})
	t.Run("register begin", func(t *testing.T) {
		sweep(t, worldConfig{}, func(w *world) func() error {
			a := w.signUp(alice)
			w.addKey(a, nil)
			return func() error {
				return w.expect(post, "/auth/twofactor/security-key/register-begin", a.tok, none{}, http.StatusOK)
			}
		})
	})
	t.Run("challenge and verify by key", func(t *testing.T) {
		sweep(t, worldConfig{}, func(w *world) func() error {
			a := w.signUp(alice)
			w.addKey(a, nil)
			ptok := w.pending(a)
			return func() error {
				r := w.try(post, "/auth/twofactor/security-key/challenge", ptok, none{})
				if r.status != http.StatusOK {
					return fmt.Errorf("challenge: %d %s", r.status, r.body)
				}
				var ch twofactor.SecurityKeyChallenge
				mustJSON(w.t, r, &ch)
				return w.expect(post, "/auth/twofactor/verify", ptok, obj{"method": "security_key", "securityKey": obj{"ceremony": ch.Ceremony, "credential": a.key.assert(w.t.(*testing.T), ch.Options, "")}}, http.StatusOK)
			}
		})
	})
	t.Run("add a code factor and confirm it", func(t *testing.T) {
		sweep(t, worldConfig{}, func(w *world) func() error {
			b := w.signUp(bob)
			w.addKey(b, nil)
			proof := b.recovery()
			return func() error {
				r := w.try(post, "/auth/twofactor/enroll", b.tok, obj{"method": "totp", "proof": obj{"code": proof}})
				if r.status != http.StatusOK {
					return fmt.Errorf("enroll: %d %s", r.status, r.body)
				}
				var enr twofactor.EnrollResult
				mustJSON(w.t, r, &enr)
				b.secret = enr.Secret
				return w.expect(post, "/auth/twofactor/confirm", b.tok, fields{"method": "totp", "code": w.totpNow(b)}, http.StatusOK)
			}
		})
	})
	t.Run("add delivered codes", func(t *testing.T) {
		sweep(t, worldConfig{}, func(w *world) func() error {
			a := w.signUp(alice)
			w.enrolTOTP(a)
			code := w.totpNow(a)
			return func() error {
				return w.expect(post, "/auth/twofactor/enroll", a.tok, obj{"method": "delivered", "proof": obj{"code": code}}, http.StatusOK)
			}
		})
	})
	t.Run("add at once under skip", func(t *testing.T) {
		sweep(t, worldConfig{skipVerify: true}, func(w *world) func() error {
			b := w.signUp(bob)
			w.addKey(b, nil)
			proof := b.recovery()
			return func() error {
				return w.expect(post, "/auth/twofactor/enroll", b.tok, obj{"method": "delivered", "proof": obj{"code": proof}}, http.StatusOK)
			}
		})
	})
	t.Run("send and verify an added delivered code", func(t *testing.T) {
		sweep(t, worldConfig{}, func(w *world) func() error {
			a := w.signUp(alice)
			w.enrolTOTP(a)
			w.must(post, "/auth/twofactor/enroll", a.tok, obj{"method": "delivered", "proof": obj{"code": w.totpNow(a)}}, http.StatusOK)
			w.must(post, "/auth/twofactor/confirm", a.tok, fields{"method": "delivered", "code": w.lastMail(alice)}, http.StatusOK)
			ptok := w.pending(a)
			return func() error {
				if err := w.expect(post, "/auth/twofactor/send", ptok, none{}, http.StatusOK); err != nil {
					return err
				}
				return w.expect(post, "/auth/twofactor/verify", ptok, fields{"method": "delivered", "code": w.lastMail(alice)}, http.StatusOK)
			}
		})
	})
	t.Run("verify by an added app", func(t *testing.T) {
		sweep(t, worldConfig{}, func(w *world) func() error {
			b := w.signUp(bob)
			w.addKey(b, nil)
			var enr twofactor.EnrollResult
			mustJSON(w.t, w.must(post, "/auth/twofactor/enroll", b.tok, obj{"method": "totp", "proof": obj{"code": b.recovery()}}, http.StatusOK), &enr)
			b.secret = enr.Secret
			w.must(post, "/auth/twofactor/confirm", b.tok, fields{"method": "totp", "code": w.totpNow(b)}, http.StatusOK)
			ptok := w.pending(b)
			code := w.totpNow(b)
			return func() error {
				return w.expect(post, "/auth/twofactor/verify", ptok, fields{"code": code}, http.StatusOK)
			}
		})
	})
	t.Run("totp-uri of an added app", func(t *testing.T) {
		sweep(t, worldConfig{}, func(w *world) func() error {
			b := w.signUp(bob)
			w.addKey(b, nil)
			w.must(post, "/auth/twofactor/enroll", b.tok, obj{"method": "totp", "proof": obj{"code": b.recovery()}}, http.StatusOK)
			return func() error {
				return w.expect(post, "/auth/twofactor/totp-uri", b.tok, fields{"password": testPassword}, http.StatusOK)
			}
		})
	})
	t.Run("status with factors", func(t *testing.T) {
		sweep(t, worldConfig{}, func(w *world) func() error {
			a := w.signUp(alice)
			w.enrolTOTP(a)
			w.addKey(a, obj{"code": w.totpNow(a)})
			return func() error { return w.expect(http.MethodGet, "/auth/twofactor/status", a.tok, nil, http.StatusOK) }
		})
	})
	t.Run("remove a key, the app moves up", func(t *testing.T) {
		sweep(t, worldConfig{}, func(w *world) func() error {
			b := w.signUp(bob)
			w.addKey(b, nil)
			var enr twofactor.EnrollResult
			mustJSON(w.t, w.must(post, "/auth/twofactor/enroll", b.tok, obj{"method": "totp", "proof": obj{"code": b.recovery()}}, http.StatusOK), &enr)
			b.secret = enr.Secret
			w.must(post, "/auth/twofactor/confirm", b.tok, fields{"method": "totp", "code": w.totpNow(b)}, http.StatusOK)
			proof := b.recovery()
			return func() error {
				return w.expect(post, "/auth/twofactor/remove-factor", b.tok, obj{"method": "security_key", "id": b.keyID, "proof": obj{"code": proof}}, http.StatusOK)
			}
		})
	})
	t.Run("remove the app, a key stays", func(t *testing.T) {
		sweep(t, worldConfig{}, func(w *world) func() error {
			a := w.signUp(alice)
			w.enrolTOTP(a)
			w.addKey(a, obj{"code": w.totpNow(a)})
			proof := a.recovery()
			return func() error {
				return w.expect(post, "/auth/twofactor/remove-factor", a.tok, obj{"method": "totp", "proof": obj{"code": proof}}, http.StatusOK)
			}
		})
	})
	t.Run("remove an added code factor", func(t *testing.T) {
		sweep(t, worldConfig{}, func(w *world) func() error {
			a := w.signUp(alice)
			w.enrolTOTP(a)
			w.must(post, "/auth/twofactor/enroll", a.tok, obj{"method": "delivered", "proof": obj{"code": w.totpNow(a)}}, http.StatusOK)
			proof := a.recovery()
			return func() error {
				return w.expect(post, "/auth/twofactor/remove-factor", a.tok, obj{"method": "delivered", "proof": obj{"code": proof}}, http.StatusOK)
			}
		})
	})
	t.Run("remove the last key", func(t *testing.T) {
		sweep(t, worldConfig{}, func(w *world) func() error {
			b := w.signUp(bob)
			w.addKey(b, nil)
			proof := b.recovery()
			return func() error {
				return w.expect(post, "/auth/twofactor/remove-factor", b.tok, obj{"method": "security_key", "id": b.keyID, "proof": obj{"code": proof}}, http.StatusOK)
			}
		})
	})
	t.Run("support reset", func(t *testing.T) {
		sweep(t, worldConfig{}, func(w *world) func() error {
			a := w.signUp(alice)
			w.enrolTOTP(a)
			w.addKey(a, obj{"code": w.totpNow(a)})
			return func() error { return w.tf.Reset(context.Background(), a.id) }
		})
	})
	t.Run("enrol under a rule", func(t *testing.T) {
		always := func(context.Context, *auth.Auth, string) (bool, error) { return true, nil }
		sweep(t, worldConfig{rule: always}, func(w *world) func() error {
			b := w.signUp(bob)
			body := w.beginKey(b, nil)
			return func() error {
				return w.expect(post, "/auth/twofactor/security-key/register-finish", b.tok, body, http.StatusOK)
			}
		})
	})
	t.Run("sign-up under a rule", func(t *testing.T) {
		always := func(context.Context, *auth.Auth, string) (bool, error) { return true, nil }
		sweep(t, worldConfig{rule: always}, func(w *world) func() error {
			return func() error {
				return w.expect(post, "/auth/password/sign-up", "", fields{"identifier": alice, "password": testPassword}, http.StatusOK)
			}
		})
	})
}
