package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // RFC 6238 TOTP is HMAC-SHA1, the algorithm every authenticator app uses
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/twofactor"
)

const (
	alice        = "alice@example.com"
	bob          = "bob@example.com"
	testPassword = "correct horse battery staple"
	keyName      = "YubiKey"
	// hotpModulus keeps six digits of the truncated HMAC (RFC 4226).
	hotpModulus = 1_000_000
	// wrongCode is a code that is not the current one at the test's start.
	wrongCode = "000000"
)

// testSecret is a fixed app secret; production reads AUTH_SECRET.
var testSecret = bytes.Repeat([]byte("s"), 32)

// newClock starts the test clock now, on a 30-second step boundary so each
// Step forward is exactly one new TOTP code. It starts from the real time,
// not a fixed date, because the cookie jar drops a cookie whose expiry
// (test time plus the pending-session lifetime) is already past in real
// time.
func newClock() *clock { return &clock{now: time.Now().Truncate(twofactor.Step)} }

// TestSecurityKey_SeveralFactorsPickOne walks a user from one factor (an
// authenticator app, enrolled the way every existing user enrolled) to two
// (adding a security key needs a current code), signs in with each in turn
// at the challenge, and checks every refusal the challenge owes: a factor
// the user does not have, a forged signature, another user's key, a
// replayed assertion and a removed key.
func TestSecurityKey_SeveralFactorsPickOne(t *testing.T) {
	clk := newClock()
	a := newTestAuth(t, clk)
	h := newHandler(a)
	b := newBrowser(t, h)
	key := newAuthenticator(t)

	// One factor, the authenticator app: the path every existing user took.
	post[none](t, b, "/auth/password/sign-up", fields{"identifier": alice, "password": testPassword}, http.StatusOK)
	b.signedIn = true
	enr := post[twofactor.EnrollResult](t, b, "/auth/twofactor/enroll", none{}, http.StatusOK)
	codes := post[twofactor.RecoveryCodes](t, b, "/auth/twofactor/confirm", fields{"code": totp(t, enr.Secret, clk.Now())}, http.StatusOK)
	if len(codes.Codes) != twofactor.DefaultRecoveryCodes {
		t.Fatalf("confirm = %+v", codes)
	}

	// A second factor needs a current one: without the proof the key is
	// refused, with it the key is added and the recovery codes stay.
	clk.Advance(twofactor.Step)
	reg := post[twofactor.SecurityKeyChallenge](t, b, "/auth/twofactor/security-key/register-begin", none{}, http.StatusOK)
	cred := key.register(t, reg.Options)
	noProof := post[errorAnswer](t, b, "/auth/twofactor/security-key/register-finish", obj{"ceremony": reg.Ceremony, "credential": cred, "name": keyName}, http.StatusBadRequest)
	if noProof.Error.Code != twofactor.ErrProofRequired.Code {
		t.Fatalf("a key without proof = %+v", noProof.Error)
	}
	added := post[twofactor.SecurityKeyRegistered](t, b, "/auth/twofactor/security-key/register-finish",
		obj{"ceremony": reg.Ceremony, "credential": cred, "name": keyName, "proof": obj{"method": "totp", "code": totp(t, enr.Secret, clk.Now())}}, http.StatusOK)
	if added.Key.ID == "" || added.Key.Name != keyName || len(added.RecoveryCodes) != 0 {
		t.Fatalf("added key = %+v", added)
	}
	st := get[twofactor.Status](t, b, "/auth/twofactor/status", http.StatusOK)
	if !st.Enabled || st.Method != twofactor.MethodTOTP || len(st.Factors) != 2 ||
		st.Factors[0].Method != twofactor.MethodTOTP || !st.Factors[0].Primary ||
		st.Factors[1].Method != twofactor.MethodSecurityKey || st.Factors[1].ID != added.Key.ID {
		t.Fatalf("status = %+v", st)
	}

	// Bob's only factor is a key: it turns two-factor on and hands out the
	// recovery codes.
	bb := newBrowser(t, h)
	bobKey := newAuthenticator(t)
	post[none](t, bb, "/auth/password/sign-up", fields{"identifier": bob, "password": testPassword}, http.StatusOK)
	bb.signedIn = true
	breg := post[twofactor.SecurityKeyChallenge](t, bb, "/auth/twofactor/security-key/register-begin", none{}, http.StatusOK)
	bobAdded := post[twofactor.SecurityKeyRegistered](t, bb, "/auth/twofactor/security-key/register-finish", obj{"ceremony": breg.Ceremony, "credential": bobKey.register(t, breg.Options)}, http.StatusOK)
	if len(bobAdded.RecoveryCodes) != twofactor.DefaultRecoveryCodes {
		t.Fatalf("bob's first factor = %+v", bobAdded)
	}
	if bst := get[twofactor.Status](t, bb, "/auth/twofactor/status", http.StatusOK); !bst.Enabled || bst.Method != twofactor.MethodSecurityKey || len(bst.Factors) != 1 {
		t.Fatalf("bob's status = %+v", bst)
	}

	// Alice signs in: the password alone leaves the session pending.
	signIn(t, b, alice, true)
	pending := get[twofactor.Status](t, b, "/auth/twofactor/status", http.StatusOK)
	if len(pending.Factors) != 2 {
		t.Fatalf("pending status = %+v: the picker needs both factors", pending)
	}
	notHers := post[errorAnswer](t, b, "/auth/twofactor/verify", obj{"method": "delivered", "code": "123456"}, http.StatusBadRequest)
	if notHers.Error.Code != twofactor.ErrFactorNotEnrolled.Code {
		t.Fatalf("a factor she does not have = %+v", notHers.Error)
	}
	// A key presenting her credential id with another private key.
	forger := newAuthenticator(t)
	forger.credID = key.credID
	ch := post[twofactor.SecurityKeyChallenge](t, b, "/auth/twofactor/security-key/challenge", none{}, http.StatusOK)
	refuseKey(t, b, ch.Ceremony, forger.assert(t, ch.Options, ""))
	// Bob's genuine key answering her challenge.
	ch = post[twofactor.SecurityKeyChallenge](t, b, "/auth/twofactor/security-key/challenge", none{}, http.StatusOK)
	refuseKey(t, b, ch.Ceremony, bobKey.assert(t, ch.Options, ""))
	get[none](t, b, "/me", http.StatusUnauthorized)
	// Her own key passes.
	ch = post[twofactor.SecurityKeyChallenge](t, b, "/auth/twofactor/security-key/challenge", none{}, http.StatusOK)
	good := key.assert(t, ch.Options, "")
	post[none](t, b, "/auth/twofactor/verify", obj{"method": "security_key", "securityKey": obj{"ceremony": ch.Ceremony, "credential": good}}, http.StatusOK)
	get[meResponse](t, b, "/me", http.StatusOK)

	// The same assertion again, on a new pending sign-in, is a replay.
	signIn(t, b, alice, true)
	refuseKey(t, b, ch.Ceremony, good)
	// The authenticator app passes at the same challenge.
	clk.Advance(twofactor.Step)
	post[none](t, b, "/auth/twofactor/verify", obj{"method": "totp", "code": totp(t, enr.Secret, clk.Now())}, http.StatusOK)

	// A second browser holds a signed assertion while the key is removed.
	other := newBrowser(t, h)
	signIn(t, other, alice, true)
	och := post[twofactor.SecurityKeyChallenge](t, other, "/auth/twofactor/security-key/challenge", none{}, http.StatusOK)
	held := key.assert(t, och.Options, "")

	bad := post[errorAnswer](t, b, "/auth/twofactor/remove-factor", obj{"method": "security_key", "id": added.Key.ID, "proof": obj{"code": wrongCode}}, http.StatusBadRequest)
	if bad.Error.Code != twofactor.ErrCodeInvalid.Code {
		t.Fatalf("remove with a wrong proof = %+v", bad.Error)
	}
	left := post[twofactor.RemoveFactorResult](t, b, "/auth/twofactor/remove-factor", obj{"method": "security_key", "id": added.Key.ID, "proof": obj{"code": codes.Codes[0]}}, http.StatusOK)
	if !left.Enabled {
		t.Fatal("removing one of two factors turned two-factor off")
	}
	gone := post[errorAnswer](t, other, "/auth/twofactor/verify", obj{"method": "security_key", "securityKey": obj{"ceremony": och.Ceremony, "credential": held}}, http.StatusBadRequest)
	if gone.Error.Code != twofactor.ErrFactorNotEnrolled.Code {
		t.Fatalf("a removed key = %+v", gone.Error)
	}
	get[none](t, other, "/me", http.StatusUnauthorized)
	if st := get[twofactor.Status](t, b, "/auth/twofactor/status", http.StatusOK); len(st.Factors) != 1 || st.Factors[0].Method != twofactor.MethodTOTP {
		t.Fatalf("status after removal = %+v", st)
	}

	// Bob removes his only factor: two-factor is off and the password alone
	// signs him in again.
	off := post[twofactor.RemoveFactorResult](t, bb, "/auth/twofactor/remove-factor", obj{"method": "security_key", "id": bobAdded.Key.ID, "proof": obj{"code": bobAdded.RecoveryCodes[0]}}, http.StatusOK)
	if off.Enabled {
		t.Fatal("removing the last factor left two-factor on")
	}
	signIn(t, bb, bob, false)
	get[meResponse](t, bb, "/me", http.StatusOK)
}

// TestSecurityKey_KeyIsNotAPasskey: a key registered as a second factor
// never signs anyone in on its own through the passkey sign-in.
func TestSecurityKey_KeyIsNotAPasskey(t *testing.T) {
	clk := newClock()
	b := newBrowser(t, newHandler(newTestAuth(t, clk)))
	key := newAuthenticator(t)
	up := post[password.SignInResult](t, b, "/auth/password/sign-up", fields{"identifier": alice, "password": testPassword}, http.StatusOK)
	reg := post[twofactor.SecurityKeyChallenge](t, b, "/auth/twofactor/security-key/register-begin", none{}, http.StatusOK)
	post[twofactor.SecurityKeyRegistered](t, b, "/auth/twofactor/security-key/register-finish", obj{"ceremony": reg.Ceremony, "credential": key.register(t, reg.Options)}, http.StatusOK)
	post[none](t, b, "/auth/sign-out", none{}, http.StatusOK)
	login := post[twofactor.SecurityKeyChallenge](t, b, "/auth/passkey/login-begin", none{}, http.StatusOK)
	post[errorAnswer](t, b, "/auth/passkey/login-finish", obj{"ceremony": login.Ceremony, "credential": key.assert(t, login.Options, up.User.ID)}, http.StatusUnauthorized)
	get[none](t, b, "/me", http.StatusUnauthorized)
}

// refuseKey sends an assertion to verify and wants ErrSecurityKeyInvalid.
func refuseKey(t *testing.T, b *browser, ceremony string, credential json.RawMessage) {
	t.Helper()
	got := post[errorAnswer](t, b, "/auth/twofactor/verify", obj{"method": "security_key", "securityKey": obj{"ceremony": ceremony, "credential": credential}}, http.StatusUnauthorized)
	if got.Error.Code != twofactor.ErrSecurityKeyInvalid.Code {
		t.Fatalf("refused key = %+v", got.Error)
	}
}

// signIn signs in with the password, after signing out a browser that is
// signed in; pending says whether a second factor must be asked for.
func signIn(t *testing.T, b *browser, identifier string, pending bool) {
	t.Helper()
	if b.signedIn {
		post[none](t, b, "/auth/sign-out", none{}, http.StatusOK)
	}
	b.signedIn = true
	in := post[password.SignInResult](t, b, "/auth/password/sign-in", fields{"identifier": identifier, "password": testPassword}, http.StatusOK)
	if in.SecondFactorRequired != pending {
		t.Fatalf("sign-in of %s: second factor required %v, want %v", identifier, in.SecondFactorRequired, pending)
	}
}

// clock is the test's time, moved forward by hand so TOTP steps are exact.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

// Now is the current test time.
func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock forward by d.
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
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

// newTestAuth builds the app's Auth on a fresh SQLite file with a mail sink
// and the test clock.
func newTestAuth(t *testing.T, clk *clock) *auth.Auth {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	a, err := newAuth(db, email.MailerFunc(func(context.Context, email.Mail) error { return nil }), testSecret, auth.WithClock(clk.Now))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a
}

// authenticator is a software security key: one P-256 key, "none"
// attestation, user presence only (a security key proves possession, not
// who holds it). It builds exactly the JSON a browser hands the server, so
// the test runs real ceremonies through the real verifier.
type authenticator struct {
	// aaguid is the model the key discloses at registration; nil discloses
	// none (all zeros).
	aaguid []byte
	key    *ecdsa.PrivateKey
	credID []byte
	count  uint32
	rpID   string
}

// credIDBytes is the length of a credential id.
const credIDBytes = 16

func newAuthenticator(t *testing.T) *authenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, credIDBytes)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	return &authenticator{key: key, credID: id, rpID: u.Hostname()}
}

// b64 is WebAuthn's JSON encoding of bytes: base64url without padding.
var b64 = base64.RawURLEncoding

// WebAuthn authenticator-data flag bits.
const (
	flagUserPresent = 0x01
	flagAttested    = 0x40
)

// COSE key parameters for an ES256 (P-256) public key, RFC 9053.
const (
	coseKeyTypeEC2 = 2
	coseAlgES256   = -7
	coseCurveP256  = 1
	p256CoordBytes = 32
	aaguidBytes    = 16
)

// coseKey is the public key in the COSE form the attestation carries.
type coseKey struct {
	Kty int    `cbor:"1,keyasint"`
	Alg int    `cbor:"3,keyasint"`
	Crv int    `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}

// attestationObject is the CBOR returned at registration, "none" format.
type attestationObject struct {
	Fmt      string   `cbor:"fmt"`
	AttStmt  struct{} `cbor:"attStmt"`
	AuthData []byte   `cbor:"authData"`
}

// clientData is what the browser signs over.
type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

// attestationResponse is the response part of a registration credential.
type attestationResponse struct {
	ClientDataJSON    string   `json:"clientDataJSON"`
	AttestationObject string   `json:"attestationObject"`
	Transports        []string `json:"transports"`
}

// assertionResponse is the response part of an assertion credential.
type assertionResponse struct {
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle,omitempty"`
}

// publicKeyCredential is PublicKeyCredential.toJSON() in a browser.
type publicKeyCredential[R attestationResponse | assertionResponse] struct {
	ID                      string   `json:"id"`
	RawID                   string   `json:"rawId"`
	Type                    string   `json:"type"`
	Response                R        `json:"response"`
	ClientExtensionResults  struct{} `json:"clientExtensionResults"`
	AuthenticatorAttachment string   `json:"authenticatorAttachment"`
}

// authData builds the authenticator data: the relying party's hash, the
// flags, the sign count, and at registration the credential and its key.
func (a *authenticator) authData(t *testing.T, attested bool) []byte {
	t.Helper()
	rp := sha256.Sum256([]byte(a.rpID))
	flags := byte(flagUserPresent)
	if attested {
		flags |= flagAttested
	}
	out := append([]byte{}, rp[:]...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, a.count)
	if !attested {
		return out
	}
	aaguid := a.aaguid
	if aaguid == nil {
		aaguid = make([]byte, aaguidBytes) // "none": the model is not disclosed
	}
	out = append(out, aaguid...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(a.credID)))
	out = append(out, a.credID...)
	key, err := cbor.Marshal(coseKey{
		Kty: coseKeyTypeEC2, Alg: coseAlgES256, Crv: coseCurveP256,
		X: a.key.X.FillBytes(make([]byte, p256CoordBytes)), Y: a.key.Y.FillBytes(make([]byte, p256CoordBytes)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return append(out, key...)
}

// clientDataJSON answers the challenge in the options from the app's origin.
func clientDataJSON(t *testing.T, typ string, options json.RawMessage) []byte {
	t.Helper()
	var o struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &o); err != nil || o.PublicKey.Challenge == "" {
		t.Fatalf("options %s: %v", options, err)
	}
	out, err := json.Marshal(clientData{Type: typ, Challenge: o.PublicKey.Challenge, Origin: baseURL})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// register answers navigator.credentials.create.
func (a *authenticator) register(t *testing.T, options json.RawMessage) json.RawMessage {
	t.Helper()
	cd := clientDataJSON(t, "webauthn.create", options)
	att, err := cbor.Marshal(attestationObject{Fmt: "none", AuthData: a.authData(t, true)})
	if err != nil {
		t.Fatal(err)
	}
	return marshal(t, publicKeyCredential[attestationResponse]{
		ID: b64.EncodeToString(a.credID), RawID: b64.EncodeToString(a.credID), Type: "public-key", AuthenticatorAttachment: "cross-platform",
		Response: attestationResponse{ClientDataJSON: b64.EncodeToString(cd), AttestationObject: b64.EncodeToString(att), Transports: []string{"usb"}},
	})
}

// assert answers navigator.credentials.get; userID is the user handle a
// discoverable credential returns, "" for a security key.
func (a *authenticator) assert(t *testing.T, options json.RawMessage, userID string) json.RawMessage {
	t.Helper()
	a.count++
	cd := clientDataJSON(t, "webauthn.get", options)
	ad := a.authData(t, false)
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	resp := assertionResponse{ClientDataJSON: b64.EncodeToString(cd), AuthenticatorData: b64.EncodeToString(ad), Signature: b64.EncodeToString(sig)}
	if userID != "" {
		resp.UserHandle = b64.EncodeToString([]byte(userID))
	}
	return marshal(t, publicKeyCredential[assertionResponse]{
		ID: b64.EncodeToString(a.credID), RawID: b64.EncodeToString(a.credID), Type: "public-key", AuthenticatorAttachment: "cross-platform",
		Response: resp,
	})
}

// marshal encodes a credential as JSON.
func marshal[T publicKeyCredential[attestationResponse] | publicKeyCredential[assertionResponse]](t *testing.T, v T) json.RawMessage {
	t.Helper()
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// browser is an HTTPS test server and a client with a cookie jar that sends
// the Origin a page of the app would.
type browser struct {
	srv    *httptest.Server
	client *http.Client
	origin string
	// signedIn is set by signIn, so the next signIn signs out first.
	signedIn bool
}

// newBrowser serves h over TLS, because the session cookie is __Host- and
// Secure. Each browser has its own cookie jar.
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

// fields is a flat JSON body; obj one with nested values. The library's own
// request types are not used to send, because their secrets encode as
// "[redacted]" on purpose.
type (
	fields map[string]string
	obj    map[string]any
)

// none is the body of a route that takes no input, and an answer the test
// does not read.
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
