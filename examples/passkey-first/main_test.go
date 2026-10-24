package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/passkey"
	"github.com/ubgo/auth/plugin/twofactor"
)

const (
	// testEmail and testName are the account the passkey creates.
	testEmail = "ada@example.com"
	testName  = "Ada"
	// testSecret is the deployment secret, exactly auth.MinSecretSize bytes.
	testSecret = "0123456789abcdef0123456789abcdef"
	// minCodeLength is the shortest run of digits read as a mailed code.
	minCodeLength = 6
)

// TestPasskeyFirst_SignUpWithAPasskeyAlone: an account is created by a
// passkey ceremony with no password, signed in at once, and signs back in
// with the passkey after signing out.
func TestPasskeyFirst_SignUpWithAPasskeyAlone(t *testing.T) {
	a, _ := newTestAuth(t)
	b := newBrowser(t, newServer(t, newHandler(a)))
	dev := newAuthenticator(t)

	up := signUp(t, b, dev)
	if up.User.ID == "" || up.VerificationRequired || up.Passkey.ID == "" {
		t.Fatalf("sign-up = %+v, want a user, a passkey and a session", up)
	}
	if got := get[meResponse](t, b, "/me", http.StatusOK); got.ID != up.User.ID {
		t.Fatalf("/me after sign-up = %+v", got)
	}
	post[none](t, b, "/auth/sign-out", none{}, http.StatusOK)
	in := signIn(t, b, dev, up.User.ID)
	if in.User.ID != up.User.ID || in.SecondFactorRequired {
		t.Fatalf("passkey sign-in = %+v", in)
	}
	get[meResponse](t, b, "/me", http.StatusOK)

}

// TestPasskeyFirst_DeniedModelIsRefused: a passkey from the denied model
// creates no account.
func TestPasskeyFirst_DeniedModelIsRefused(t *testing.T) {
	a, _ := newTestAuth(t)
	b := newBrowser(t, newServer(t, newHandler(a)))
	dev := newAuthenticator(t)
	model, err := hex.DecodeString(strings.ReplaceAll(deniedModel, "-", ""))
	if err != nil {
		t.Fatal(err)
	}
	dev.aaguid = model

	begin := post[passkey.BeginResult](t, b, "/auth/passkey/sign-up-begin", fields{"identifier": testEmail, "name": testName}, http.StatusOK)
	got := post[errorAnswer](t, b, "/auth/passkey/sign-up-finish", finishBody{Ceremony: begin.Ceremony, Credential: dev.register(t, begin.Options)}, http.StatusForbidden)
	if got.Error.Code != passkey.ErrAuthenticatorNotAllowed.Code {
		t.Fatalf("sign-up with the denied model = %+v, want %s", got.Error, passkey.ErrAuthenticatorNotAllowed.Code)
	}
	get[errorAnswer](t, b, "/me", http.StatusUnauthorized)
}

// TestPasskeyFirst_KeyWithoutUserVerificationAsksForTheFactor: for a user who
// turned on a second factor, a passkey sign-in that verified the user is a
// full session, and one from a key that did not (no PIN, no biometric) proves
// one factor and is pending until the second.
func TestPasskeyFirst_KeyWithoutUserVerificationAsksForTheFactor(t *testing.T) {
	a, box := newTestAuth(t)
	b := newBrowser(t, newServer(t, newHandler(a)))
	dev := newAuthenticator(t)

	up := signUp(t, b, dev)
	post[email.VerifyResult](t, b, "/auth/email/verify", fields{"token": box.lastToken(t, a, testEmail)}, http.StatusOK)
	post[twofactor.EnrollResult](t, b, "/auth/twofactor/enroll", fields{"method": string(twofactor.MethodDelivered)}, http.StatusOK)
	post[twofactor.RecoveryCodes](t, b, "/auth/twofactor/confirm", fields{"code": box.lastCode(t, a, testEmail)}, http.StatusOK)

	post[none](t, b, "/auth/sign-out", none{}, http.StatusOK)
	if in := signIn(t, b, dev, up.User.ID); in.SecondFactorRequired {
		t.Fatal("a passkey that verified the user was asked for the second factor")
	}

	post[none](t, b, "/auth/sign-out", none{}, http.StatusOK)
	dev.skipUV = true
	if in := signIn(t, b, dev, up.User.ID); !in.SecondFactorRequired {
		t.Fatal("a passkey that did not verify the user signed in with one factor")
	}
	get[errorAnswer](t, b, "/me", http.StatusUnauthorized)
	post[none](t, b, "/auth/twofactor/send", none{}, http.StatusOK)
	post[none](t, b, "/auth/twofactor/verify", fields{"code": box.lastCode(t, a, testEmail)}, http.StatusOK)
	get[meResponse](t, b, "/me", http.StatusOK)
}

// signUp runs the passkey-first sign-up ceremony on b with dev.
func signUp(t *testing.T, b *browser, dev *authenticator) passkey.SignUpResult {
	t.Helper()
	begin := post[passkey.BeginResult](t, b, "/auth/passkey/sign-up-begin", fields{"identifier": testEmail, "name": testName}, http.StatusOK)
	return post[passkey.SignUpResult](t, b, "/auth/passkey/sign-up-finish", finishBody{Ceremony: begin.Ceremony, Credential: dev.register(t, begin.Options)}, http.StatusOK)
}

// signIn runs the passkey sign-in ceremony on b with dev for userID.
func signIn(t *testing.T, b *browser, dev *authenticator, userID string) passkey.SignInResult {
	t.Helper()
	begin := post[passkey.BeginResult](t, b, "/auth/passkey/login-begin", none{}, http.StatusOK)
	return post[passkey.SignInResult](t, b, "/auth/passkey/login-finish", finishBody{Ceremony: begin.Ceremony, Credential: dev.assert(t, begin.Options, userID)}, http.StatusOK)
}

// finishBody is the body of sign-up-finish and login-finish. It is sent as
// its own type because Credential is a JSON object, not a string.
type finishBody struct {
	Ceremony   string          `json:"ceremony"`
	Credential json.RawMessage `json:"credential"`
}

// newTestAuth builds the app's Auth on a fresh SQLite file with a mailbox
// that records mail instead of printing it.
func newTestAuth(t *testing.T) (*auth.Auth, *mailbox) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	box := &mailbox{}
	a, err := newAuth(db, []byte(testSecret), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a, box
}

// mailbox records every mail sent.
type mailbox struct {
	mu   sync.Mutex
	sent []email.Mail
}

// Send records m.
func (m *mailbox) Send(_ context.Context, mail email.Mail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, mail)
	return nil
}

// lastWord returns the first word of the newest mail to addr that match
// accepts. Mail goes out after the transaction commits, so it waits for
// deliveries first.
func (m *mailbox) lastWord(t *testing.T, a *auth.Auth, addr string, match func(string) bool) string {
	t.Helper()
	a.WaitDeliveries()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.sent) - 1; i >= 0; i-- {
		if m.sent[i].To != addr {
			continue
		}
		for _, w := range strings.Fields(m.sent[i].Text) {
			if match(w) {
				return w
			}
		}
	}
	t.Fatalf("no matching mail to %s", addr)
	return ""
}

// lastToken returns the token of the newest link mailed to addr.
func (m *mailbox) lastToken(t *testing.T, a *auth.Auth, addr string) string {
	t.Helper()
	link := m.lastWord(t, a, addr, func(w string) bool { return strings.HasPrefix(w, baseURL) })
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("token")
}

// lastCode returns the newest code mailed to addr: a run of digits.
func (m *mailbox) lastCode(t *testing.T, a *auth.Auth, addr string) string {
	t.Helper()
	return strings.TrimSuffix(m.lastWord(t, a, addr, func(w string) bool { return isCode(strings.TrimSuffix(w, ".")) }), ".")
}

// isCode reports whether w is a run of at least minCodeLength digits.
func isCode(w string) bool {
	if len(w) < minCodeLength {
		return false
	}
	for _, r := range w {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// authenticator is a software WebAuthn authenticator: one P-256 key, "none"
// attestation, user presence always set, user verification when skipUV is
// false, and a model (AAGUID) that is all zeros unless set. It builds exactly
// the JSON a browser hands the server after navigator.credentials.create and
// .get, so the test runs real ceremonies through the real verifier.
type authenticator struct {
	key    *ecdsa.PrivateKey
	credID []byte
	count  uint32
	rpID   string
	// skipUV makes sign-ins without user verification, like a security key
	// with no PIN.
	skipUV bool
	// aaguid is the model the authenticator reports at registration.
	aaguid []byte
}

// credIDBytes is the length of a credential id; 16 random bytes is what
// platform authenticators typically use.
const credIDBytes = 16

// newAuthenticator is a software authenticator with a fresh P-256 key and
// credential id, bound to the relying party id of baseURL as a real one is.
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
	return &authenticator{key: key, credID: id, rpID: u.Hostname(), aaguid: make([]byte, aaguidBytes)}
}

// b64 is WebAuthn's JSON encoding of bytes: base64url without padding.
var b64 = base64.RawURLEncoding

// WebAuthn authenticator-data flag bits.
const (
	flagUserPresent  = 0x01
	flagUserVerified = 0x04
	flagAttested     = 0x40
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

// attestationObject is the CBOR the authenticator returns at registration,
// with "none" attestation: no statement about the device's make.
type attestationObject struct {
	Fmt      string   `cbor:"fmt"`
	AttStmt  struct{} `cbor:"attStmt"`
	AuthData []byte   `cbor:"authData"`
}

// clientData is what the browser signs over: the ceremony type, the server's
// challenge and the page's origin.
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

// assertionResponse is the response part of a sign-in credential.
type assertionResponse struct {
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle"`
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
// flags, the sign count, and at registration the new credential and its key.
func (a *authenticator) authData(t *testing.T, attested bool) []byte {
	t.Helper()
	rp := sha256.Sum256([]byte(a.rpID))
	flags := byte(flagUserPresent)
	if !a.skipUV {
		flags |= flagUserVerified
	}
	if attested {
		flags |= flagAttested
	}
	out := append([]byte{}, rp[:]...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, a.count)
	if !attested {
		return out
	}
	out = append(out, a.aaguid...)
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

// clientDataJSON returns the client data for a ceremony of typ, answering
// the challenge in the begin options, from the app's own origin.
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
		ID: b64.EncodeToString(a.credID), RawID: b64.EncodeToString(a.credID), Type: "public-key", AuthenticatorAttachment: "platform",
		Response: attestationResponse{ClientDataJSON: b64.EncodeToString(cd), AttestationObject: b64.EncodeToString(att), Transports: []string{"internal"}},
	})
}

// assert answers navigator.credentials.get for userID, signing the
// authenticator data and the client data's hash with the device key.
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
	return marshal(t, publicKeyCredential[assertionResponse]{
		ID: b64.EncodeToString(a.credID), RawID: b64.EncodeToString(a.credID), Type: "public-key", AuthenticatorAttachment: "platform",
		Response: assertionResponse{
			ClientDataJSON: b64.EncodeToString(cd), AuthenticatorData: b64.EncodeToString(ad),
			Signature: b64.EncodeToString(sig), UserHandle: b64.EncodeToString([]byte(userID)),
		},
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

// newServer serves h over TLS, because the session and poll cookies are
// __Host- and Secure, and a cookie jar keeps such a cookie only for an https
// URL.
func newServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// browser is a client with its own cookie jar that sends the Origin a page of
// the app would; two browsers on one server are two devices.
type browser struct {
	srv    *httptest.Server
	client *http.Client
	origin string
}

// newBrowser is a fresh device on srv.
func newBrowser(t *testing.T, srv *httptest.Server) *browser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: srv.Client().Transport, Jar: jar}
	return &browser{srv: srv, client: client, origin: baseURL}
}

// fields is a JSON request body as a client writes it. The library's own
// request types are not used to send: their secrets (auth.Token) encode as
// "[redacted]" on purpose, so a logged struct never leaks one.
type fields map[string]string

// none is the request body of a route that takes no input.
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
