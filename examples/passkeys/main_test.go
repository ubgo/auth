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
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/passkey"
	"github.com/ubgo/auth/plugin/password"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery staple"
	testName     = "Alice"
	deviceName   = "Laptop"
)

// TestPasskeys_AddThenSignInWithThePasskeyAlone: an account adds a passkey,
// signs out, and signs back in with nothing but the passkey. A ceremony
// works once, and a signature from another key is refused.
func TestPasskeys_AddThenSignInWithThePasskeyAlone(t *testing.T) {
	a := newTestAuth(t)
	b := newBrowser(t, newHandler(a))
	dev := newAuthenticator(t)

	up := post[password.SignInResult](t, b, "/auth/password/sign-up", fields{"identifier": testEmail, "password": testPassword, "name": testName}, http.StatusOK)

	reg := post[passkey.BeginResult](t, b, "/auth/passkey/register-begin", none{}, http.StatusOK)
	if !bytes.Contains(reg.Options, []byte(`"displayName":"`+testName+`"`)) {
		t.Fatalf("register options %s: the prompt must show the user's name", reg.Options)
	}
	added := post[passkey.Passkey](t, b, "/auth/passkey/register-finish", finishBody{Ceremony: reg.Ceremony, Credential: dev.register(t, reg.Options), Name: deviceName}, http.StatusOK)
	if added.ID == "" || added.Name != deviceName {
		t.Fatalf("register = %+v", added)
	}
	again := post[errorAnswer](t, b, "/auth/passkey/register-finish", finishBody{Ceremony: reg.Ceremony, Credential: dev.register(t, reg.Options)}, http.StatusBadRequest)
	if again.Error.Code != passkey.ErrCeremonyInvalid.Code {
		t.Fatalf("a ceremony used twice = %+v", again.Error)
	}

	post[none](t, b, "/auth/sign-out", none{}, http.StatusOK)
	get[none](t, b, "/me", http.StatusUnauthorized)

	login := post[passkey.BeginResult](t, b, "/auth/passkey/login-begin", none{}, http.StatusOK)
	in := post[passkey.SignInResult](t, b, "/auth/passkey/login-finish", finishBody{Ceremony: login.Ceremony, Credential: dev.assert(t, login.Options, up.User.ID)}, http.StatusOK)
	if in.User.ID != up.User.ID {
		t.Fatalf("passkey sign-in = %+v, want %s", in, up.User.ID)
	}
	if me := get[meResponse](t, b, "/me", http.StatusOK); me.ID != up.User.ID {
		t.Fatalf("/me = %+v", me)
	}
	list := get[passkey.ListResult](t, b, "/auth/passkey/list", http.StatusOK)
	if len(list.Passkeys) != 1 || list.Passkeys[0].Name != deviceName || list.Passkeys[0].LastUsedAt == nil {
		t.Fatalf("list = %+v", list)
	}

	// Another key presenting the same credential id does not verify.
	forger := newAuthenticator(t)
	forger.credID = dev.credID
	login = post[passkey.BeginResult](t, b, "/auth/passkey/login-begin", none{}, http.StatusOK)
	forged := post[errorAnswer](t, b, "/auth/passkey/login-finish", finishBody{Ceremony: login.Ceremony, Credential: forger.assert(t, login.Options, up.User.ID)}, http.StatusUnauthorized)
	if forged.Error.Code != passkey.ErrPasskeyInvalid.Code {
		t.Fatalf("forged assertion = %+v", forged.Error)
	}
}

// TestPasskeys_PageIsServed: the browser page is where the ceremony runs.
func TestPasskeys_PageIsServed(t *testing.T) {
	b := newBrowser(t, newHandler(newTestAuth(t)))
	res, err := b.client.Get(b.srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(res.Body); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK || !bytes.Contains(buf.Bytes(), []byte("navigator.credentials.create")) {
		t.Fatalf("GET /: %d %q", res.StatusCode, buf.String())
	}
}

// finishBody is the body of register-finish and login-finish. It is sent as
// its own type because Credential is a JSON object, not a string.
type finishBody struct {
	Ceremony   string          `json:"ceremony"`
	Credential json.RawMessage `json:"credential"`
	Name       string          `json:"name,omitempty"`
}

// newTestAuth builds the app's Auth on a fresh SQLite file with a mail sink.
func newTestAuth(t *testing.T) *auth.Auth {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	a, err := newAuth(db, email.MailerFunc(func(context.Context, email.Mail) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a
}

// authenticator is a software WebAuthn authenticator: one P-256 key, "none"
// attestation, user presence and verification always set. It builds exactly
// the JSON a browser hands the server after navigator.credentials.create and
// .get, so the test runs real ceremonies through the real verifier.
type authenticator struct {
	key    *ecdsa.PrivateKey
	credID []byte
	count  uint32
	rpID   string
}

// credIDBytes is the length of a credential id; 16 random bytes is what
// platform authenticators typically use.
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
	flags := byte(flagUserPresent | flagUserVerified)
	if attested {
		flags |= flagAttested
	}
	out := append([]byte{}, rp[:]...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, a.count)
	if !attested {
		return out
	}
	out = append(out, make([]byte, aaguidBytes)...)
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
