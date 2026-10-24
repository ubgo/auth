package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

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
