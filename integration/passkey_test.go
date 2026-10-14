package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/url"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/passkey"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/twofactor"
)

// authenticator is a software WebAuthn authenticator: one P-256 key, "none"
// attestation, user presence always set and verification unless noUV. It builds exactly
// the bytes a browser would hand the server, so the plugin and the WebAuthn
// library are tested on real ceremonies.
type authenticator struct {
	// noUV leaves the user-verified flag off, as an authenticator that
	// skipped the PIN or biometric would.
	noUV bool
	// aaguid is the model the authenticator claims; nil sends sixteen
	// zero bytes, a model kept private.
	aaguid []byte
	key    *ecdsa.PrivateKey
	credID []byte
	count  uint32
	rpID   string
	origin string
}

func newAuthenticator(t *testing.T) *authenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	u, _ := url.Parse(testBaseURL)
	return &authenticator{key: key, credID: id, rpID: u.Hostname(), origin: testBaseURL}
}

var b64 = base64.RawURLEncoding

// WebAuthn flag bits.
const (
	flagUserPresent  = 0x01
	flagUserVerified = 0x04
	flagAttested     = 0x40
)

func (a *authenticator) authData(attested bool) []byte {
	rp := sha256.Sum256([]byte(a.rpID))
	flags := byte(flagUserPresent | flagUserVerified)
	if a.noUV {
		flags = flagUserPresent
	}
	if attested {
		flags |= flagAttested
	}
	out := append([]byte{}, rp[:]...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, a.count)
	if attested {
		aaguid := a.aaguid
		if aaguid == nil {
			aaguid = make([]byte, 16)
		}
		out = append(out, aaguid...) // AAGUID
		out = binary.BigEndian.AppendUint16(out, uint16(len(a.credID)))
		out = append(out, a.credID...)
		cose, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: a.key.X.FillBytes(make([]byte, 32)), -3: a.key.Y.FillBytes(make([]byte, 32))})
		out = append(out, cose...)
	}
	return out
}

func challengeOf(t *testing.T, options json.RawMessage) string {
	t.Helper()
	var o struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &o); err != nil || o.PublicKey.Challenge == "" {
		t.Fatalf("options %s: %v", options, err)
	}
	return o.PublicKey.Challenge
}

func (a *authenticator) clientData(typ, challenge string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": a.origin, "crossOrigin": false})
	return b
}

// register answers navigator.credentials.create.
func (a *authenticator) register(t *testing.T, options json.RawMessage) json.RawMessage {
	t.Helper()
	cd := a.clientData("webauthn.create", challengeOf(t, options))
	att, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": a.authData(true)})
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(a.credID), "rawId": b64.EncodeToString(a.credID), "type": "public-key",
		"response":               map[string]any{"clientDataJSON": b64.EncodeToString(cd), "attestationObject": b64.EncodeToString(att), "transports": []string{"internal"}},
		"clientExtensionResults": map[string]any{}, "authenticatorAttachment": "platform",
	})
	return out
}

// assert answers navigator.credentials.get for userID.
func (a *authenticator) assert(t *testing.T, options json.RawMessage, userID string) json.RawMessage {
	t.Helper()
	a.count++
	cd := a.clientData("webauthn.get", challengeOf(t, options))
	ad := a.authData(false)
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(a.credID), "rawId": b64.EncodeToString(a.credID), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON": b64.EncodeToString(cd), "authenticatorData": b64.EncodeToString(ad),
			"signature": b64.EncodeToString(sig), "userHandle": b64.EncodeToString([]byte(userID)),
		},
		"clientExtensionResults": map[string]any{}, "authenticatorAttachment": "platform",
	})
	return out
}

func TestPasskey_RegisterSignInRemove(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		tf := twofactor.New(twofactor.WithEncryptionKey(twoFactorKey))
		pk := passkey.New(passkey.DisplayName("Acme"))
		a := e.newAuth(t, nil, em, pw, tf, pk)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)
		dev := newAuthenticator(t)

		begin := must[passkey.BeginResult](t)(pk.RegisterBegin(ctx))
		added, err := pk.RegisterFinish(ctx, passkey.FinishRequest{Ceremony: begin.Ceremony, Credential: dev.register(t, begin.Options), Name: "Laptop"})
		if err != nil {
			t.Fatalf("register: %v", err)
		}
		if _, err := pk.RegisterFinish(ctx, passkey.FinishRequest{Ceremony: begin.Ceremony, Credential: dev.register(t, begin.Options)}); !errors.Is(err, passkey.ErrCeremonyInvalid) {
			t.Fatalf("a ceremony used twice: %v", err)
		}

		// Turn on TOTP: a passkey sign-in must still be a full session,
		// because the passkey is two factors on its own.
		enr := must[twofactor.EnrollResult](t)(tf.Enroll(ctx))
		must[twofactor.RecoveryCodes](t)(tf.Confirm(ctx, totpAt(t, enr.Secret, e.clock.Now())))

		lb := must[passkey.BeginResult](t)(pk.LoginBegin(anon(a)))
		in, err := pk.LoginFinish(anon(a), passkey.FinishRequest{Ceremony: lb.Ceremony, Credential: dev.assert(t, lb.Options, up.User.ID)})
		if err != nil || in.User.ID != up.User.ID {
			t.Fatalf("passkey sign-in: %+v %v", in, err)
		}
		if _, _, _, err := a.ResolveSession(context.Background(), in.Token); err != nil {
			t.Fatalf("the passkey session must be full, not pending: %v", err)
		}

		// Another device's signature does not verify.
		other := newAuthenticator(t)
		other.credID = dev.credID
		lb = must[passkey.BeginResult](t)(pk.LoginBegin(anon(a)))
		if _, err := pk.LoginFinish(anon(a), passkey.FinishRequest{Ceremony: lb.Ceremony, Credential: other.assert(t, lb.Options, up.User.ID)}); !errors.Is(err, passkey.ErrPasskeyInvalid) {
			t.Fatalf("forged assertion: %v", err)
		}

		// A replayed sign count means a cloned credential.
		dev.count = 0
		lb = must[passkey.BeginResult](t)(pk.LoginBegin(anon(a)))
		if _, err := pk.LoginFinish(anon(a), passkey.FinishRequest{Ceremony: lb.Ceremony, Credential: dev.assert(t, lb.Options, up.User.ID)}); !errors.Is(err, passkey.ErrPasskeyInvalid) {
			t.Fatalf("counter went back: %v", err)
		}

		list := must[[]passkey.Passkey](t)(pk.List(request(a, in.Token)))
		if len(list) != 1 || list[0].Name != "Laptop" || list[0].LastUsedAt == nil {
			t.Fatalf("list = %+v", list)
		}
		if err := pk.Remove(request(a, in.Token), added.ID); err != nil {
			t.Fatalf("remove with a verified email left: %v", err)
		}
	})
}

// TestPasskey_OnlyWayInCannotBeRemoved: a user whose one way in is a passkey
// cannot remove it.
func TestPasskey_OnlyWayInCannotBeRemoved(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		pk := passkey.New()
		pw := e.passwordPlugin(password.WithoutRecovery())
		a := e.newAuth(t, nil, e.emailPlugin(), pw, pk)
		u := must[auth.User](t)(a.CreateUser(context.Background(), auth.NewUser{Name: "Pat"}))
		sess, tok, err := a.CreateSession(context.Background(), u.ID, auth.Client{})
		if err != nil || sess.SecondFactorPending {
			t.Fatal(err)
		}
		ctx := request(a, tok)
		dev := newAuthenticator(t)
		begin := must[passkey.BeginResult](t)(pk.RegisterBegin(ctx))
		added := must[passkey.Passkey](t)(pk.RegisterFinish(ctx, passkey.FinishRequest{Ceremony: begin.Ceremony, Credential: dev.register(t, begin.Options)}))
		if err := pk.Remove(ctx, added.ID); !errors.Is(err, auth.ErrLastSignInMethod) {
			t.Fatalf("removing the only way in: %v", err)
		}
	})
}
