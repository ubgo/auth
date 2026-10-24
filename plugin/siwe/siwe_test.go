package siwe_test

import (
	"context"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/siwe"
	"github.com/ubgo/auth/plugin/siwe/siwetest"
)

// hardhat0 is HardhatKey0's well-known address.
const hardhat0 = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

// TestChecksumAddress_EIP55Vectors: the test vectors printed in EIP-55
// itself, which pin the Keccak variant (the legacy one, not SHA3-256) and
// the nibble rule.
func TestChecksumAddress_EIP55Vectors(t *testing.T) {
	for _, want := range []string{
		"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
		"0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
		"0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
		"0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
	} {
		if got := siwe.ChecksumAddress(strings.ToLower(want)); got != want {
			t.Errorf("ChecksumAddress = %s, want %s", got, want)
		}
	}
}

// TestNormalizeAddress: every spelling of one wallet normalizes to one
// value, and a mixed-case spelling with a wrong checksum is refused rather
// than lowered, because it is a typo or a tampered message.
func TestNormalizeAddress(t *testing.T) {
	lower := strings.ToLower(hardhat0)
	for _, in := range []string{hardhat0, lower, "0x" + strings.ToUpper(lower[2:])} {
		if got, err := siwe.NormalizeAddress(in); err != nil || got != lower {
			t.Errorf("NormalizeAddress(%s) = %s, %v; want %s", in, got, err, lower)
		}
	}
	// One letter's case flipped: the checksum no longer matches.
	bad := "0x" + strings.Replace(hardhat0[2:], "f", "F", 1)
	for _, in := range []string{bad, "", "0x", "f39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "0x" + strings.Repeat("g", 40), hardhat0 + "00", "1x" + lower[2:]} {
		if _, err := siwe.NormalizeAddress(in); !errors.Is(err, siwe.ErrAddressInvalid) {
			t.Errorf("NormalizeAddress(%q) = %v, want ErrAddressInvalid", in, err)
		}
	}
}

// TestKeys_KnownAddresses: the test keys derive the addresses every
// Ethereum tool shows for them, which pins key derivation and the address
// hash end to end against an outside source.
func TestKeys_KnownAddresses(t *testing.T) {
	if got := siwetest.MustKey(siwetest.HardhatKey0).Address(); got != hardhat0 {
		t.Fatalf("HardhatKey0 address = %s, want %s", got, hardhat0)
	}
	if got := siwetest.MustKey(siwetest.SecondKey).Address(); got != "0x22181e4B9Bb252e079fC81DEB438E49d571F9faf" {
		t.Fatalf("SecondKey address = %s", got)
	}
	for _, bad := range []string{"", "zz", "00"} {
		if _, err := siwetest.NewKey(bad); !errors.Is(err, siwetest.ErrKeyInvalid) {
			t.Errorf("NewKey(%q) = %v", bad, err)
		}
	}
}

func sampleMessage(addr string) siwe.Message {
	exp := time.Date(2026, 10, 9, 12, 15, 0, 0, time.UTC)
	nb := time.Date(2026, 10, 9, 11, 59, 0, 0, time.UTC)
	return siwe.Message{
		Scheme: "https", Domain: "app.example.com", Address: addr, Statement: "Sign in to Example.",
		URI: "https://app.example.com/login", Version: siwe.Version, ChainID: 1, Nonce: "abcdef0123456789",
		IssuedAt: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC), ExpirationTime: &exp, NotBefore: &nb,
		RequestID: "req-1", Resources: []string{"ipfs://bafy", "https://app.example.com/terms"},
	}
}

// TestParseMessage_RoundTrip: String writes what ParseMessage reads, for a
// message with every optional field and for one with none.
func TestParseMessage_RoundTrip(t *testing.T) {
	full := sampleMessage(hardhat0)
	bare := siwe.Message{Domain: "localhost:3000", Address: hardhat0, URI: "http://localhost:3000", Version: siwe.Version, ChainID: 137, Nonce: "Nonce1234", IssuedAt: full.IssuedAt}
	for _, m := range []siwe.Message{full, bare} {
		got, err := siwe.ParseMessage(m.String())
		if err != nil {
			t.Fatalf("ParseMessage(%q): %v", m.String(), err)
		}
		if got.String() != m.String() {
			t.Fatalf("round trip:\n%s\nwant\n%s", got.String(), m.String())
		}
	}
	if !strings.Contains(bare.String(), hardhat0+"\n\n\nURI: ") {
		t.Fatalf("no statement must leave the two blank lines the ABNF requires:\n%s", bare.String())
	}
}

// TestParseMessage_RefusesMalformed: each mutation of a valid message is
// refused, so the parser cannot accept a text the wallet showed differently.
func TestParseMessage_RefusesMalformed(t *testing.T) {
	good := sampleMessage(hardhat0).String()
	cases := map[string]string{
		"header":            strings.Replace(good, " wants you to sign in", " wants you to log in", 1),
		"scheme":            strings.Replace(good, "https://app", "1ttps://app", 1),
		"domain with path":  strings.Replace(good, "app.example.com wants", "app.example.com/x wants", 1),
		"bad checksum":      strings.Replace(good, hardhat0, "0x"+strings.Replace(hardhat0[2:], "f", "F", 1), 1),
		"no blank":          strings.Replace(good, hardhat0+"\n\n", hardhat0+"\nx\n", 1),
		"missing blank":     strings.Replace(good, "Sign in to Example.\n\n", "Sign in to Example.\n", 1),
		"version 2":         strings.Replace(good, "Version: 1", "Version: 2", 1),
		"chain zero":        strings.Replace(good, "Chain ID: 1", "Chain ID: 0", 1),
		"chain leading 0":   strings.Replace(good, "Chain ID: 1", "Chain ID: 01", 1),
		"short nonce":       strings.Replace(good, "abcdef0123456789", "abc", 1),
		"nonce symbol":      strings.Replace(good, "abcdef0123456789", "abcdef01-3456789", 1),
		"issued at":         strings.Replace(good, "Issued At: 2026", "Issued At: x2026", 1),
		"expiration":        strings.Replace(good, "Expiration Time: 2026", "Expiration Time: x", 1),
		"not before":        strings.Replace(good, "Not Before: 2026", "Not Before: x", 1),
		"relative uri":      strings.Replace(good, "URI: https://app.example.com/login", "URI: /login", 1),
		"resource relative": strings.Replace(good, "- ipfs://bafy", "- bafy", 1),
		"empty resources":   strings.Split(good, "\n- ")[0],
		"trailing text":     good + "\nextra",
		"fields reordered":  strings.Replace(good, "Version: 1\nChain ID: 1", "Chain ID: 1\nVersion: 1", 1),
		"truncated":         strings.Split(good, "\nURI:")[0],
		"crlf":              strings.ReplaceAll(good, "\n", "\r\n"),
		"too long":          strings.Replace(good, "Sign in to Example.", strings.Repeat("a", siwe.MaxMessageLength), 1),
		"header only":       strings.Split(good, "\n")[0],
		"no statement line": strings.Split(good, "\n\n")[0] + "\n",
		"no chain line":     strings.Replace(good, "Chain ID: 1\n", "", 1),
		"no issued line":    regexp.MustCompile(`Issued At: [^\n]*\n`).ReplaceAllString(good, ""),
		"empty scheme":      strings.Replace(good, "https://app", "://app", 1),
		"scheme symbol":     strings.Replace(good, "https://app", "ht$tps://app", 1),
	}
	for name, text := range cases {
		if _, err := siwe.ParseMessage(text); !errors.Is(err, siwe.ErrMessageMalformed) {
			t.Errorf("%s: ParseMessage = %v, want ErrMessageMalformed", name, err)
		}
	}
	if _, err := siwe.ParseMessage(good); err != nil {
		t.Fatalf("the unmutated message must parse: %v", err)
	}
}

// TestPersonalSign_RecoversTheSigner: a real signature from the fixed key
// recovers its address; the same signature over another text, a flipped
// byte, a bad v and a wrong length do not verify, and a signature with v
// written as 0/1 (some signers) is accepted like 27/28.
func TestPersonalSign_RecoversTheSigner(t *testing.T) {
	key := siwetest.MustKey(siwetest.HardhatKey0)
	m := sampleMessage(key.Address())
	text := m.String()
	sig, err := siwe.DecodeSignature(key.Sign(text))
	if err != nil {
		t.Fatal(err)
	}
	v := siwe.PersonalSign{}
	ctx := context.Background()
	if err := v.VerifySignature(ctx, siwe.SignedMessage{Text: text, Message: m, Signature: sig}); err != nil {
		t.Fatalf("a real signature: %v", err)
	}
	low := append([]byte{}, sig...)
	low[64] -= 27
	if err := v.VerifySignature(ctx, siwe.SignedMessage{Text: text, Message: m, Signature: low}); err != nil {
		t.Fatalf("v as 0/1: %v", err)
	}
	other := siwetest.MustKey(siwetest.SecondKey)
	flipped := append([]byte{}, sig...)
	flipped[10] ^= 0x01
	badV := append([]byte{}, sig...)
	badV[64] = 29
	for name, sm := range map[string]siwe.SignedMessage{
		"other text":    {Text: text + " ", Message: m, Signature: sig},
		"flipped byte":  {Text: text, Message: m, Signature: flipped},
		"bad v":         {Text: text, Message: m, Signature: badV},
		"short":         {Text: text, Message: m, Signature: sig[:64]},
		"other address": {Text: text, Message: sampleMessage(other.Address()), Signature: sig},
	} {
		if err := v.VerifySignature(ctx, sm); !errors.Is(err, siwe.ErrSignatureMismatch) {
			t.Errorf("%s: %v, want ErrSignatureMismatch", name, err)
		}
	}
}

// TestPersonalSign_RefusesHighS: the malleable twin of a valid signature
// (s replaced by n - s, v flipped) recovers the same key mathematically, and
// is refused (EIP-2), so one message has one valid signature.
func TestPersonalSign_RefusesHighS(t *testing.T) {
	key := siwetest.MustKey(siwetest.HardhatKey0)
	text := sampleMessage(key.Address()).String()
	sig, _ := siwe.DecodeSignature(key.Sign(text))
	n, _ := hex.DecodeString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
	twin := append([]byte{}, sig...)
	// s' = n - s, big-endian subtraction.
	var borrow int
	for i := 31; i >= 0; i-- {
		d := int(n[i]) - int(sig[32+i]) - borrow
		borrow = 0
		if d < 0 {
			d += 256
			borrow = 1
		}
		twin[32+i] = byte(d)
	}
	twin[64] ^= 1
	if _, err := siwe.RecoverAddress(text, twin); !errors.Is(err, siwe.ErrSignatureMismatch) {
		t.Fatalf("high-s twin: %v, want ErrSignatureMismatch", err)
	}
}

func TestDecodeSignature(t *testing.T) {
	for _, bad := range []string{"", "0x", "0xzz"} {
		if _, err := siwe.DecodeSignature(bad); !errors.Is(err, siwe.ErrSignatureMismatch) {
			t.Errorf("DecodeSignature(%q) = %v", bad, err)
		}
	}
	if b, err := siwe.DecodeSignature("0a0b"); err != nil || len(b) != 2 {
		t.Fatalf("without 0x: %v %v", b, err)
	}
}

// TestValidate_RefusesUnusableConfigs: no BaseURL and no Origins, and
// RequireEmail without the email plugin, fail at start-up.
func TestValidate_RefusesUnusableConfigs(t *testing.T) {
	if _, err := auth.New(auth.WithPlugins(siwe.New())); !errors.Is(err, siwe.ErrNoOrigin) {
		t.Fatalf("no origin: %v", err)
	}
	if _, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(siwe.New(siwe.RequireEmail()))); !errors.Is(err, siwe.ErrRequireEmailNoKind) {
		t.Fatalf("RequireEmail without email: %v", err)
	}
	if _, err := auth.New(auth.WithPlugins(siwe.New(siwe.Origins("https://app.example.com")))); err != nil {
		t.Fatalf("Origins alone is enough: %v", err)
	}
}

// TestOptions_RefuseBadValues: the value options record an error naming
// themselves, and an empty variadic keeps the default.
func TestOptions_RefuseBadValues(t *testing.T) {
	for name, opt := range map[string]siwe.Option{
		"siwe.WithNonceTTL": siwe.WithNonceTTL(0),
		"siwe.Origins":      siwe.Origins("https://app.example.com/path"),
		"siwe.Chains":       siwe.Chains(1, -5),
	} {
		if err := siwe.New(opt).OptionErr(); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: OptionErr = %v, want an error naming it", name, err)
		}
	}
	for _, opt := range []siwe.Option{siwe.Origins(), siwe.Chains(), siwe.WithNonceTTL(time.Minute)} {
		if err := siwe.New(opt).OptionErr(); err != nil {
			t.Errorf("OptionErr = %v, want nil", err)
		}
	}
}

func TestMigrations_PerEngine(t *testing.T) {
	p := siwe.New()
	if _, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(p)); err != nil {
		t.Fatal(err)
	}
	if _, err := p.TypedMigrations("oracle", auth.TypesFor("oracle")); err == nil {
		t.Fatal("an unknown engine must be refused")
	}
	my, err := p.TypedMigrations(auth.EngineMySQL, auth.TypesFor(auth.EngineMySQL))
	if err != nil || len(my) != 1 || len(my[0].Statements) != 1 || !strings.Contains(my[0].Statements[0], "INDEX ") {
		t.Fatalf("mysql declares the index inside CREATE TABLE: %+v, %v", my, err)
	}
	pg, err := p.TypedMigrations(auth.EnginePostgres, auth.TypesFor(auth.EnginePostgres))
	if err != nil || len(pg) != 1 || len(pg[0].Statements) != 2 || !strings.Contains(pg[0].Statements[0], "UNIQUE ("+siwe.ColAddress+", "+siwe.ColChainID+")") {
		t.Fatalf("postgres: %+v, %v", pg, err)
	}
}

// TestAdapters_VerifierFuncAndNameResolverFuncCallTheirFunction pins the two
// function adapters, which an app uses to plug in an RPC-backed check or an
// ENS lookup without declaring a type.
func TestAdapters_VerifierFuncAndNameResolverFuncCallTheirFunction(t *testing.T) {
	errMine := errors.New("mine")
	v := siwe.VerifierFunc(func(context.Context, siwe.SignedMessage) error { return errMine })
	if err := v.VerifySignature(context.Background(), siwe.SignedMessage{}); !errors.Is(err, errMine) {
		t.Fatalf("VerifierFunc = %v", err)
	}
	r := siwe.NameResolverFunc(func(_ context.Context, addr string, chain int64) (siwe.WalletName, error) {
		return siwe.WalletName{Name: addr, Avatar: "chain"}, nil
	})
	if got, err := r.LookupName(context.Background(), "0xabc", 1); err != nil || got.Name != "0xabc" {
		t.Fatalf("NameResolverFunc = %+v, %v", got, err)
	}
}

// TestRecoverAddress_RefusesASignatureThatRecoversNothing: 65 bytes of zero
// have the right length and a legal v but no public key behind them.
func TestRecoverAddress_RefusesASignatureThatRecoversNothing(t *testing.T) {
	if _, err := siwe.RecoverAddress("text", make([]byte, 65)); !errors.Is(err, siwe.ErrSignatureMismatch) {
		t.Fatalf("zero signature = %v, want ErrSignatureMismatch", err)
	}
}
