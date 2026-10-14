package oauth

import (
	"encoding/json"
	"testing"
	"time"
)

// The claim key covers what the provider signed and nothing else: a second
// spelling of the signature (an ES256 (r, n-s) twin) is the same issuance,
// any change to the header or payload is another, and a token that is not a
// compact JWS is keyed whole.
func TestIDTokenKey(t *testing.T) {
	base := idTokenKey("aGVhZA.cGF5bG9hZA.c2lnMQ")
	if len(base) != 64 {
		t.Fatalf("key %q is not a hex SHA-256", base)
	}
	if idTokenKey("aGVhZA.cGF5bG9hZA.c2lnMg") != base {
		t.Fatal("another signature over the same header and payload changed the key")
	}
	if idTokenKey("aGVhZA.cGF5bG9hZB.c2lnMQ") == base || idTokenKey("aGVhZB.cGF5bG9hZA.c2lnMQ") == base {
		t.Fatal("another payload or header kept the key")
	}
	if idTokenKey("opaque") == idTokenKey("opaque2") || idTokenKey("a.b") == idTokenKey("a.c") {
		t.Fatal("a token that is not a compact JWS must be keyed whole")
	}
}

// The claim lasts until exp plus the verifier's leeway; without a readable
// exp, idTokenClaimFallback from now.
func TestIDTokenUntil(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	exp := now.Add(time.Hour)
	withExp := Profile{Claims: map[string]json.RawMessage{claimExp: json.RawMessage(jsonInt(exp.Unix()))}}
	if got := idTokenUntil(withExp, now); !got.Equal(exp.Add(idTokenLeeway)) {
		t.Fatalf("until = %v, want exp plus leeway", got)
	}
	for name, p := range map[string]Profile{
		"no claims":    {},
		"a string exp": {Claims: map[string]json.RawMessage{claimExp: json.RawMessage(`"soon"`)}},
		"a zero exp":   {Claims: map[string]json.RawMessage{claimExp: json.RawMessage(`0`)}},
	} {
		if got := idTokenUntil(p, now); !got.Equal(now.Add(idTokenClaimFallback)) {
			t.Fatalf("%s: until = %v, want the fallback", name, got)
		}
	}
}

func jsonInt(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}
