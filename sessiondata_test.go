package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// The AppData type is the one shape the app's JSON takes on its way through
// a store, a sealed token and a cache, so each conversion is pinned here:
// the value a driver gets, what a driver may hand back, and the JSON that
// rides inside the session's JSON.

type prefs struct {
	Workspace string `json:"ws"`
	Dark      bool   `json:"dark"`
}

func TestAppData_DriverRoundTrip(t *testing.T) {
	var none AppData
	if v, err := none.Value(); err != nil || v != nil {
		t.Fatalf("Value of none = %v, %v; want NULL", v, err)
	}
	some := AppData(`{"ws":"acme"}`)
	v, err := some.Value()
	if err != nil || v != `{"ws":"acme"}` {
		t.Fatalf("Value = %#v, %v; want the JSON as text", v, err)
	}
	for name, src := range map[string]any{"text": `{"ws":"acme"}`, "bytes": []byte(`{"ws":"acme"}`)} {
		var got AppData
		if err := got.Scan(src); err != nil || !bytes.Equal(got, some) {
			t.Fatalf("Scan(%s) = %q, %v; want %q", name, got, err, some)
		}
	}
	buf := []byte(`{"ws":"acme"}`)
	var got AppData
	if err := got.Scan(buf); err != nil {
		t.Fatal(err)
	}
	buf[2] = 'X'
	if !bytes.Equal(got, some) {
		t.Fatal("Scan must copy the driver's buffer, which the driver may reuse")
	}
	got = some
	if err := got.Scan(nil); err != nil || got != nil {
		t.Fatalf("Scan(NULL) = %q, %v; want none", got, err)
	}
	if err := got.Scan(42); err == nil || !strings.Contains(err.Error(), "int") {
		t.Fatalf("Scan(int) = %v, want an error naming the type", err)
	}
}

func TestAppData_JSONRoundTrip(t *testing.T) {
	type holder struct {
		D AppData `json:"d,omitempty"`
	}
	for name, tc := range map[string]struct {
		in   holder
		json string
	}{
		"none is omitted":    {holder{}, `{}`},
		"data rides as JSON": {holder{AppData(`{"ws":"acme"}`)}, `{"d":{"ws":"acme"}}`},
		"a scalar rides too": {holder{AppData(`7`)}, `{"d":7}`},
	} {
		b, err := json.Marshal(tc.in)
		if err != nil || string(b) != tc.json {
			t.Fatalf("%s: Marshal = %s, %v; want %s", name, b, err, tc.json)
		}
		var out holder
		if err := json.Unmarshal(b, &out); err != nil || !bytes.Equal(out.D, tc.in.D) {
			t.Fatalf("%s: Unmarshal = %q, %v; want %q", name, out.D, err, tc.in.D)
		}
	}
	// Without omitempty, as the Redis store and a plain Session encode it,
	// none is null and null reads back as none.
	b, err := json.Marshal(struct{ D AppData }{})
	if err != nil || string(b) != `{"D":null}` {
		t.Fatalf("Marshal of none without omitempty = %s, %v; want null", b, err)
	}
	var out struct{ D AppData }
	if err := json.Unmarshal(b, &out); err != nil || out.D != nil {
		t.Fatalf("Unmarshal of null = %q, %v; want none", out.D, err)
	}
	// Session itself round-trips with its data, as every JSON-based store
	// and cache relies on.
	s := Session{ID: "s1", Data: AppData(`{"ws":"acme"}`)}
	b, _ = json.Marshal(s)
	var back Session
	if err := json.Unmarshal(b, &back); err != nil || !bytes.Equal(back.Data, s.Data) {
		t.Fatalf("Session round trip: data %q, %v; want %q", back.Data, err, s.Data)
	}
}

func TestEncodeSessionData_Bounds(t *testing.T) {
	d, err := EncodeSessionData(prefs{Workspace: "acme", Dark: true})
	if err != nil || string(d) != `{"ws":"acme","dark":true}` {
		t.Fatalf("Encode = %s, %v", d, err)
	}
	if d, err := EncodeSessionData(nil); err != nil || d != nil {
		t.Fatalf("Encode(nil) = %q, %v; want none: nil clears the data", d, err)
	}
	if _, err := EncodeSessionData(make(chan int)); !errors.Is(err, ErrSessionDataInvalid) {
		t.Fatalf("Encode of a channel = %v, want ErrSessionDataInvalid", err)
	}
	fits := strings.Repeat("x", MaxSessionDataSize-2)
	if _, err := EncodeSessionData(fits); err != nil {
		t.Fatalf("a value of exactly MaxSessionDataSize bytes: %v, want accepted", err)
	}
	if _, err := EncodeSessionData(fits + "x"); !errors.Is(err, ErrSessionDataTooLarge) {
		t.Fatalf("one byte over = %v, want ErrSessionDataTooLarge", err)
	}
	// What a hook sets by hand passes the same checks at the insert, and is
	// compacted, so a JSON-based store and a SQL store hold the same bytes.
	if _, err := AppData(`{not json`).normalized(); !errors.Is(err, ErrSessionDataInvalid) {
		t.Fatalf("normalized of non-JSON = %v, want ErrSessionDataInvalid", err)
	}
	if d, err := AppData(nil).normalized(); err != nil || d != nil {
		t.Fatalf("normalized of none = %q, %v", d, err)
	}
	if d, err := AppData("{ \"ws\" : \"acme\" }\n").normalized(); err != nil || string(d) != `{"ws":"acme"}` {
		t.Fatalf("normalized of spaced JSON = %q, %v; want it compact", d, err)
	}
	// The bound applies to the compact form: spaces do not count.
	spaced := AppData(`"` + fits + `"` + strings.Repeat(" ", 10))
	if _, err := spaced.normalized(); err != nil {
		t.Fatalf("a value within the bound once compacted: %v", err)
	}
}

func TestDecodeSessionData(t *testing.T) {
	v, ok, err := DecodeSessionData[prefs](AppData(`{"ws":"acme","dark":true}`))
	if err != nil || !ok || v != (prefs{Workspace: "acme", Dark: true}) {
		t.Fatalf("Decode = %+v, %v, %v", v, ok, err)
	}
	if v, ok, err := DecodeSessionData[prefs](nil); err != nil || ok || v != (prefs{}) {
		t.Fatalf("Decode of none = %+v, %v, %v; want zero, false, nil", v, ok, err)
	}
	if _, ok, err := DecodeSessionData[prefs](AppData(`"a string"`)); err == nil || ok {
		t.Fatalf("Decode of another type = %v, %v; want an error", ok, err)
	}
}

func TestSessionData_OutsideARequest(t *testing.T) {
	if v, ok, err := SessionData[prefs](context.Background()); err != nil || ok || v != (prefs{}) {
		t.Fatalf("SessionData with no request = %+v, %v, %v; want zero, false, nil", v, ok, err)
	}
	a, err := New(WithPlugins(scriptSignIn{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := SetSessionData(a.WithRequest(context.Background(), Request{}), a, prefs{}); !errors.Is(err, ErrSignedOut) {
		t.Fatalf("SetSessionData signed out = %v, want ErrSignedOut", err)
	}
	if err := SetSessionData(context.Background(), a, prefs{}); !errors.Is(err, ErrSignedOut) {
		t.Fatalf("SetSessionData with no request = %v, want ErrSignedOut", err)
	}
}

func TestMemorySessionStore_SetDataOfUnknownID(t *testing.T) {
	m := NewMemorySessionStore()
	if err := m.SetData(context.Background(), "nobody", AppData(`1`)); err != nil {
		t.Fatalf("SetData of an unknown id = %v, want nil", err)
	}
}
