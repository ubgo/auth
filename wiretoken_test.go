package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/ubgo/auth"
)

// TestWireToken_EncodesInJSONOnly: a WireToken crosses the wire as itself,
// both ways, and still prints "[redacted]" on every other formatting path.
func TestWireToken_EncodesInJSONOnly(t *testing.T) {
	const raw = "sentinel-wire-7d1e"
	tok := auth.WireToken(raw)

	js, err := json.Marshal(struct {
		T auth.WireToken `json:"t"`
	}{tok})
	if err != nil || string(js) != `{"t":"`+raw+`"}` {
		t.Fatalf("json = %s %v", js, err)
	}
	var back struct {
		T auth.WireToken `json:"t"`
	}
	if err := json.Unmarshal(js, &back); err != nil || back.T.Reveal() != raw || back.T.Token() != auth.Token(raw) {
		t.Fatalf("decoded %q %v", back.T.Reveal(), err)
	}
	if auth.Token(raw).Wire() != tok {
		t.Fatal("Token.Wire must keep the value")
	}

	if tok.String() != "[redacted]" || tok.GoString() != "[redacted]" {
		t.Fatal("String and GoString must redact")
	}
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("x", "token", tok)
	for name, s := range map[string]string{
		"%v": fmt.Sprintf("%v", tok), "%s": fmt.Sprintf("%s", tok), "%q": fmt.Sprintf("%q", tok),
		"%#v": fmt.Sprintf("%#v", tok), "%x": fmt.Sprintf("%x", tok), "%d": fmt.Sprintf("%d", tok),
		"%+v in a struct": fmt.Sprintf("%+v", struct{ T auth.WireToken }{tok}),
		"slog":            logged.String(), "error": fmt.Errorf("failed with %v", tok).Error(),
	} {
		if strings.Contains(s, raw) {
			t.Errorf("%s printed the raw token: %s", name, s)
		}
	}
}

// Outputs the guard must refuse, one per path encoding/json can reach a
// Token through, and outputs it must accept.
type (
	outDirect struct{ Token auth.Token }
	outTagged struct {
		T auth.Token `json:"tok,omitempty"`
	}
	outPointer struct{ P *outTagged }
	outSlice   struct{ S []outDirect }
	outMap     struct{ M map[string]auth.Token }
	outEmbed   struct{ outTagged }
	outRecurse struct {
		Next *outRecurse
		T    auth.Token
	}

	outHidden struct {
		T auth.Token `json:"-"`
		W auth.WireToken
		t auth.Token
	}
	outOwnJSON struct{ T auth.Token }
	outCycle   struct{ Next *outCycle }
)

// MarshalJSON gives outOwnJSON its own encoding, which the guard leaves to it.
func (outOwnJSON) MarshalJSON() ([]byte, error) { return []byte(`{}`), nil }

// outputPlugin registers one operation whose output is Out.
type outputPlugin[Out any] struct{}

func (outputPlugin[Out]) Name() string { return "outp" }
func (outputPlugin[Out]) Operations() []auth.Operation {
	return []auth.Operation{auth.Define(auth.OpInfo{ID: "outp.get", Kind: auth.Query, Require: auth.Public, Path: "/get"},
		func(context.Context, *auth.Call, struct{}) (Out, error) {
			var zero Out
			return zero, nil
		})}
}

// TestNew_RefusesARedactedTokenInAnOutput: auth.New refuses an operation
// whose answer would carry "[redacted]" in place of a token, naming the
// field, and accepts tokens hidden from JSON or carried as WireToken.
func TestNew_RefusesARedactedTokenInAnOutput(t *testing.T) {
	refused := map[string]auth.Plugin{
		"Token":       outputPlugin[outDirect]{},
		"tok":         outputPlugin[outTagged]{},
		"P.tok":       outputPlugin[outPointer]{},
		"S.Token":     outputPlugin[outSlice]{},
		"M":           outputPlugin[outMap]{},
		"tok (embed)": outputPlugin[outEmbed]{},
		"T":           outputPlugin[outRecurse]{},
		"itself":      outputPlugin[auth.Token]{},
	}
	for field, p := range refused {
		_, err := auth.New(auth.WithPlugins(signIn{on: true}, p))
		name, _, _ := strings.Cut(field, " ")
		if !errors.Is(err, auth.ErrBadOperation) || !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), "auth.WireToken") {
			t.Errorf("%s: %v", field, err)
		}
	}
	for name, p := range map[string]auth.Plugin{
		"hidden":   outputPlugin[outHidden]{},
		"own json": outputPlugin[outOwnJSON]{},
		"cycle":    outputPlugin[outCycle]{},
	} {
		if _, err := auth.New(auth.WithPlugins(signIn{on: true}, p)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestTranslate_LooksUpTheRequestLocale: Translate answers the catalogue's
// text for the request's locale, and false without a catalogue or a text.
func TestTranslate_LooksUpTheRequestLocale(t *testing.T) {
	const code = "app.page.heading"
	plain, err := newAuth(auth.WithPlugins(signIn{on: true}))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := plain.Translate(context.Background(), code); ok {
		t.Fatal("no catalogue must answer false")
	}
	a, err := newAuth(auth.WithPlugins(signIn{on: true}), auth.WithDefaultLocale("de"), auth.WithMessages(auth.Messages{"de": {code: "Hallo"}}))
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := a.Translate(context.Background(), code); !ok || got != "Hallo" {
		t.Fatalf("de = %q %v", got, ok)
	}
	if _, ok := a.Translate(context.Background(), "app.other"); ok {
		t.Fatal("a missing code must answer false")
	}
}
