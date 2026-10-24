package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/ubgo/auth"
)

// german is a catalogue with a base language and one regional override, as a
// translation file would unmarshal.
func german(t *testing.T) auth.Messages {
	t.Helper()
	var m auth.Messages
	raw := `{"de": {"auth.signed_out": "Bitte anmelden.", "auth.rate_limited": "Zu viele Versuche."}, "de-CH": {"auth.signed_out": "Bitte anmelde."}}`
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMessages_LooksUpExactThenBaseLanguage(t *testing.T) {
	m := german(t)
	cases := []struct {
		locale, code, want string
		ok                 bool
	}{
		{"de", "auth.signed_out", "Bitte anmelden.", true},
		{"DE", "auth.signed_out", "Bitte anmelden.", true},
		{"de-CH", "auth.signed_out", "Bitte anmelde.", true},
		{"de-ch", "auth.signed_out", "Bitte anmelde.", true},
		// The region lacks the code: the base language serves it.
		{"de-CH", "auth.rate_limited", "Zu viele Versuche.", true},
		{"de-AT", "auth.signed_out", "Bitte anmelden.", true},
		{"fr", "auth.signed_out", "", false},
		{"de", "auth.unknown", "", false},
		{"", "auth.signed_out", "", false},
	}
	for _, c := range cases {
		got, ok := m.Message(c.locale, c.code)
		if got != c.want || ok != c.ok {
			t.Errorf("Message(%q, %q) = %q, %v; want %q, %v", c.locale, c.code, got, ok, c.want, c.ok)
		}
	}
	if _, ok := auth.Messages(nil).Message("de", "auth.signed_out"); ok {
		t.Error("an empty catalogue has no message")
	}
	empty := auth.Messages{"de": {"auth.signed_out": ""}}
	if _, ok := empty.Message("de", "auth.signed_out"); ok {
		t.Error("an empty translation is no translation: the English message must be used")
	}
}

func TestWithMessages_TranslatesErrorsInTheRequestLocale(t *testing.T) {
	a, err := newAuth(auth.WithPlugins(basic("s")), auth.WithMessages(german(t)), auth.WithDefaultLocale("de"))
	if err != nil {
		t.Fatal(err)
	}
	signedOut := auth.ErrorOf(auth.ErrSignedOut)

	// A request in Swiss German gets the regional text; code and status stay.
	ctx := a.WithRequest(context.Background(), auth.Request{Client: auth.Client{Locale: "de-CH"}})
	got := auth.ErrorInfoFor(ctx, auth.ErrSignedOut)
	if got.Message != "Bitte anmelde." || got.Code != signedOut.Code || got.Status != signedOut.Status {
		t.Fatalf("de-CH: %+v", got)
	}
	// A wrapped error still translates, because ErrorOf matches by code.
	if got := a.ErrorInfo(ctx, errors.Join(errors.New("sign-in"), auth.ErrSignedOut)); got.Message != "Bitte anmelde." {
		t.Fatalf("wrapped: %+v", got)
	}
	// No language on the request: the default locale.
	if got := auth.ErrorInfoFor(a.WithRequest(context.Background(), auth.Request{}), auth.ErrSignedOut); got.Message != "Bitte anmelden." {
		t.Fatalf("default locale: %+v", got)
	}
	// A language the catalogue lacks, or a code it lacks: the declared text.
	if got := auth.ErrorInfoFor(a.WithRequest(context.Background(), auth.Request{Client: auth.Client{Locale: "fr"}}), auth.ErrSignedOut); got.Message != signedOut.Message {
		t.Fatalf("fr: %+v", got)
	}
	if got := a.ErrorInfo(ctx, auth.ErrUserNotFound); got.Message != auth.ErrUserNotFound.Message {
		t.Fatalf("untranslated code: %+v", got)
	}
	// An internal error is still hidden, in any language.
	if got := a.ErrorInfo(ctx, errors.New("pq: relation auth_user does not exist")); got != auth.ErrorOf(auth.ErrInternal) {
		t.Fatalf("internal: %+v", got)
	}
	// Locale is the one rule behind it.
	if l := a.Locale(ctx); l != "de-CH" {
		t.Fatalf("Locale = %q", l)
	}
	if l := a.Locale(context.Background()); l != "de" {
		t.Fatalf("Locale without a request = %q, want the default", l)
	}
}

func TestErrorInfoFor_WithoutACatalogueOrRequestIsErrorOf(t *testing.T) {
	// No request attached: nothing to translate with.
	if got := auth.ErrorInfoFor(context.Background(), auth.ErrSignedOut); got != auth.ErrorOf(auth.ErrSignedOut) {
		t.Fatalf("no request: %+v", got)
	}
	// A request on an Auth without WithMessages: the declared text, so
	// adding a locale to a request changes nothing for apps without a
	// catalogue.
	a, err := newAuth(auth.WithPlugins(basic("s")))
	if err != nil {
		t.Fatal(err)
	}
	ctx := a.WithRequest(context.Background(), auth.Request{Client: auth.Client{Locale: "de"}})
	if got := auth.ErrorInfoFor(ctx, auth.ErrSignedOut); got != auth.ErrorOf(auth.ErrSignedOut) {
		t.Fatalf("no catalogue: %+v", got)
	}
	if l := a.Locale(context.Background()); l != "" {
		t.Fatalf("Locale with nothing set = %q", l)
	}
}

// A catalogue that is not a Messages map is the app's and is not inspected.
type funcCatalog func(locale, code string) (string, bool)

func (f funcCatalog) Message(locale, code string) (string, bool) { return f(locale, code) }

func TestNew_RefusesACatalogueWithABadLocale(t *testing.T) {
	for _, bad := range []auth.Messages{{"": {"x": "y"}}, {"de CH": {"x": "y"}}, {"de_CH": {"x": "y"}}} {
		if _, err := newAuth(auth.WithPlugins(basic("s")), auth.WithMessages(bad)); !errors.Is(err, auth.ErrBadOperation) {
			t.Errorf("%v: got %v, want ErrBadOperation", bad, err)
		}
	}
	custom := funcCatalog(func(_, code string) (string, bool) { return "X " + code, true })
	a, err := newAuth(auth.WithPlugins(basic("s")), auth.WithMessages(custom), auth.WithDefaultLocale("xx"))
	if err != nil {
		t.Fatal(err)
	}
	if got := a.ErrorInfo(context.Background(), auth.ErrSignedOut); got.Message != "X auth.signed_out" {
		t.Fatalf("custom catalogue: %+v", got)
	}
}
