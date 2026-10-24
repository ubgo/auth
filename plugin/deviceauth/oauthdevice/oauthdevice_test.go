package oauthdevice

import (
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"reflect"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/deviceauth"
	"github.com/ubgo/auth/plugin/oauthprovider"
)

// TestCredentials reads each client authentication method and refuses two
// at once, a wrong assertion type, another scheme and a mismatched id.
func TestCredentials(t *testing.T) {
	basic := func(id, secret string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(id)+":"+url.QueryEscape(secret)))
	}
	ok := []struct {
		header string
		in     deviceauth.CodeRequest
		want   oauthprovider.ClientCredentials
	}{
		{"", deviceauth.CodeRequest{ClientID: "c"}, oauthprovider.ClientCredentials{ID: "c", Method: oauthprovider.AuthMethodNone}},
		{"", deviceauth.CodeRequest{ClientID: "c", ClientSecret: "s"}, oauthprovider.ClientCredentials{ID: "c", Secret: "s", Method: oauthprovider.AuthMethodPost}},
		{basic("c d", "s:x"), deviceauth.CodeRequest{}, oauthprovider.ClientCredentials{ID: "c d", Secret: "s:x", Method: oauthprovider.AuthMethodBasic}},
		{"", deviceauth.CodeRequest{ClientID: "c", ClientAssertion: "jwt", ClientAssertionType: oauthprovider.ClientAssertionType},
			oauthprovider.ClientCredentials{ID: "c", Method: oauthprovider.AuthMethodPrivateKeyJWT, Assertion: "jwt"}},
	}
	for _, c := range ok {
		got, err := credentials(c.header, c.in)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q %+v = %+v %v", c.header, c.in, got, err)
		}
	}
	bad := []struct {
		header string
		in     deviceauth.CodeRequest
		want   error
	}{
		{basic("c", "s"), deviceauth.CodeRequest{ClientAssertion: "j", ClientAssertionType: oauthprovider.ClientAssertionType}, oauthprovider.ErrInvalidRequest},
		{"", deviceauth.CodeRequest{ClientAssertion: "j", ClientAssertionType: "other"}, oauthprovider.ErrInvalidClient},
		{"Bearer x", deviceauth.CodeRequest{}, oauthprovider.ErrInvalidClient},
		{basic("c", "s"), deviceauth.CodeRequest{ClientSecret: "s"}, oauthprovider.ErrInvalidRequest},
		{"Basic !!", deviceauth.CodeRequest{}, oauthprovider.ErrInvalidClient},
		{"Basic " + base64.StdEncoding.EncodeToString([]byte("nocolon")), deviceauth.CodeRequest{}, oauthprovider.ErrInvalidClient},
		{basic("c", "s"), deviceauth.CodeRequest{ClientID: "other"}, oauthprovider.ErrInvalidRequest},
	}
	for _, c := range bad {
		if _, err := credentials(c.header, c.in); !errors.Is(err, c.want) {
			t.Errorf("%q %+v: %v, want %v", c.header, c.in, err, c.want)
		}
	}
}

// TestWireAndSurface: provider refusals carry their RFC code; the grant
// is the device_code type under this plugin's error namespace.
func TestWireAndSurface(t *testing.T) {
	for err, want := range map[error]string{oauthprovider.ErrInvalidScope: "invalid_scope", oauthprovider.ErrInvalidTarget: "invalid_target",
		oauthprovider.ErrUnauthorizedClient: "unauthorized_client", oauthprovider.ErrInvalidClient: "invalid_client"} {
		if got := deviceauth.RFCErrorCode(wire(err)); got != want || !errors.Is(wire(err), err) {
			t.Errorf("%v = %s", err, got)
		}
	}
	other := errors.New("x")
	if wire(other) != other || wire(other).Error() != "x" || (wireError{err: other}).Error() != "x" {
		t.Fatal("an unknown error passes through")
	}
	g := New("https://app.example.com/auth/device/code")
	eg := g.ExtensionGrant()
	if g.Name() != PluginName || len(g.Requires()) != 2 || g.Endpoint() == "" || eg.Type != deviceauth.GrantType || eg.ErrorNamespace != errorNamespace || eg.Handle == nil {
		t.Fatal("surface")
	}
	if New("/relative").Validate(nil) == nil || g.Validate(nil) != nil {
		t.Fatal("Validate")
	}
	if !contains([]string{"a", "b"}, "b") || contains(nil, "a") {
		t.Fatal("contains")
	}
}

// TestAuthorizeCode_RefusesBeforeTheRegistry: credentials that do not parse
// answer with their RFC code, and a request naming no client at all is
// invalid_request, both before the provider is asked (AuthorizeCode is
// exported, so a caller other than deviceauth may skip its client_id check).
func TestAuthorizeCode_RefusesBeforeTheRegistry(t *testing.T) {
	g := New("https://app.example.com/auth/device/code")
	_, err := g.AuthorizeCode(context.Background(), &auth.Call{}, deviceauth.CodeRequest{ClientID: "c", ClientAssertion: "x", ClientAssertionType: "wrong"})
	if !errors.Is(err, oauthprovider.ErrInvalidClient) || deviceauth.RFCErrorCode(err) != "invalid_client" {
		t.Fatalf("bad assertion type: %v", err)
	}
	if _, err := g.AuthorizeCode(context.Background(), &auth.Call{}, deviceauth.CodeRequest{}); !errors.Is(err, deviceauth.ErrInvalidRequest) {
		t.Fatalf("no client: %v", err)
	}
}
