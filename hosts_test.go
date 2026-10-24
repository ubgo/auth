package auth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ubgo/auth"
)

func TestBaseURL_FollowsAnAllowedHost(t *testing.T) {
	a, err := newAuth(auth.WithPlugins(basic("s")), auth.WithAllowedHosts("Preview.example.com", "*.customers.example.net", "app.example.com:8443"))
	if err != nil {
		t.Fatal(err)
	}
	if got := a.BaseURL(context.Background()); got != "https://app.example.com" {
		t.Fatalf("outside a request: %q, want the static base URL", got)
	}
	cases := map[string]string{
		"preview.example.com":        "https://preview.example.com",
		"Preview.Example.com":        "https://preview.example.com", // hosts are case-insensitive
		"acme.customers.example.net": "https://acme.customers.example.net",
		"app.example.com:8443":       "https://app.example.com:8443",
		"evil.example":               "https://app.example.com", // not allowed: the static base URL
		"customers.example.net":      "https://app.example.com", // the wildcard needs a subdomain
		"":                           "https://app.example.com",
	}
	for host, want := range cases {
		ctx := a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP, Host: host})
		if got := a.BaseURL(ctx); got != want {
			t.Errorf("BaseURL for host %q = %q, want %q", host, got, want)
		}
		if got := auth.RequestHost(ctx); got != host {
			t.Errorf("RequestHost = %q, want %q", got, host)
		}
	}
	if auth.RequestHost(context.Background()) != "" {
		t.Fatal("RequestHost outside a request must be empty")
	}
	// Allowed hosts are trusted origins under the base URL's scheme, and
	// only that scheme.
	for origin, want := range map[string]bool{
		"https://preview.example.com":        true,
		"https://acme.customers.example.net": true,
		"https://app.example.com:8443":       true,
		"http://preview.example.com":         false,
		"https://evil.example":               false,
	} {
		if got := a.TrustsOrigin(origin); got != want {
			t.Errorf("TrustsOrigin(%q) = %v, want %v", origin, got, want)
		}
	}
}

func TestBaseURL_WithoutAllowedHostsIsStatic(t *testing.T) {
	a, err := newAuth(auth.WithPlugins(basic("s")))
	if err != nil {
		t.Fatal(err)
	}
	ctx := a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP, Host: "preview.example.com"})
	if got := a.BaseURL(ctx); got != "https://app.example.com" {
		t.Fatalf("without the option the host is ignored: %q", got)
	}
	// A base URL with a trailing slash never produces a double slash.
	b, err := auth.New(auth.WithPlugins(basic("s")), auth.WithBaseURL("http://localhost:8081/"))
	if err != nil {
		t.Fatal(err)
	}
	if got := b.BaseURL(context.Background()); got != "http://localhost:8081" {
		t.Fatalf("trailing slash: %q", got)
	}
	// The scheme follows the base URL: a plain-http base gives http hosts.
	c, err := auth.New(auth.WithPlugins(basic("s")), auth.WithBaseURL("http://localhost:8081"), auth.WithAllowedHosts("127.0.0.1:8081"))
	if err != nil {
		t.Fatal(err)
	}
	ctx = c.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP, Host: "127.0.0.1:8081"})
	if got := c.BaseURL(ctx); got != "http://127.0.0.1:8081" {
		t.Fatalf("http base: %q", got)
	}
	// No base URL at all: https is assumed for allowed hosts.
	d, err := auth.New(auth.WithPlugins(basic("s")), auth.WithAllowedHosts("x.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	ctx = d.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP, Host: "x.example.com"})
	if got := d.BaseURL(ctx); got != "https://x.example.com" {
		t.Fatalf("no base URL: %q", got)
	}
}

func TestNew_RefusesAHostThatIsNotAHost(t *testing.T) {
	for _, raw := range []string{"", "https://app.example.com", "app.example.com/path", "api.*", "*.example.*", "*", "*.com", "two words", "app.example.com:notaport"} {
		_, err := newAuth(auth.WithPlugins(basic("s")), auth.WithAllowedHosts(raw))
		if !errors.Is(err, auth.ErrBadHost) {
			t.Errorf("%q: %v, want ErrBadHost", raw, err)
		}
	}
}
