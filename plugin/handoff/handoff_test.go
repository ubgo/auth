package handoff_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/handoff"
)

var noMail = email.MailerFunc(func(context.Context, email.Mail) error { return nil })

func base() []auth.Option {
	return []auth.Option{auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(email.New(email.Login(), email.SignInWithCode(), email.WithMailer(noMail)))}
}

// TestValidate: a non-positive TTL is refused at auth.New; the plugin is not
// a sign-in method by itself, so it needs one beside it.
func TestValidate(t *testing.T) {
	if _, err := auth.New(append(base(), auth.WithPlugins(handoff.New(handoff.WithTTL(0))))...); !errors.Is(err, handoff.ErrBadTTL) {
		t.Fatalf("TTL 0 = %v", err)
	}
	if _, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(handoff.New())); !errors.Is(err, auth.ErrNoSignInMethod) {
		t.Fatalf("hand-off alone = %v", err)
	}
	a, err := auth.New(append(base(), auth.WithPlugins(handoff.New(handoff.WithTTL(time.Minute), handoff.ServerOnly())))...)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []auth.EndpointID{handoff.EndpointGenerate, handoff.EndpointVerify} {
		if _, ok := a.Operation(id); !ok {
			t.Fatalf("%s not registered", id)
		}
	}
}

// TestGenerateLimitOption: WithGenerateLimit and WithVerifyLimit replace the
// two per-IP rules; the per-token verify rule is fixed, and keys on the
// token's hash rather than the token.
func TestGenerateLimitOption(t *testing.T) {
	rules := handoff.New(handoff.WithGenerateLimit(3, time.Hour), handoff.WithVerifyLimit(4, 2*time.Hour)).RateLimits()
	if len(rules) != 3 || rules[0].Match != handoff.EndpointGenerate || rules[0].Key != auth.ByIP || rules[0].Limit != 3 || rules[0].Window != time.Hour {
		t.Fatalf("rules = %+v", rules)
	}
	if rules[1].Match != handoff.EndpointVerify || rules[1].Key != auth.ByIP || rules[1].Limit != 4 || rules[1].Window != 2*time.Hour {
		t.Fatalf("verify per IP = %+v", rules[1])
	}
	if rules[2].Match != handoff.EndpointVerify || rules[2].Key != auth.ByIdentifier || rules[2].Limit != 5 || rules[2].Window != time.Minute {
		t.Fatalf("verify per token = %+v", rules[2])
	}
	def := handoff.New().RateLimits()
	if def[0].Limit != 10 || def[0].Window != time.Minute || def[1].Limit != 10 || def[1].Window != time.Minute {
		t.Fatalf("default = %+v", def)
	}
	key := handoff.VerifyRequest{Token: "secret-token"}.RateIdentifier()
	if key == "secret-token" || len(key) != 64 || key != (handoff.VerifyRequest{Token: "secret-token"}).RateIdentifier() {
		t.Fatalf("rate key must be the stable hash of the token, got %q", key)
	}
}

// TestUnwired: the Go methods of a plugin not passed to auth.New report it.
func TestUnwired(t *testing.T) {
	hp := handoff.New()
	if _, err := hp.Generate(context.Background()); !errors.Is(err, auth.ErrOperationNotWired) {
		t.Fatalf("Generate = %v", err)
	}
	if _, err := hp.Verify(context.Background(), "x"); !errors.Is(err, auth.ErrOperationNotWired) {
		t.Fatalf("Verify = %v", err)
	}
	if hp.Name() != handoff.PluginName {
		t.Fatal("name")
	}
}

// TestChallengeOf: the S256 challenge is RFC 7636 appendix B's worked
// example, and NewVerifier makes distinct verifiers of the documented size.
func TestChallengeOf(t *testing.T) {
	const verifier, challenge = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := handoff.ChallengeOf(verifier); got != challenge {
		t.Fatalf("ChallengeOf = %s", got)
	}
	v1, c1, err := handoff.NewVerifier()
	if err != nil {
		t.Fatal(err)
	}
	v2, c2, err := handoff.NewVerifier()
	if err != nil {
		t.Fatal(err)
	}
	if v1 == v2 || c1 == c2 || len(v1) != handoff.MinVerifierLen || c1 != handoff.ChallengeOf(v1) {
		t.Fatalf("NewVerifier = %q %q / %q %q", v1, c1, v2, c2)
	}
	if handoff.ChallengeMethod != "S256" || handoff.VerifierBytes != 32 || handoff.MaxVerifierLen != 128 {
		t.Fatal("the documented constants changed")
	}
}

// TestServerOnly_NotOffered: under ServerOnly the generate route is in no
// generated surface (the TypeScript client, its method list, the OpenAPI
// document), because every transport would answer it
// auth.unknown_operation; without the option it is in all three, so the
// check is not vacuous.
func TestServerOnly_NotOffered(t *testing.T) {
	for _, tc := range []struct {
		name    string
		opts    []handoff.Option
		offered bool
	}{
		{"default", nil, true},
		{"ServerOnly", []handoff.Option{handoff.ServerOnly()}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := auth.New(append(base(), auth.WithPlugins(handoff.New(tc.opts...)))...)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := a.Operation(handoff.EndpointGenerate); !ok {
				t.Fatal("generate must stay registered, for the Go call")
			}
			files, err := authhttp.TypeScriptClient(a)
			if err != nil {
				t.Fatal(err)
			}
			methods, err := authhttp.TypeScriptMethods(a)
			if err != nil {
				t.Fatal(err)
			}
			listed := false
			for _, m := range methods {
				listed = listed || m.ID == handoff.EndpointGenerate
			}
			id := `"` + string(handoff.EndpointGenerate) + `"`
			doc := authhttp.OpenAPIDocument(a, authhttp.OpenAPIInfo{Title: "t", Version: "1"})
			for surface, got := range map[string]bool{
				"client.ts":         strings.Contains(string(files[authhttp.TSFileClient]), id),
				"TypeScriptMethods": listed,
				"OpenAPI":           strings.Contains(string(doc), id),
			} {
				if got != tc.offered {
					t.Errorf("%s lists %s = %v, want %v", surface, handoff.EndpointGenerate, got, tc.offered)
				}
			}
		})
	}
}
