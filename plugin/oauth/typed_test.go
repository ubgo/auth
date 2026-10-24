package oauth

import (
	"context"
	"errors"
	"testing"

	"github.com/ubgo/auth"
)

// TestStartCallback_ProviderLookup pins what the typed methods answer before
// the pipeline runs: a provider not configured, or left out by
// SkipBrokenProviders, is ErrProviderUnknown, and a configured one on a plugin
// auth.New never wired is the pipeline's own ErrOperationNotWired.
func TestStartCallback_ProviderLookup(t *testing.T) {
	ctx := context.Background()
	p := New(WithProviders(Google("id", "secret"), GitHub("id", "secret")))
	if _, err := p.Start(ctx, "nope", StartRequest{}); !errors.Is(err, ErrProviderUnknown) {
		t.Fatalf("Start(unknown) = %v", err)
	}
	if _, err := p.Callback(ctx, "nope", CallbackRequest{}); !errors.Is(err, ErrProviderUnknown) {
		t.Fatalf("Callback(unknown) = %v", err)
	}
	if _, err := p.Start(ctx, "github", StartRequest{}); !errors.Is(err, auth.ErrOperationNotWired) {
		t.Fatalf("Start(unwired) = %v", err)
	}
	if _, err := p.Callback(ctx, "google", CallbackRequest{}); !errors.Is(err, auth.ErrOperationNotWired) {
		t.Fatalf("Callback(unwired) = %v", err)
	}
	p.skipped["github"] = errors.New("broken")
	if _, err := p.Start(ctx, "github", StartRequest{}); !errors.Is(err, ErrProviderUnknown) {
		t.Fatalf("Start(skipped) = %v", err)
	}
	// A group without the provider's operation (never the case after New)
	// answers the same, rather than running another provider's flow.
	if _, err := callProvider[StartRequest, StartResult](ctx, p, nil, "google", StartRequest{}); !errors.Is(err, ErrProviderUnknown) {
		t.Fatalf("callProvider(empty group) = %v", err)
	}
}
