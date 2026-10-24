package oauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
)

// Loader is a Provider that reads part of its configuration lazily (a
// discovery document, a key set). SkipBrokenProviders calls Load on every
// one at auth.New, so a provider that cannot be loaded is found and left out
// then rather than failing its first flow. *OAuth2 and *OIDCProvider
// implement it; a custom Provider that is not a Loader is checked on its
// name alone.
//
//ds:def id=loader-n7wk3xqt owner=@khanakia stability=stable
type Loader interface {
	Provider
	// Load fetches what the provider would otherwise fetch at its first
	// flow, and reports why it cannot be used.
	Load(ctx context.Context, hc *http.Client) error
}

// Load fetches the ID-token key set when the provider accepts ID tokens;
// a provider without one has nothing to load.
func (o *OAuth2) Load(ctx context.Context, hc *http.Client) error {
	if !o.IDToken.Enabled() {
		return nil
	}
	return o.idTokens().cache.load(ctx, hc, o.IDToken.JWKSURL)
}

// Load discovers the issuer (a Fallback in use counts) and fetches the key
// set it names.
func (o *OIDCProvider) Load(ctx context.Context, hc *http.Client) error {
	c, err := o.discover(ctx, hc)
	if err != nil {
		return err
	}
	return c.Load(ctx, hc)
}

// ErrAllProvidersBroken is auth.New under SkipBrokenProviders when every
// provider was left out: there is nothing left to keep working, so the
// failure is loud. It wraps each provider's reason.
var ErrAllProvidersBroken = errors.New("oauth: every provider is broken")

// skipBrokenProviders loads every Loader in parallel, records the ones that
// fail beside those Validate already refused, and logs each at Error. It
// fails only when no provider is left.
func (p *Plugin) skipBrokenProviders(ctx context.Context, log *slog.Logger) error {
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, prov := range p.providers {
		l, ok := prov.(Loader)
		if _, gone := p.skipped[prov.Name()]; gone || !ok {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := l.Load(ctx, p.hc); err != nil {
				mu.Lock()
				p.skipped[prov.Name()] = err
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	var reasons []error
	for _, prov := range p.providers {
		if err, gone := p.skipped[prov.Name()]; gone {
			log.Error("oauth: provider left out (SkipBrokenProviders)", "provider", prov.Name(), "error", err)
			reasons = append(reasons, fmt.Errorf("%s: %w", prov.Name(), err))
		}
	}
	if len(reasons) == len(p.providers) {
		return fmt.Errorf("%w: %w", ErrAllProvidersBroken, errors.Join(reasons...))
	}
	return nil
}
