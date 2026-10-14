package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth/plugin/oauthprovider"
)

// CIMD as better-auth caches and governs it: HTTP freshness spares fetches,
// a stale document is revalidated with If-None-Match (304 keeps it), a new
// document refreshes the client and runs the hook, and the governor refuses
// fetches over budget or too soon after a failure (temporarily_unavailable).
func TestOAuthProvider_CIMDCacheAndGovernor(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		const docURL = "https://tool.example.com/client.json"
		var mu sync.Mutex
		name, etag, cacheControl := "Tool", `"v1"`, "max-age=60"
		var fetches, conditional int
		var created, refreshed []string
		const noValidators = "https://other.example.com/nv.json"
		nvServed := false
		transport := func(_ context.Context, u string, cond http.Header) (oauthprovider.CIMDResponse, error) {
			mu.Lock()
			defer mu.Unlock()
			fetches++
			if u == noValidators {
				if nvServed {
					return oauthprovider.CIMDResponse{Status: http.StatusNotModified, Header: http.Header{}}, nil
				}
				nvServed = true
				body := must[[]byte](t)(json.Marshal(map[string]any{"client_id": noValidators, "client_name": "NV", "redirect_uris": []string{opRedirect}}))
				return oauthprovider.CIMDResponse{Status: 200, Body: body, Header: http.Header{"Content-Type": {"application/json"}, "Cache-Control": {"max-age=10"}}}, nil
			}
			if u != docURL {
				return oauthprovider.CIMDResponse{Status: 404, Header: http.Header{}}, nil
			}
			if cond.Get("If-None-Match") == etag {
				conditional++
				return oauthprovider.CIMDResponse{Status: http.StatusNotModified, Header: http.Header{"Etag": {etag}, "Cache-Control": {cacheControl}}}, nil
			}
			body := must[[]byte](t)(json.Marshal(map[string]any{"client_id": docURL, "client_name": name, "redirect_uris": []string{opRedirect}}))
			return oauthprovider.CIMDResponse{Status: 200, Body: body, Header: http.Header{"Content-Type": {"application/json"}, "Etag": {etag}, "Cache-Control": {cacheControl}}}, nil
		}
		o := newOPEnv(t, e, oauthprovider.ClientIDMetadataDocuments(oauthprovider.CIMDTransport(transport),
			oauthprovider.CIMDPolicy(oauthprovider.CIMDFetchPolicy{MaxPerOriginPerMinute: 3}),
			oauthprovider.CIMDOnClientCreated(func(_ context.Context, c oauthprovider.Client, _ json.RawMessage) { created = append(created, c.Name) }),
			oauthprovider.CIMDOnClientRefreshed(func(_ context.Context, c, prev oauthprovider.Client, _ json.RawMessage) {
				refreshed = append(refreshed, prev.Name+">"+c.Name)
			})))
		authorize := func(id string) error { _, err := o.op.Authorize(request(o.a, o.token), authzReq(id)); return err }
		if err := authorize(docURL); err != nil {
			t.Fatal(err)
		}
		e.clock.Advance(30 * time.Second)
		if err := authorize(docURL); err != nil || fetches != 1 {
			t.Fatalf("fresh document refetched: fetches=%d %v", fetches, err)
		}
		e.clock.Advance(40 * time.Second)
		if err := authorize(docURL); err != nil || fetches != 2 || conditional != 1 || len(refreshed) != 0 {
			t.Fatalf("revalidation: fetches=%d conditional=%d refreshed=%v %v", fetches, conditional, refreshed, err)
		}
		// A new document after expiry refreshes the client and runs the hook.
		mu.Lock()
		name, etag = "Tool 2", `"v2"`
		mu.Unlock()
		e.clock.Advance(61 * time.Second)
		if err := authorize(docURL); err != nil {
			t.Fatal(err)
		}
		if got := must[oauthprovider.Client](t)(o.op.Client(context.Background(), docURL)); got.Name != "Tool 2" || len(created) != 1 || len(refreshed) != 1 || refreshed[0] != "Tool>Tool 2" {
			t.Fatalf("refresh: client %q created %v refreshed %v", got.Name, created, refreshed)
		}
		// A 304 for a document stored without validators is refused.
		if err := authorize(noValidators); err != nil {
			t.Fatal(err)
		}
		e.clock.Advance(11 * time.Second)
		if err := authorize(noValidators); !errors.Is(err, oauthprovider.ErrBadRedirectTarget) {
			t.Fatalf("304 without validators: %v", err)
		}
		// A failed fetch is paced: an immediate retry is refused unfetched.
		missing := "https://tool.example.com/missing.json"
		if err := authorize(missing); !errors.Is(err, oauthprovider.ErrBadRedirectTarget) {
			t.Fatalf("missing document: %v", err)
		}
		before := fetches
		if err := authorize(missing); !errors.Is(err, oauthprovider.ErrCIMDBusy) || fetches != before {
			t.Fatalf("retry too soon: %v fetches %d->%d", err, before, fetches)
		}
		// The per-origin budget (3 per minute here) refuses the next fetch.
		e.clock.Advance(2 * time.Second)
		_ = authorize("https://tool.example.com/a.json")
		if err := authorize("https://tool.example.com/b.json"); !errors.Is(err, oauthprovider.ErrCIMDBusy) {
			t.Fatalf("over the per-origin budget: %v", err)
		}
	})
}
