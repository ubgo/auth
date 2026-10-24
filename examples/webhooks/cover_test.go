package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/webhook"
	"github.com/ubgo/auth/plugin/webhook/signature"
)

// queue is a WithBackground runner that holds every post-commit send until
// the test runs it, so a test can change the world between the commit and
// the send, and a fault sweep does not count the send's database calls.
type queue struct {
	mu    sync.Mutex
	tasks []func()
}

func (q *queue) run(ctx context.Context, task func(context.Context)) {
	q.mu.Lock()
	q.tasks = append(q.tasks, func() { task(ctx) })
	q.mu.Unlock()
}

// drain runs the held sends, oldest first.
func (q *queue) drain() {
	q.mu.Lock()
	tasks := q.tasks
	q.tasks = nil
	q.mu.Unlock()
	for _, task := range tasks {
		task()
	}
}

// held is an app whose post-commit sends wait in a queue.
type held struct {
	e     *authtest.Env
	hooks *webhook.Plugin
	sink  *sink
	ep    webhook.Endpoint
	q     *queue
}

// heldWorld builds a held app, with faults when f is not nil, an endpoint on
// a fresh sink subscribed to every event, and the queue drained before the
// app closes.
func heldWorld(t *testing.T, f *authtest.Faults, wopts []webhook.Option, extra ...auth.Option) *held {
	t.Helper()
	q := &queue{}
	hooks := webhook.New(append([]webhook.Option{webhook.AllowPrivateNetworks()}, wopts...)...)
	opts := []authtest.Option{
		authtest.WithOptions(append([]auth.Option{auth.WithSecret(testSecret), auth.WithBackground(q.run)}, extra...)...),
		authtest.WithPlugins(func(*authtest.Env) []auth.Plugin { return plugins(hooks) }),
	}
	if f != nil {
		opts = append(opts, authtest.WithFaults(f))
	}
	e := authtest.New(t, opts...)
	t.Cleanup(q.drain)
	s := newSink(t)
	s.now = e.Clock.Now
	ep, secret, err := hooks.CreateEndpoint(context.Background(), webhook.EndpointInput{URL: s.srv.URL + receiverPath})
	if err != nil {
		t.Fatal(err)
	}
	s.setSecret(secret)
	return &held{e: e, hooks: hooks, sink: s, ep: ep, q: q}
}

// publish writes one event and returns its delivery, still unsent.
func (h *held) publish(t *testing.T) webhook.Delivery {
	t.Helper()
	if err := h.hooks.Publish(context.Background(), "app.thing.done", map[string]string{"k": "v"}); err != nil {
		t.Fatal(err)
	}
	page, err := h.hooks.Deliveries(context.Background(), webhook.DeliveryQuery{EventType: "app.thing.done"})
	if err != nil || len(page.Deliveries) == 0 {
		t.Fatalf("deliveries = %+v, %v", page, err)
	}
	return page.Deliveries[0]
}

// sweep runs authtest.SweepFaults over op on a fresh held app per step,
// prepared by prep with faults off.
func sweep(t *testing.T, prep func(h *held), op func(ctx context.Context, h *held) error) {
	t.Helper()
	authtest.SweepFaults(t, func() (*held, *authtest.Faults) {
		f := authtest.NewFaults()
		return heldWorld(t, f, nil), f
	}, func(h *held) func(context.Context) error {
		if prep != nil {
			prep(h)
		}
		return func(ctx context.Context) error { return op(ctx, h) }
	})
}

// TestWebhooks_EveryDatabaseFailureSurfaces: each Go API call returns the
// error of every database call it makes, never a success for work that did
// not happen.
func TestWebhooks_EveryDatabaseFailureSurfaces(t *testing.T) {
	pending := func(h *held) { h.publish(t) }
	for name, c := range map[string]struct {
		prep func(*held)
		op   func(context.Context, *held) error
	}{
		"CreateEndpoint": {nil, func(ctx context.Context, h *held) error {
			_, _, err := h.hooks.CreateEndpoint(ctx, webhook.EndpointInput{URL: h.sink.srv.URL + "/two"})
			return err
		}},
		"UpdateEndpoint": {nil, func(ctx context.Context, h *held) error {
			u, d, off := h.sink.srv.URL+"/moved", "moved", false
			_, err := h.hooks.UpdateEndpoint(ctx, h.ep.ID, webhook.EndpointUpdate{URL: &u, Events: &[]string{"user.*"}, Description: &d, Enabled: &off})
			return err
		}},
		"DeleteEndpoint": {pending, func(ctx context.Context, h *held) error { return h.hooks.DeleteEndpoint(ctx, h.ep.ID) }},
		"RotateSecret": {nil, func(ctx context.Context, h *held) error {
			_, err := h.hooks.RotateSecret(ctx, h.ep.ID, time.Hour)
			return err
		}},
		"EndpointSecret": {nil, func(ctx context.Context, h *held) error {
			_, err := h.hooks.EndpointSecret(ctx, h.ep.ID)
			return err
		}},
		"Endpoints": {nil, func(ctx context.Context, h *held) error {
			_, err := h.hooks.Endpoints(ctx)
			return err
		}},
		"Deliveries": {pending, func(ctx context.Context, h *held) error {
			_, err := h.hooks.Deliveries(ctx, webhook.DeliveryQuery{EndpointID: h.ep.ID, Status: webhook.StatusPending})
			return err
		}},
		"Publish": {nil, func(ctx context.Context, h *held) error {
			return h.hooks.Publish(ctx, "app.thing.done", map[string]int{"n": 1})
		}},
		"Maintain": {pending, func(ctx context.Context, h *held) error {
			_, err := h.e.Auth.Maintain(ctx, auth.MaintainOptions{})
			return err
		}},
		// A failing receiver: the retry is recorded, or the endpoint
		// disabled on 410, and either write can fail.
		"Maintain, receiver 500": {func(h *held) { h.sink.setStatus(http.StatusInternalServerError); h.publish(t) }, func(ctx context.Context, h *held) error {
			_, err := h.e.Auth.Maintain(ctx, auth.MaintainOptions{})
			return err
		}},
		"Maintain, receiver 410": {func(h *held) { h.sink.setStatus(http.StatusGone); h.publish(t) }, func(ctx context.Context, h *held) error {
			_, err := h.e.Auth.Maintain(ctx, auth.MaintainOptions{})
			return err
		}},
		"Sweep": {nil, func(ctx context.Context, h *held) error {
			_, err := h.hooks.Sweep(ctx, time.Time{})
			return err
		}},
		"SecuritySink": {nil, func(ctx context.Context, h *held) error {
			return h.hooks.SecuritySink().WriteSecurity(ctx, []auth.SecurityEvent{{ID: "sev_1", At: h.e.Clock.Now(), Kind: auth.SecurityLockout}})
		}},
	} {
		t.Run(name, func(t *testing.T) { sweep(t, c.prep, c.op) })
	}
	// Replay needs the id of a delivery made before the fault is armed.
	t.Run("Replay", func(t *testing.T) {
		authtest.SweepFaults(t, func() (*held, *authtest.Faults) {
			f := authtest.NewFaults()
			return heldWorld(t, f, nil), f
		}, func(h *held) func(context.Context) error {
			id := h.publish(t).ID
			return func(ctx context.Context) error {
				_, err := h.hooks.Replay(ctx, id)
				return err
			}
		})
	})
}

// TestWebhooks_FailedBackgroundSendIsLogged: a post-commit send whose
// database read fails is logged and leaves the delivery pending for Maintain.
func TestWebhooks_FailedBackgroundSendIsLogged(t *testing.T) {
	f := authtest.NewFaults()
	h := heldWorld(t, f, nil)
	d := h.publish(t)
	f.Arm(1)
	h.q.drain()
	if !f.Disarm() {
		t.Fatal("the held send made no database call")
	}
	if got, err := h.hooks.Delivery(context.Background(), d.ID); err != nil || got.Status != webhook.StatusPending || got.Attempts != 0 {
		t.Fatalf("after a failed background send: %+v, %v", got, err)
	}
	if res, err := h.e.Auth.Maintain(context.Background(), auth.MaintainOptions{}); err != nil || res["webhook.delivered"] != 1 {
		t.Fatalf("maintain = %v, %v", res, err)
	}
}

// TestWebhooks_LateSendsAreSkippedOrCancelled: a held send that finds its
// delivery already sent, swept away, or its endpoint disabled does nothing
// to the receiver; the disabled case cancels the delivery.
func TestWebhooks_LateSendsAreSkippedOrCancelled(t *testing.T) {
	ctx := context.Background()
	h := heldWorld(t, nil, nil)
	d := h.publish(t)
	if res, err := h.e.Auth.Maintain(ctx, auth.MaintainOptions{}); err != nil || res["webhook.delivered"] != 1 {
		t.Fatalf("maintain = %v, %v", res, err)
	}
	h.q.drain() // finds it delivered: skipped
	if accepted, _ := h.sink.count(); accepted != 1 {
		t.Fatalf("receiver got %d, want 1", accepted)
	}
	// Swept away before its held send runs.
	h.publish(t)
	if _, err := h.e.Auth.Maintain(ctx, auth.MaintainOptions{}); err != nil {
		t.Fatal(err)
	}
	h.e.Clock.Advance(webhook.DefaultRetention + time.Hour)
	if n, err := h.hooks.Sweep(ctx, time.Time{}); err != nil || n != 2 {
		t.Fatalf("sweep = %d, %v", n, err)
	}
	h.q.drain()
	if accepted, _ := h.sink.count(); accepted != 2 {
		t.Fatalf("receiver got %d, want 2", accepted)
	}
	// Endpoint disabled before the send.
	d = h.publish(t)
	off := false
	if _, err := h.hooks.UpdateEndpoint(ctx, h.ep.ID, webhook.EndpointUpdate{Enabled: &off}); err != nil {
		t.Fatal(err)
	}
	h.q.drain()
	if got, _ := h.hooks.Delivery(ctx, d.ID); got.Status != webhook.StatusCancelled || got.FinishedAt == nil {
		t.Fatalf("delivery to a disabled endpoint: %+v", got)
	}
	if ep, _ := h.hooks.Endpoint(ctx, h.ep.ID); ep.Enabled || ep.DisabledReason != webhook.DisabledManual {
		t.Fatalf("endpoint = %+v", ep)
	}
	on := true
	if ep, err := h.hooks.UpdateEndpoint(ctx, h.ep.ID, webhook.EndpointUpdate{Enabled: &on}); err != nil || !ep.Enabled || ep.DisabledReason != "" {
		t.Fatalf("re-enable = %+v, %v", ep, err)
	}
	// Deleting the endpoint cancels what is still pending.
	d = h.publish(t)
	if err := h.hooks.DeleteEndpoint(ctx, h.ep.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := h.hooks.Delivery(ctx, d.ID); got.Status != webhook.StatusCancelled {
		t.Fatalf("pending delivery after delete: %+v", got)
	}
	if _, err := h.hooks.Replay(ctx, d.ID); !errors.Is(err, webhook.ErrEndpointNotFound) {
		t.Fatalf("replay to a deleted endpoint = %v", err)
	}
	h.q.drain()
}

// TestWebhooks_Refusals: every refusal of the Go API answers its typed error.
func TestWebhooks_Refusals(t *testing.T) {
	ctx := context.Background()
	h := heldWorld(t, nil, nil)
	long := strings.Repeat("d", webhook.MaxDescriptionLength+1)
	u := h.sink.srv.URL + "/x"
	for name, c := range map[string]struct {
		in   webhook.EndpointInput
		want error
	}{
		"bad filter":       {webhook.EndpointInput{URL: u, Events: []string{"User.Created"}}, webhook.ErrBadEventType},
		"long description": {webhook.EndpointInput{URL: u, Description: long}, webhook.ErrBadDescription},
		"bad secret":       {webhook.EndpointInput{URL: u, Secret: "whsec_short"}, webhook.ErrBadSecret},
		"bad URL":          {webhook.EndpointInput{URL: "ftp://x"}, webhook.ErrBadURL},
	} {
		if _, _, err := h.hooks.CreateEndpoint(ctx, c.in); !errors.Is(err, c.want) {
			t.Errorf("create %s = %v, want %v", name, err, c.want)
		}
	}
	// A secret brought from another sender is kept as given.
	own := signature.NewSecret()
	ep, got, err := h.hooks.CreateEndpoint(ctx, webhook.EndpointInput{URL: u, Secret: own})
	if err != nil || got != own {
		t.Fatalf("own secret = %q, %v", got, err)
	}
	if back, _ := h.hooks.EndpointSecret(ctx, ep.ID); back != own {
		t.Fatalf("stored secret differs")
	}
	bad, badFilter := "ftp://x", []string{"**"}
	for name, c := range map[string]struct {
		id   string
		in   webhook.EndpointUpdate
		want error
	}{
		"missing":          {"whe_none", webhook.EndpointUpdate{}, webhook.ErrEndpointNotFound},
		"bad URL":          {ep.ID, webhook.EndpointUpdate{URL: &bad}, webhook.ErrBadURL},
		"bad filter":       {ep.ID, webhook.EndpointUpdate{Events: &badFilter}, webhook.ErrBadEventType},
		"long description": {ep.ID, webhook.EndpointUpdate{Description: &long}, webhook.ErrBadDescription},
	} {
		if _, err := h.hooks.UpdateEndpoint(ctx, c.id, c.in); !errors.Is(err, c.want) {
			t.Errorf("update %s = %v, want %v", name, err, c.want)
		}
	}
	missing := []error{}
	_, err = h.hooks.EndpointSecret(ctx, "whe_none")
	missing = append(missing, err)
	_, err = h.hooks.RotateSecret(ctx, "whe_none", 0)
	missing = append(missing, err)
	missing = append(missing, h.hooks.DeleteEndpoint(ctx, "whe_none"))
	_, err = h.hooks.Endpoint(ctx, "whe_none")
	missing = append(missing, err)
	for i, err := range missing {
		if !errors.Is(err, webhook.ErrEndpointNotFound) {
			t.Errorf("missing endpoint %d = %v", i, err)
		}
	}
	if _, err := h.hooks.Delivery(ctx, "whd_none"); !errors.Is(err, webhook.ErrDeliveryNotFound) {
		t.Errorf("missing delivery = %v", err)
	}
	if _, err := h.hooks.Replay(ctx, "whd_none"); !errors.Is(err, webhook.ErrDeliveryNotFound) {
		t.Errorf("replay of a missing delivery = %v", err)
	}
	if err := h.hooks.Publish(ctx, "app.bad.data", make(chan int)); err == nil || !strings.Contains(err.Error(), "encode") {
		t.Errorf("unencodable data = %v", err)
	}
	// The default grace applies when none is given.
	if _, err := h.hooks.RotateSecret(ctx, ep.ID, 0); err != nil {
		t.Fatal(err)
	}
	// The registry is bounded.
	eps, err := h.hooks.Endpoints(ctx)
	if err != nil || len(eps) != 2 || len(eps[0].Events) != 0 {
		t.Fatalf("endpoints = %+v, %v", eps, err)
	}
	for range webhook.MaxEndpoints - len(eps) {
		if _, _, err := h.hooks.CreateEndpoint(ctx, webhook.EndpointInput{URL: u}); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := h.hooks.CreateEndpoint(ctx, webhook.EndpointInput{URL: u}); !errors.Is(err, webhook.ErrTooManyEndpoints) {
		t.Fatalf("over the bound = %v", err)
	}
}

// failSealer is a working sealer that fails, on request, to seal or open the
// values whose additional data starts with a given prefix.
type failSealer struct {
	inner              auth.Sealer
	mu                 sync.Mutex
	failSeal, failOpen string
}

var errSealer = errors.New("key service down")

func (s *failSealer) set(seal, open string) {
	s.mu.Lock()
	s.failSeal, s.failOpen = seal, open
	s.mu.Unlock()
}

func (s *failSealer) Seal(ctx context.Context, plain []byte, aad string) (string, error) {
	s.mu.Lock()
	fail := s.failSeal != "" && strings.HasPrefix(aad, s.failSeal)
	s.mu.Unlock()
	if fail {
		return "", errSealer
	}
	return s.inner.Seal(ctx, plain, aad)
}

func (s *failSealer) Open(ctx context.Context, sealed, aad string) ([]byte, error) {
	s.mu.Lock()
	fail := s.failOpen != "" && strings.HasPrefix(aad, s.failOpen)
	s.mu.Unlock()
	if fail {
		return nil, errSealer
	}
	return s.inner.Open(ctx, sealed, aad)
}

// AAD prefixes of the two secret slots, as the plugin binds them.
const (
	curSlot  = "webhook.endpoint.secret:"
	prevSlot = "webhook.endpoint.previous:"
)

// TestWebhooks_SealerFailures: a key service that cannot seal or open fails
// the registry call that needs it, and a send that cannot open a signing
// secret is retried like a receiver that is down, never sent unsigned.
func TestWebhooks_SealerFailures(t *testing.T) {
	ctx := context.Background()
	ring, err := auth.NewKeyRing([]byte(strings.Repeat("k", auth.SealKeySize)))
	if err != nil {
		t.Fatal(err)
	}
	fs := &failSealer{inner: auth.RingSealer(ring)}
	h := heldWorld(t, nil, []webhook.Option{webhook.WithSealer(fs)})
	u := h.sink.srv.URL + "/x"

	fs.set(curSlot, "")
	if _, _, err := h.hooks.CreateEndpoint(ctx, webhook.EndpointInput{URL: u}); !errors.Is(err, errSealer) {
		t.Errorf("create with sealing down = %v", err)
	}
	if _, err := h.hooks.RotateSecret(ctx, h.ep.ID, time.Hour); !errors.Is(err, errSealer) {
		t.Errorf("rotate, new secret not sealed = %v", err)
	}
	fs.set(prevSlot, "")
	if _, err := h.hooks.RotateSecret(ctx, h.ep.ID, time.Hour); !errors.Is(err, errSealer) {
		t.Errorf("rotate, old secret not sealed = %v", err)
	}
	fs.set("", curSlot)
	if _, err := h.hooks.EndpointSecret(ctx, h.ep.ID); !errors.Is(err, errSealer) {
		t.Errorf("secret with opening down = %v", err)
	}
	if _, err := h.hooks.RotateSecret(ctx, h.ep.ID, time.Hour); !errors.Is(err, errSealer) {
		t.Errorf("rotate, old secret not opened = %v", err)
	}
	// A send that cannot open the current secret, then one that cannot open
	// the previous one during a rotation: both retried, nothing sent.
	d := h.publish(t)
	h.q.drain()
	if got, _ := h.hooks.Delivery(ctx, d.ID); got.Status != webhook.StatusPending || got.LastError != "signing secret unavailable" {
		t.Fatalf("send without a secret: %+v", got)
	}
	fs.set("", "")
	if _, err := h.hooks.RotateSecret(ctx, h.ep.ID, time.Hour); err != nil {
		t.Fatal(err)
	}
	fs.set("", prevSlot)
	h.e.Clock.Advance(webhook.DefaultRetryBase * 2)
	if res, err := h.e.Auth.Maintain(ctx, auth.MaintainOptions{}); err != nil || res["webhook.retrying"] != 1 {
		t.Fatalf("maintain without the previous secret = %v, %v", res, err)
	}
	if accepted, refused := h.sink.count(); accepted+refused != 0 {
		t.Fatalf("receiver got %d requests", accepted+refused)
	}
}

// TestWebhooks_AppSealerIsUsed: without webhook.WithSealer, auth.WithSealer
// seals the endpoint secrets.
func TestWebhooks_AppSealerIsUsed(t *testing.T) {
	ring, err := auth.NewKeyRing([]byte(strings.Repeat("a", auth.SealKeySize)))
	if err != nil {
		t.Fatal(err)
	}
	fs := &failSealer{inner: auth.RingSealer(ring)}
	h := heldWorld(t, nil, nil, auth.WithSealer(fs))
	fs.set("", curSlot)
	if _, err := h.hooks.EndpointSecret(context.Background(), h.ep.ID); !errors.Is(err, errSealer) {
		t.Fatalf("auth.WithSealer was not used: %v", err)
	}
}

// TestWebhooks_InitRefusals: the plugin needs a database and a way to seal
// secrets; its migrations refuse an unknown engine and have a MySQL form.
func TestWebhooks_InitRefusals(t *testing.T) {
	noDB, err := auth.New(auth.WithBaseURL(authtest.BaseURL), auth.WithPlugins(plugins(webhook.New())[:2]...))
	if err != nil {
		t.Fatal(err)
	}
	if err := webhook.New().Init(noDB); !errors.Is(err, auth.ErrNoDatabase) {
		t.Errorf("Init without a database = %v", err)
	}
	e := authtest.New(t, authtest.WithPlugins(func(*authtest.Env) []auth.Plugin { return plugins(webhook.New())[:2] }))
	if err := webhook.New().Init(e.Auth); !errors.Is(err, webhook.ErrNoEncryptionKey) {
		t.Errorf("Init without a secret = %v", err)
	}
	h := heldWorld(t, nil, nil)
	if _, err := h.hooks.TypedMigrations("oracle", auth.SQLTypes{}); err == nil {
		t.Error("an unknown engine was accepted")
	}
	ms, err := h.hooks.TypedMigrations(auth.EngineMySQL, auth.TypesFor(auth.EngineMySQL))
	if err != nil || len(ms) != 1 || len(ms[0].Statements) != 2 || !strings.Contains(ms[0].Statements[1], "INDEX") {
		t.Fatalf("mysql migrations = %+v, %v", ms, err)
	}
	if webhook.New().SecuritySink().WriteSecurity(context.Background(), []auth.SecurityEvent{{Kind: auth.SecurityLockout}}) != nil {
		t.Error("a sink of a plugin never wired should do nothing")
	}
}

// pendingAll asks every sign-in for a second factor, so sessions are created
// pending.
type pendingAll struct{}

func (pendingAll) Name() string { return "pendingall" }
func (pendingAll) SecondFactorRequired(context.Context, string) (bool, error) {
	return true, nil
}

// TestWebhooks_LifecycleEvents: profile changes, identity verification and
// removal, user deletion, an impersonation, a sign-out and security events
// each become their webhook; a session still waiting for a second factor
// does not.
func TestWebhooks_LifecycleEvents(t *testing.T) {
	ctx := context.Background()
	e, hooks, s, _ := world(t, nil, nil)
	b := e.Browser(newHandler(e.Auth, http.NotFoundHandler()))
	b.Post("/auth/password/sign-up", map[string]string{"identifier": adaMail, "password": adaPass, "name": "Ada"}).Expect(http.StatusOK)
	b.Get("/auth/session").Expect(http.StatusOK) // a signed-in call that ends no session
	b.Post("/auth/sign-out", map[string]string{}).Expect(http.StatusOK)
	e.Auth.WaitDeliveries()
	ids, err := e.Auth.Identities(ctx, firstUser(t, s))
	if err != nil || len(ids) != 1 {
		t.Fatalf("identities = %v, %v", ids, err)
	}
	userID := ids[0].UserID
	name := "Ada L."
	if _, err := e.Auth.UpdateUser(ctx, userID, auth.UserUpdate{Name: &name}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Auth.VerifyIdentity(ctx, ids[0].ID); err != nil {
		t.Fatal(err)
	}
	extra, err := e.Auth.CreateIdentity(ctx, auth.NewIdentity{UserID: userID, Kind: email.KindEmail, Raw: "ada2@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Auth.DeleteIdentity(ctx, userID, extra.ID); err != nil {
		t.Fatal(err)
	}
	admin := e.CreateUser("Admin")
	if _, _, err := e.Auth.CreateImpersonationSession(ctx, userID, admin.ID, auth.Client{}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := hooks.SecuritySink().WriteSecurity(ctx, []auth.SecurityEvent{
		{ID: "sev_1", At: e.Clock.Now(), Kind: auth.SecurityLockout, UserID: userID},
		{ID: "sev_2", At: e.Clock.Now(), Kind: "Not A Type"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.Auth.DeleteUser(ctx, userID); err != nil {
		t.Fatal(err)
	}
	e.Auth.WaitDeliveries()
	types := s.types()
	for _, want := range []string{webhook.EventSessionRevoked, webhook.EventUserUpdated, webhook.EventIdentityUpdated, webhook.EventIdentityDeleted, webhook.EventUserDeleted, webhook.SecurityEventPrefix + string(auth.SecurityLockout)} {
		if !contains(types, want) {
			t.Errorf("got %v, want %s among them", types, want)
		}
	}
	s.mu.Lock()
	impersonated := false
	for _, g := range s.accepted {
		if g.Type == webhook.EventSessionCreated && strings.Contains(string(g.Body), `"impersonatedBy":"`+admin.ID+`"`) {
			impersonated = true
		}
	}
	s.mu.Unlock()
	if !impersonated {
		t.Error("the impersonation session was not reported with its admin")
	}

	// With every sign-in pending a second factor, the pending session is
	// not reported.
	hooks2 := webhook.New(webhook.AllowPrivateNetworks())
	e2 := authtest.New(t, authtest.WithOptions(auth.WithSecret(testSecret)),
		authtest.WithPlugins(func(*authtest.Env) []auth.Plugin { return append(plugins(hooks2), pendingAll{}) }))
	s2 := newSink(t)
	s2.now = e2.Clock.Now
	_, secret, err := hooks2.CreateEndpoint(ctx, webhook.EndpointInput{URL: s2.srv.URL + receiverPath, Events: []string{"session.*"}})
	if err != nil {
		t.Fatal(err)
	}
	s2.setSecret(secret)
	u := e2.CreateUser("Pat")
	if _, _, err := e2.Auth.CreateSession(ctx, u.ID, auth.Client{}); err != nil {
		t.Fatal(err)
	}
	e2.Auth.WaitDeliveries()
	if types := s2.types(); len(types) != 0 {
		t.Fatalf("a pending session was reported: %v", types)
	}
}

// firstUser is the user id in the first user.created the sink accepted.
func firstUser(t *testing.T, s *sink) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, g := range s.accepted {
		if g.Type == webhook.EventUserCreated {
			i := strings.Index(string(g.Body), `"id":"`)
			rest := string(g.Body)[i+len(`"id":"`):]
			return rest[:strings.Index(rest, `"`)]
		}
	}
	t.Fatal("no user.created")
	return ""
}

// TestWebhooks_DeliveryFilters: Deliveries narrows by message id and type.
func TestWebhooks_DeliveryFilters(t *testing.T) {
	e, hooks, _, _ := world(t, nil, nil)
	signUp(t, e, hooks)
	ctx := context.Background()
	all, err := hooks.Deliveries(ctx, webhook.DeliveryQuery{})
	if err != nil || len(all.Deliveries) < 2 {
		t.Fatalf("deliveries = %+v, %v", all, err)
	}
	d := all.Deliveries[0]
	byMsg, err := hooks.Deliveries(ctx, webhook.DeliveryQuery{MessageID: d.MessageID})
	if err != nil || byMsg.Total != 1 || byMsg.Deliveries[0].ID != d.ID {
		t.Fatalf("by message = %+v, %v", byMsg, err)
	}
	byType, err := hooks.Deliveries(ctx, webhook.DeliveryQuery{EventType: d.EventType, Page: 2, Limit: 1})
	if err != nil || byType.Total != 1 || len(byType.Deliveries) != 0 || byType.Page != 2 || byType.Limit != 1 {
		t.Fatalf("by type, page 2 = %+v, %v", byType, err)
	}
}

// TestWebhooks_IDGeneratorFailure: an app id generator that fails refuses
// the registration and the event write that needed an id.
func TestWebhooks_IDGeneratorFailure(t *testing.T) {
	var mu sync.Mutex
	failing := ""
	errIDs := errors.New("id service down")
	ids := func(prefix string) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		if prefix == failing {
			return "", errIDs
		}
		return prefix + "_" + strings.ReplaceAll(signature.NewSecret()[len(signature.SecretPrefix):len(signature.SecretPrefix)+16], "/", "x"), nil
	}
	h := heldWorld(t, nil, nil, auth.WithIDs(ids))
	set := func(p string) { mu.Lock(); failing = p; mu.Unlock() }
	set(webhook.IDPrefixEndpoint)
	if _, _, err := h.hooks.CreateEndpoint(context.Background(), webhook.EndpointInput{URL: h.sink.srv.URL + "/x"}); !errors.Is(err, errIDs) {
		t.Errorf("create = %v", err)
	}
	set(webhook.IDPrefixDelivery)
	if err := h.hooks.Publish(context.Background(), "app.thing.done", nil); !errors.Is(err, errIDs) {
		t.Errorf("publish = %v", err)
	}
	set("")
}
