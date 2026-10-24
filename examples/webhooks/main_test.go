package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/webhook"
	"github.com/ubgo/auth/plugin/webhook/signature"
	"github.com/ubgo/sqlb"
)

const (
	adaMail = "ada@example.com"
	adaPass = "correct horse battery staple"
)

// testSecret is the deployment secret, exactly auth.MinSecretSize bytes.
var testSecret = []byte(strings.Repeat("s", auth.MinSecretSize))

// got is one request the receiver accepted, verified.
type got struct {
	ID   string
	Type string
	Body []byte
}

// sink is a receiver on a real local HTTP server. It verifies every request
// with the endpoint's secret and answers status (200 unless changed).
type sink struct {
	srv *httptest.Server

	mu     sync.Mutex
	secret string
	status int
	// now is the receiver's clock: the app's test clock, which stamps
	// webhook-timestamp, so a test that moves it hours ahead still verifies.
	now      func() time.Time
	accepted []got
	refused  int
}

func newSink(t *testing.T) *sink {
	s := &sink{status: http.StatusOK, now: time.Now}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		defer s.mu.Unlock()
		if err := signature.VerifyAt(s.secret, r.Header, body, s.now(), signature.DefaultTolerance); err != nil {
			s.refused++
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		var ev webhook.Envelope
		if err := json.Unmarshal(body, &ev); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if s.status == http.StatusOK {
			s.accepted = append(s.accepted, got{ID: r.Header.Get(signature.HeaderID), Type: ev.Type, Body: body})
		}
		w.WriteHeader(s.status)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *sink) setSecret(v string) { s.mu.Lock(); s.secret = v; s.mu.Unlock() }
func (s *sink) setStatus(v int)    { s.mu.Lock(); s.status = v; s.mu.Unlock() }

// types lists the accepted event types in arrival order.
func (s *sink) types() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, g := range s.accepted {
		out = append(out, g.Type)
	}
	return out
}

func (s *sink) count() (accepted, refused int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.accepted), s.refused
}

// world is the app with the webhook plugin and an endpoint on a fresh sink.
func world(t *testing.T, opts []webhook.Option, filters []string, extra ...auth.Option) (*authtest.Env, *webhook.Plugin, *sink, webhook.Endpoint) {
	t.Helper()
	hooks := webhook.New(append([]webhook.Option{webhook.AllowPrivateNetworks()}, opts...)...)
	e := authtest.New(t,
		authtest.WithOptions(append([]auth.Option{auth.WithSecret(testSecret)}, extra...)...),
		authtest.WithPlugins(func(*authtest.Env) []auth.Plugin { return plugins(hooks) }))
	s := newSink(t)
	s.now = e.Clock.Now
	ep, secret, err := hooks.CreateEndpoint(context.Background(), webhook.EndpointInput{URL: s.srv.URL + receiverPath, Events: filters})
	if err != nil {
		t.Fatal(err)
	}
	s.setSecret(secret)
	return e, hooks, s, ep
}

// signUp signs ada up through the real handler.
func signUp(t *testing.T, e *authtest.Env, hooks *webhook.Plugin) {
	t.Helper()
	b := e.Browser(newHandler(e.Auth, http.NotFoundHandler()))
	b.Post("/auth/password/sign-up", map[string]string{"identifier": adaMail, "password": adaPass, "name": "Ada"}).Expect(http.StatusOK)
	e.Auth.WaitDeliveries()
}

// TestWebhooks_SignUpDeliversSignedEvents: a real sign-up over
// authhttp.Handler reaches a real HTTP receiver as signed Standard Webhooks
// requests the receiver verifies, one per event, and every delivery row is
// delivered after the first send.
func TestWebhooks_SignUpDeliversSignedEvents(t *testing.T) {
	e, hooks, s, ep := world(t, nil, nil)
	signUp(t, e, hooks)
	types := s.types()
	for _, want := range []string{webhook.EventUserCreated, webhook.EventIdentityCreated, webhook.EventSessionCreated} {
		if !contains(types, want) {
			t.Errorf("receiver got %v, want %s among them", types, want)
		}
	}
	if _, refused := s.count(); refused != 0 {
		t.Fatalf("receiver refused %d requests", refused)
	}
	s.mu.Lock()
	var user struct {
		Data webhook.UserData `json:"data"`
	}
	for _, g := range s.accepted {
		if g.Type == webhook.EventUserCreated {
			if err := json.Unmarshal(g.Body, &user); err != nil {
				t.Fatal(err)
			}
		}
		if !strings.HasPrefix(g.ID, "msg_") {
			t.Errorf("webhook-id %q", g.ID)
		}
	}
	s.mu.Unlock()
	if user.Data.Name != "Ada" || user.Data.ID == "" {
		t.Fatalf("user.created data = %+v", user.Data)
	}
	page, err := hooks.Deliveries(context.Background(), webhook.DeliveryQuery{EndpointID: ep.ID})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total < 3 {
		t.Fatalf("deliveries = %d, want at least 3", page.Total)
	}
	for _, d := range page.Deliveries {
		if d.Status != webhook.StatusDelivered || d.Attempts != 1 || d.LastStatus != http.StatusOK || d.FinishedAt == nil {
			t.Errorf("delivery %+v, want delivered on the first attempt", d)
		}
	}
}

// TestWebhooks_FilterNarrowsEvents: an endpoint subscribed to session.* gets
// the session event and nothing about the user.
func TestWebhooks_FilterNarrowsEvents(t *testing.T) {
	e, hooks, s, _ := world(t, nil, []string{"session.*"})
	signUp(t, e, hooks)
	if types := s.types(); len(types) != 1 || types[0] != webhook.EventSessionCreated {
		t.Fatalf("receiver got %v, want only session.created", types)
	}
}

// TestWebhooks_FailingReceiverIsRetriedThenDeadLettered: a receiver that
// answers 500 is retried by Maintain on the backoff schedule, never before it
// is due, and dead-lettered after MaxAttempts; Replay of the dead letter sends
// it again, with the same webhook-id, once the receiver is fixed.
func TestWebhooks_FailingReceiverIsRetriedThenDeadLettered(t *testing.T) {
	const attempts = 3
	e, hooks, s, ep := world(t, []webhook.Option{webhook.Retry(webhook.RetryPolicy{MaxAttempts: attempts})}, []string{webhook.EventUserCreated})
	s.setStatus(http.StatusInternalServerError)
	signUp(t, e, hooks)
	ctx := context.Background()
	d := onlyDelivery(t, hooks, ep.ID)
	if d.Status != webhook.StatusPending || d.Attempts != 1 || d.LastStatus != http.StatusInternalServerError || !strings.Contains(d.LastError, "500") {
		t.Fatalf("after the first send: %+v", d)
	}

	// Not due yet: Maintain sends nothing.
	if res, err := e.Auth.Maintain(ctx, auth.MaintainOptions{}); err != nil || res["webhook.retrying"] != 0 {
		t.Fatalf("maintain before due = %v, %v", res, err)
	}
	// A dry run counts the due row without sending it.
	e.Clock.Advance(webhook.DefaultRetryBase + webhook.DefaultRetryBase/5)
	if res, err := e.Auth.Maintain(ctx, auth.MaintainOptions{DryRun: true}); err != nil || res["webhook.due"] != 1 {
		t.Fatalf("dry run = %v, %v", res, err)
	}
	if res, err := e.Auth.Maintain(ctx, auth.MaintainOptions{}); err != nil || res["webhook.retrying"] != 1 {
		t.Fatalf("second attempt = %v, %v", res, err)
	}
	e.Clock.Advance(2*webhook.DefaultRetryBase + webhook.DefaultRetryBase/2)
	if res, err := e.Auth.Maintain(ctx, auth.MaintainOptions{}); err != nil || res["webhook.dead"] != 1 {
		t.Fatalf("last attempt = %v, %v", res, err)
	}
	d = onlyDelivery(t, hooks, ep.ID)
	if d.Status != webhook.StatusDead || d.Attempts != attempts || d.FinishedAt == nil {
		t.Fatalf("dead letter: %+v", d)
	}
	e.Clock.Advance(webhook.DefaultRetryMax)
	if res, _ := e.Auth.Maintain(ctx, auth.MaintainOptions{}); len(res) != 0 {
		t.Fatalf("a dead letter was picked up again: %v", res)
	}

	s.setStatus(http.StatusOK)
	r, err := hooks.Replay(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	e.Auth.WaitDeliveries()
	r, err = hooks.Delivery(ctx, r.ID)
	if err != nil || r.Status != webhook.StatusDelivered || r.MessageID != d.MessageID || r.ID == d.ID {
		t.Fatalf("replay = %+v, %v", r, err)
	}
	if old, _ := hooks.Delivery(ctx, d.ID); old.Status != webhook.StatusDead {
		t.Fatalf("replay changed the original: %+v", old)
	}
	if dead, _ := hooks.Deliveries(ctx, webhook.DeliveryQuery{Status: webhook.StatusDead}); dead.Total != 1 {
		t.Fatalf("dead letters = %d", dead.Total)
	}
}

// TestWebhooks_GoneDisablesTheEndpoint: 410 dead-letters at once and turns
// the endpoint off, as the spec says.
func TestWebhooks_GoneDisablesTheEndpoint(t *testing.T) {
	e, hooks, s, ep := world(t, nil, []string{webhook.EventUserCreated})
	s.setStatus(http.StatusGone)
	signUp(t, e, hooks)
	if d := onlyDelivery(t, hooks, ep.ID); d.Status != webhook.StatusDead || d.Attempts != 1 {
		t.Fatalf("delivery after 410: %+v", d)
	}
	got, err := hooks.Endpoint(context.Background(), ep.ID)
	if err != nil || got.Enabled || got.DisabledReason != webhook.DisabledGone {
		t.Fatalf("endpoint after 410 = %+v, %v", got, err)
	}
	if _, err := hooks.Replay(context.Background(), onlyDelivery(t, hooks, ep.ID).ID); !errors.Is(err, webhook.ErrEndpointDisabled) {
		t.Fatalf("replay to a disabled endpoint = %v", err)
	}
}

// TestWebhooks_RolledBackTransactionSendsNothing: an event written inside a
// transaction that rolls back leaves no delivery row and no request, whether
// it came from a data hook (a user created then refused) or from Publish.
func TestWebhooks_RolledBackTransactionSendsNothing(t *testing.T) {
	e, hooks, s, _ := world(t, nil, nil)
	ctx := context.Background()
	refuse := errors.New("refused by the app")
	err := e.Auth.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		if _, err := e.Auth.CreateUser(ctx, auth.NewUser{Name: "Ghost"}); err != nil {
			return err
		}
		if err := hooks.Publish(ctx, "app.invoice.paid", map[string]int{"cents": 100}); err != nil {
			return err
		}
		return refuse
	})
	if !errors.Is(err, refuse) {
		t.Fatalf("tx = %v", err)
	}
	e.Auth.WaitDeliveries()
	if page, _ := hooks.Deliveries(ctx, webhook.DeliveryQuery{}); page.Total != 0 {
		t.Fatalf("rows after rollback = %d", page.Total)
	}
	if accepted, refused := s.count(); accepted+refused != 0 {
		t.Fatalf("receiver got %d requests after a rollback", accepted+refused)
	}
	// The same Publish in a committed transaction is delivered.
	if err := hooks.Publish(ctx, "app.invoice.paid", map[string]int{"cents": 100}); err != nil {
		t.Fatal(err)
	}
	e.Auth.WaitDeliveries()
	if types := s.types(); len(types) != 1 || types[0] != "app.invoice.paid" {
		t.Fatalf("receiver got %v", types)
	}
	if err := hooks.Publish(ctx, "Bad Type", nil); !errors.Is(err, webhook.ErrBadEventType) {
		t.Fatalf("bad type = %v", err)
	}
}

// TestWebhooks_SecretNeverLeaks: the endpoint secret is sealed at rest and
// appears in no log line, no stored error, no Endpoint value and no delivery
// row, through a successful send, a failed one and a refused registration.
func TestWebhooks_SecretNeverLeaks(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	e, hooks, s, ep := world(t, nil, nil, auth.WithLogger(logger))
	ctx := context.Background()
	secret, err := hooks.EndpointSecret(ctx, ep.ID)
	if err != nil {
		t.Fatal(err)
	}
	key := strings.TrimPrefix(secret, signature.SecretPrefix)
	signUp(t, e, hooks)
	s.setStatus(http.StatusInternalServerError)
	if _, err := e.Auth.CreateUser(ctx, auth.NewUser{Name: "Grace"}); err != nil {
		t.Fatal(err)
	}
	e.Auth.WaitDeliveries()
	_, _, regErr := hooks.CreateEndpoint(ctx, webhook.EndpointInput{URL: "ftp://x", Secret: secret})

	var stored string
	if err := e.Auth.One(ctx, e.Auth.Select().Columns(sqlb.Bind(sqlb.Col[string](webhook.TableEndpoint, webhook.ColSecret), &stored)).From(webhook.TableEndpoint)); err != nil {
		t.Fatal(err)
	}
	epJSON, _ := json.Marshal(ep)
	page, _ := hooks.Deliveries(ctx, webhook.DeliveryQuery{})
	pageJSON, _ := json.Marshal(page)
	for name, text := range map[string]string{
		"logs": logs.String(), "stored column": stored, "endpoint": string(epJSON), "deliveries": string(pageJSON), "refusal": regErr.Error(),
	} {
		if strings.Contains(text, key) {
			t.Errorf("%s holds the secret", name)
		}
	}
	if stored == "" {
		t.Fatal("no secret stored")
	}
}

// TestWebhooks_RotationSignsWithBoth: after RotateSecret a receiver with
// either secret verifies, until the grace ends.
func TestWebhooks_RotationSignsWithBoth(t *testing.T) {
	e, hooks, s, ep := world(t, nil, []string{webhook.EventUserCreated})
	ctx := context.Background()
	old, _ := hooks.EndpointSecret(ctx, ep.ID)
	fresh, err := hooks.RotateSecret(ctx, ep.ID, time.Hour)
	if err != nil || fresh == old {
		t.Fatalf("rotate = %v", err)
	}
	for i, secret := range []string{old, fresh} {
		s.setSecret(secret)
		if _, err := e.Auth.CreateUser(ctx, auth.NewUser{Name: "R"}); err != nil {
			t.Fatal(err)
		}
		e.Auth.WaitDeliveries()
		if accepted, refused := s.count(); accepted != i+1 || refused != 0 {
			t.Fatalf("secret %d: accepted %d refused %d", i, accepted, refused)
		}
	}
	e.Clock.Advance(time.Hour + time.Second)
	s.setSecret(old)
	if _, err := e.Auth.CreateUser(ctx, auth.NewUser{Name: "R"}); err != nil {
		t.Fatal(err)
	}
	e.Auth.WaitDeliveries()
	if _, refused := s.count(); refused != 1 {
		t.Fatalf("old secret after the grace still verified (refused %d)", refused)
	}
}

// TestWebhooks_SSRFGuard: without AllowPrivateNetworks a local URL is refused
// at registration, and an endpoint stored earlier with a name that resolves
// to loopback is refused when the connection is made.
func TestWebhooks_SSRFGuard(t *testing.T) {
	hooks := webhook.New()
	authtest.New(t, authtest.WithOptions(auth.WithSecret(testSecret)),
		authtest.WithPlugins(func(*authtest.Env) []auth.Plugin { return plugins(hooks) }))
	ctx := context.Background()
	for url, want := range map[string]error{
		"https://127.0.0.1/hook":       webhook.ErrDestinationRefused,
		"https://[::1]/hook":           webhook.ErrDestinationRefused,
		"https://169.254.169.254/meta": webhook.ErrDestinationRefused,
		"https://10.1.2.3/hook":        webhook.ErrDestinationRefused,
		"https://localhost/hook":       webhook.ErrDestinationRefused,
		"http://example.com/hook":      webhook.ErrBadURL,
		"https://u:p@example.com/hook": webhook.ErrBadURL,
	} {
		if _, _, err := hooks.CreateEndpoint(ctx, webhook.EndpointInput{URL: url}); !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", url, err, want)
		}
	}
	// The dial guard, which also stops a public name resolving to a private
	// address, is proven in the plugin's own tests (TestPost_DialGuard),
	// because no name resolves to loopback without the network or a hosts
	// entry.
}

// onlyDelivery is the one delivery to endpoint, failing otherwise.
func onlyDelivery(t *testing.T, hooks *webhook.Plugin, endpoint string) webhook.Delivery {
	t.Helper()
	page, err := hooks.Deliveries(context.Background(), webhook.DeliveryQuery{EndpointID: endpoint})
	if err != nil || len(page.Deliveries) != 1 {
		t.Fatalf("deliveries = %+v, %v; want exactly one", page, err)
	}
	return page.Deliveries[0]
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
