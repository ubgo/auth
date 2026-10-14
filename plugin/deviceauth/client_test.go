package deviceauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRFC is an RFC 8628 server scripted per poll: answers[i] is the i-th
// token answer, as (status, body, Retry-After).
type fakeRFC struct {
	mu      sync.Mutex
	answers []fakeAnswer
	polls   int
	forms   []string
}

type fakeAnswer struct {
	status int
	body   string
	retry  string
}

func (f *fakeRFC) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /code", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		f.forms = append(f.forms, r.PostForm.Encode())
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"device_code":"dev","user_code":"ABCD-EFGH","verification_uri":"https://app.example.com/device","verification_uri_complete":"https://app.example.com/device?user_code=ABCD-EFGH","expires_in":900,"interval":2}`)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		f.forms = append(f.forms, r.PostForm.Encode())
		a := f.answers[f.polls]
		f.polls++
		f.mu.Unlock()
		if a.retry != "" {
			w.Header().Set("Retry-After", a.retry)
		}
		w.WriteHeader(a.status)
		fmt.Fprint(w, a.body)
	})
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// client returns a Client against s that records every wait instead of
// sleeping.
func client(s *httptest.Server, waits *[]time.Duration) *Client {
	return &Client{CodeURL: s.URL + "/code", TokenURL: s.URL + "/token", ClientID: "cli", HTTP: s.Client(),
		Sleep: func(_ context.Context, d time.Duration) error { *waits = append(*waits, d); return nil }}
}

// TestClient_PollsUntilApproved: pending keeps the interval, slow_down adds
// five seconds to it for good, a 429 waits its Retry-After once, and the
// token answer ends the poll.
func TestClient_PollsUntilApproved(t *testing.T) {
	f := &fakeRFC{answers: []fakeAnswer{
		{400, `{"error":"authorization_pending"}`, ""},
		{400, `{"error":"slow_down"}`, ""},
		{429, `{"error":"temporarily_unavailable"}`, "30"},
		{400, `{"error":"authorization_pending"}`, ""},
		{200, `{"access_token":"tok","token_type":"Bearer","expires_in":3600,"scope":"openid"}`, ""},
	}}
	s := f.server(t)
	var waits []time.Duration
	c := client(s, &waits)
	code, err := c.RequestCode(context.Background(), "openid")
	if err != nil || code.UserCode != "ABCD-EFGH" || code.Interval != 2 {
		t.Fatalf("code = %+v %v", code, err)
	}
	tok, err := c.Poll(context.Background(), code)
	if err != nil || tok.AccessToken != "tok" || tok.ExpiresIn != 3600 {
		t.Fatalf("token = %+v %v", tok, err)
	}
	want := []time.Duration{2 * time.Second, 2 * time.Second, 7 * time.Second, 30 * time.Second, 7 * time.Second}
	if fmt.Sprint(waits) != fmt.Sprint(want) {
		t.Fatalf("waits = %v, want %v", waits, want)
	}
	if f.forms[0] != "client_id=cli&scope=openid" || !strings.Contains(f.forms[1], "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code") {
		t.Fatalf("forms = %v", f.forms)
	}
}

// TestClient_Refusals: a denial ends the poll with its RFC code; an answer
// that is not the RFC shape is server_error; a Retry-After shorter than the
// interval keeps the interval; a missing interval is RFC 8628's five seconds.
func TestClient_Refusals(t *testing.T) {
	f := &fakeRFC{answers: []fakeAnswer{
		{503, `{"error":"temporarily_unavailable"}`, "1"},
		{400, `{"error":"access_denied","error_description":"no"}`, ""},
		{502, `<html>bad gateway</html>`, ""},
	}}
	s := f.server(t)
	var waits []time.Duration
	c := client(s, &waits)
	_, err := c.Poll(context.Background(), CodeResult{DeviceCode: "dev"})
	var ce *ClientError
	if !errors.As(err, &ce) || ce.ErrorName != RFCAccessDenied || ce.Error() != "deviceauth: access_denied: no" {
		t.Fatalf("denied = %v", err)
	}
	if fmt.Sprint(waits) != fmt.Sprint([]time.Duration{5 * time.Second, 5 * time.Second}) {
		t.Fatalf("waits = %v", waits)
	}
	_, err = c.Poll(context.Background(), CodeResult{DeviceCode: "dev"})
	if !errors.As(err, &ce) || ce.ErrorName != RFCServerError || ce.Status != http.StatusBadGateway || ce.Error() != "deviceauth: server_error: Bad Gateway" {
		t.Fatalf("not RFC = %v", err)
	}
	if (&ClientError{ErrorName: RFCExpiredToken}).Error() != "deviceauth: expired_token" {
		t.Fatal("message without a description")
	}
}

// TestClient_Failures: a Client without its endpoints is refused before any
// request; a transport failure, an unreadable or undecodable answer, a bad
// URL and a cancelled context end the call.
func TestClient_Failures(t *testing.T) {
	if _, err := (&Client{}).RequestCode(context.Background(), ""); !errors.Is(err, ErrClientConfig) {
		t.Fatalf("no config: %v", err)
	}
	if _, err := (&Client{}).Poll(context.Background(), CodeResult{}); !errors.Is(err, ErrClientConfig) {
		t.Fatalf("no config poll: %v", err)
	}
	bad := &Client{CodeURL: "http://127.0.0.1:0/code", TokenURL: "x", ClientID: "c"}
	if _, err := bad.RequestCode(context.Background(), ""); err == nil || !strings.HasPrefix(err.Error(), "deviceauth: ") {
		t.Fatalf("unreachable: %v", err)
	}
	if _, err := (&Client{CodeURL: "::", TokenURL: "x", ClientID: "c"}).RequestCode(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "build request") {
		t.Fatalf("bad url: %v", err)
	}
	junk := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/short" {
			w.Header().Set("Content-Length", "100")
			fmt.Fprint(w, "{")
			return
		}
		fmt.Fprint(w, "not json")
	}))
	defer junk.Close()
	c := &Client{CodeURL: junk.URL, TokenURL: junk.URL, ClientID: "c"}
	if _, err := c.RequestCode(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "decode answer") {
		t.Fatalf("junk: %v", err)
	}
	c.CodeURL = junk.URL + "/short"
	if _, err := c.RequestCode(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "read answer") {
		t.Fatalf("short body: %v", err)
	}
	c.Sleep = func(context.Context, time.Duration) error { return nil }
	if _, err := c.Poll(context.Background(), CodeResult{}); err == nil || !strings.Contains(err.Error(), "decode answer") {
		t.Fatalf("poll junk: %v", err)
	}
	// The real timer, cut short by the context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.Sleep = nil
	if _, err := c.Poll(ctx, CodeResult{Interval: 60}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
	if err := (&Client{}).sleep(context.Background(), time.Millisecond); err != nil {
		t.Fatalf("timer: %v", err)
	}
}

// ExampleClient is the device side of a CLI login, better-auth's `npx auth
// login` demo in Go: request a code, show it, poll until the user approves
// on another device. The server here is a stand-in that approves at once;
// in an app, CodeURL and TokenURL are where CodeHandler and TokenHandler are
// mounted.
func ExampleClient() {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/device/code", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"device_code":"d","user_code":"WDJB-MJHT","verification_uri":"https://app.example.com/device","expires_in":900,"interval":5}`)
	})
	mux.HandleFunc("POST /auth/device/token", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token":"session-token","token_type":"Bearer","expires_in":604800}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &Client{CodeURL: srv.URL + "/auth/device/code", TokenURL: srv.URL + "/auth/device/token", ClientID: "my-cli",
		Sleep: func(context.Context, time.Duration) error { return nil }} // a real CLI leaves Sleep nil
	ctx := context.Background()
	code, err := c.RequestCode(ctx, "")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Open %s and enter %s\n", code.VerificationURI, code.UserCode)
	tok, err := c.Poll(ctx, code)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("signed in; send", tok.TokenType, "tokens from now on")
	// Output:
	// Open https://app.example.com/device and enter WDJB-MJHT
	// signed in; send Bearer tokens from now on
}
