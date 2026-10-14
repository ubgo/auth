package deviceauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Client is the device side of the flow in Go, better-auth's
// deviceAuthorizationClient: a CLI or any program without a browser asks
// CodeHandler for a code, shows the user code and verification URI, then
// polls TokenHandler until the user approves or denies. It speaks the RFC
// 8628 wire format only (form bodies, {"error": ...} answers), so it works
// against any RFC 8628 server, this plugin's or another's. Standard library
// only; golang.org/x/oauth2's device flow is the alternative for an app that
// already imports it.
//
//ds:def id=deviceauth-client-p3dv7kcl owner=@khanakia stability=stable
type Client struct {
	// CodeURL is where CodeHandler is mounted, such as
	// "https://app.example.com/auth/device/code".
	CodeURL string
	// TokenURL is where TokenHandler is mounted.
	TokenURL string
	// ClientID is sent with every request.
	ClientID string
	// HTTP sends the requests; nil is http.DefaultClient.
	HTTP *http.Client
	// Sleep waits between polls and returns ctx's error when ctx ends first;
	// nil waits on a timer. A test replaces it to move a fake clock.
	Sleep func(ctx context.Context, d time.Duration) error
}

// defaultPollInterval is the interval when the code answer names none, RFC
// 8628 §3.2's default. It equals DefaultInterval today, but is the RFC's
// number, not this server's setting, so it stays separate.
const defaultPollInterval = 5 * time.Second

// maxClientBody bounds an answer the client reads: a code or token answer is
// a few hundred bytes, and a server must not make the client buffer more.
const maxClientBody = 1 << 20

// ClientError is a refusal the server answered in RFC 6749 §5.2's shape.
// ErrorName is the "error" member (RFCAccessDenied, RFCExpiredToken,
// RFCInvalidClient, ...), Status the HTTP status. An answer that is not the
// RFC shape is a ClientError with ErrorName RFCServerError.
type ClientError struct {
	Status      int
	ErrorName   string
	Description string
}

// Error names the RFC error code, and the server's description when it sent one.
func (e *ClientError) Error() string {
	if e.Description == "" {
		return "deviceauth: " + e.ErrorName
	}
	return "deviceauth: " + e.ErrorName + ": " + e.Description
}

// ErrClientConfig is a Client missing its CodeURL, TokenURL or ClientID.
var ErrClientConfig = errors.New("deviceauth: a Client needs CodeURL, TokenURL and ClientID")

// RequestCode asks for a device code (RFC 8628 §3.1). scope may be empty.
// Show the user UserCode and VerificationURI (or VerificationURIComplete),
// then call Poll with the result.
//
//ds:def id=deviceauth-client-requestcode-p3m2xr8d owner=@khanakia stability=stable
func (c *Client) RequestCode(ctx context.Context, scope string) (CodeResult, error) {
	if err := c.check(); err != nil {
		return CodeResult{}, err
	}
	form := url.Values{"client_id": {c.ClientID}}
	if scope != "" {
		form.Set("scope", scope)
	}
	var out CodeResult
	if _, err := c.post(ctx, c.CodeURL, form, &out); err != nil {
		return CodeResult{}, err
	}
	return out, nil
}

// Poll asks for the token until the user decides (RFC 8628 §3.4, §3.5): it
// waits the code's interval before each request, keeps going on
// authorization_pending, adds SlowDownStep (5s, the server's own step) to the interval on
// slow_down, and waits a 429 or temporarily_unavailable answer's Retry-After
// (or the interval). Any other refusal ends it as a *ClientError: the user
// denied (RFCAccessDenied), the code expired (RFCExpiredToken), and so on. It
// also ends when ctx does.
//
//ds:def id=deviceauth-client-poll-p3w8kd4n owner=@khanakia stability=stable
func (c *Client) Poll(ctx context.Context, code CodeResult) (TokenResult, error) {
	if err := c.check(); err != nil {
		return TokenResult{}, err
	}
	interval := time.Duration(code.Interval) * time.Second
	if interval <= 0 {
		interval = defaultPollInterval
	}
	form := url.Values{"grant_type": {GrantType}, "device_code": {code.DeviceCode}, "client_id": {c.ClientID}}
	wait := interval
	for {
		if err := c.sleep(ctx, wait); err != nil {
			return TokenResult{}, err
		}
		wait = interval
		var out TokenResult
		retry, err := c.post(ctx, c.TokenURL, form, &out)
		if err == nil {
			return out, nil
		}
		var ce *ClientError
		if !errors.As(err, &ce) {
			return TokenResult{}, err
		}
		switch {
		case ce.ErrorName == RFCAuthorizationPending:
		case ce.ErrorName == RFCSlowDown:
			interval += SlowDownStep
			wait = interval
		case ce.ErrorName == RFCTemporarilyUnavailable || ce.Status == http.StatusTooManyRequests:
			if retry > wait {
				wait = retry
			}
		default:
			return TokenResult{}, err
		}
	}
}

// check refuses a Client without its endpoints or client id.
func (c *Client) check() error {
	if c.CodeURL == "" || c.TokenURL == "" || c.ClientID == "" {
		return ErrClientConfig
	}
	return nil
}

// sleep waits d through Sleep, or a timer that ctx can cut short.
func (c *Client) sleep(ctx context.Context, d time.Duration) error {
	if c.Sleep != nil {
		return c.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// post sends form to u and decodes a 200 answer into dst. A refusal is a
// *ClientError, with the Retry-After of the answer (0 when absent) returned
// beside it for Poll's back-off.
func (c *Client) post(ctx context.Context, u string, form url.Values, dst any) (time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, fmt.Errorf("deviceauth: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	res, err := hc.Do(req)
	if err != nil {
		return 0, fmt.Errorf("deviceauth: %w", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxClientBody))
	if err != nil {
		return 0, fmt.Errorf("deviceauth: read answer: %w", err)
	}
	if res.StatusCode == http.StatusOK {
		if err := json.Unmarshal(body, dst); err != nil {
			return 0, fmt.Errorf("deviceauth: decode answer: %w", err)
		}
		return 0, nil
	}
	var e rfcError
	if json.Unmarshal(body, &e) != nil || e.Error == "" {
		e = rfcError{Error: RFCServerError, Description: http.StatusText(res.StatusCode)}
	}
	retry := time.Duration(0)
	if s, err := strconv.Atoi(res.Header.Get("Retry-After")); err == nil && s > 0 {
		retry = time.Duration(s) * time.Second
	}
	return retry, &ClientError{Status: res.StatusCode, ErrorName: e.Error, Description: e.Description}
}
