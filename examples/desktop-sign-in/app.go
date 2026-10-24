package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/handoff"
)

// The desktop app's side: a loopback listener for the browser's return, the
// exchange of the token for a bearer session, and a signed-in request.

// errTimeout is returned when the browser did not come back in time.
var errTimeout = errors.New("no sign-in arrived in time")

// browserOpener opens a URL in the system browser; the real one shells out,
// the test and the demo print it.
type browserOpener func(string) error

// runApp signs the app in: it listens on the loopback interface (and only
// there: a listener on every interface would take the token from anyone on
// the network), makes a verifier and opens the web app's open-in-app page
// with its own callback as returnTo and the verifier's challenge, waits for
// the browser to come back with the token, closes the listener, exchanges
// the token with the verifier and calls /me with the bearer token. The
// exchange and the call need no cookie and no Origin: the app is not a
// browser. wait bounds how long the browser may take.
//
// The verifier (RFC 7636 PKCE, as RFC 8252 §8.1 asks of every native app)
// never leaves this process: only its hash travels to the page, so a token
// that reached a different program, on a URL scheme both registered, say,
// cannot be exchanged by it. The loopback return has no such receiver, but
// one flow for both return paths is simpler than two.
//
//ds:def id=desktop-runapp-2c6zq8wd
func runApp(ctx context.Context, out io.Writer, hc *http.Client, server, loopback string, wait time.Duration, open browserOpener) error {
	ln, err := net.Listen("tcp", loopback)
	if err != nil {
		return err
	}
	callback := "http://" + ln.Addr().String() + callbackPath
	tokens := make(chan string, 1)
	srv := &http.Server{Handler: callbackHandler(tokens), ReadHeaderTimeout: readHeaderTimeout}
	go func() { _ = srv.Serve(ln) }() // ends with Shutdown below
	// The token has arrived or the wait is over: close the listener now, not
	// when Serve gets round to it, so the port is free for the next run.
	defer func() { _ = srv.Shutdown(context.Background()); _ = ln.Close() }()

	verifier, challenge, err := handoff.NewVerifier()
	if err != nil {
		return err
	}
	if err := open(server + openInAppPath + "?" + url.Values{returnToParam: {callback}, challengeParam: {challenge}}.Encode()); err != nil {
		return err
	}
	var token string
	select {
	case token = <-tokens:
	case <-time.After(wait):
		return errTimeout
	case <-ctx.Done():
		return ctx.Err()
	}
	bearer, user, err := exchange(ctx, hc, server, token, verifier)
	if err != nil {
		return err
	}
	var me meResponse
	if err := call(ctx, hc, server+"/me", bearer, &me); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "signed in as %s (%s), /me answered %s with credential %q\n", user.User.ID, user.User.Name, me.ID, me.Credential)
	return err
}

// callbackHandler receives the browser's return: the token is in the query,
// and the page tells the person they can close the tab. The first token wins;
// a second request (a refresh) gets the same page and changes nothing.
func callbackHandler(tokens chan<- string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != callbackPath {
			http.NotFound(w, r)
			return
		}
		if t := r.URL.Query().Get(tokenParam); t != "" {
			select {
			case tokens <- t:
			default:
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<!doctype html><title>Signed in</title><p>You are signed in to the app. You can close this tab.</p>")
	})
}

// exchange spends the hand-off token for a bearer session of the app's own,
// asking for bearer delivery so the session arrives in Set-Auth-Token rather
// than a cookie the app cannot keep. verifier is the one whose challenge
// minted the token, or "" for a token minted without one (a pasted code).
//
//ds:def id=desktop-exchange-6h9rp3fk
func exchange(ctx context.Context, hc *http.Client, server, token, verifier string) (string, handoff.VerifyResult, error) {
	// The request body is a plain struct: auth.Token redacts itself when
	// marshalled, which is right for a server and wrong for the client.
	body, err := json.Marshal(struct {
		Token    string `json:"token"`
		Verifier string `json:"verifier,omitempty"`
	}{token, verifier})
	if err != nil {
		return "", handoff.VerifyResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server+authPrefix+"/handoff/verify", bytes.NewReader(body))
	if err != nil {
		return "", handoff.VerifyResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(authhttp.TokenModeHeader, authhttp.TokenModeBearer)
	res, err := hc.Do(req)
	if err != nil {
		return "", handoff.VerifyResult{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(res.Body)
		return "", handoff.VerifyResult{}, fmt.Errorf("exchange: %s: %s", res.Status, raw)
	}
	var out handoff.VerifyResult
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return "", handoff.VerifyResult{}, err
	}
	bearer := res.Header.Get(authhttp.SetTokenHeader)
	if bearer == "" {
		return "", handoff.VerifyResult{}, errors.New("exchange: no " + authhttp.SetTokenHeader + " in the answer")
	}
	return bearer, out, nil
}

// call makes a signed-in request with the bearer token and decodes the JSON
// answer into out.
func call(ctx context.Context, hc *http.Client, u, bearer string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(res.Body)
		return fmt.Errorf("%s: %s: %s", u, res.Status, raw)
	}
	return json.NewDecoder(res.Body).Decode(out)
}
