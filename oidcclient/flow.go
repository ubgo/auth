package oidcclient

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"time"
)

// A sign-in flow is the state one trip to the login server needs on its
// way back: the state that ties the callback to this browser, the nonce
// that ties the ID token to this trip, the PKCE verifier that ties the code
// to this client, and where to land. It lives in the flow cookie, sealed
// under the flow cookie's name, so it can never be replayed as a session.

// Flow constants.
const (
	// flowTTL bounds one trip to the login server: long enough to type a
	// password and pass a second factor, short enough that a stolen flow
	// cookie is soon worth nothing.
	flowTTL = 10 * time.Minute
	// maxPendingFlows is how many sign-ins one browser may have in flight:
	// two tabs that both found their session expired each start one, and
	// both must be able to finish. The oldest is dropped beyond it.
	maxPendingFlows = 3
	// randomBytes is the entropy of a state, a nonce, a PKCE verifier and a
	// session ID: 256 bits.
	randomBytes = 32
)

// pendingFlow is one sign-in in flight.
type pendingFlow struct {
	State     string    `json:"state"`
	Nonce     string    `json:"nonce"`
	Verifier  string    `json:"verifier"`
	ReturnTo  string    `json:"return_to"`
	CreatedAt time.Time `json:"created_at"`
}

// flowCookie is the flow cookie's plaintext: the pending flows, oldest
// first.
type flowCookie struct {
	Flows []pendingFlow `json:"flows"`
}

// randomToken returns randomBytes of crypto/rand entropy, base64url: a
// state, nonce, verifier or session ID. crypto/rand.Read never fails on a
// supported platform (it panics if it cannot read), so there is no error.
func randomToken() string {
	b := make([]byte, randomBytes)
	_, _ = rand.Read(b) // documented never to return an error since Go 1.24
	return base64.RawURLEncoding.EncodeToString(b)
}

// codeChallenge is the PKCE S256 challenge of verifier (RFC 7636 section
// 4.2).
func codeChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// readFlows opens the flow cookie and drops expired flows. A missing or
// unopenable cookie is no flows: the callback then refuses.
func (c *Client) readFlows(ctx context.Context, r *http.Request) flowCookie {
	ck, err := r.Cookie(c.set.cookie.flowName())
	if err != nil {
		return flowCookie{}
	}
	plain, err := c.set.sealer.Open(ctx, ck.Value, c.set.cookie.flowName())
	if err != nil {
		return flowCookie{}
	}
	var fc flowCookie
	if json.Unmarshal(plain, &fc) != nil {
		return flowCookie{}
	}
	now := c.set.now()
	fc.Flows = slices.DeleteFunc(fc.Flows, func(f pendingFlow) bool {
		return now.Sub(f.CreatedAt) > flowTTL || now.Before(f.CreatedAt.Add(-tokenLeeway))
	})
	return fc
}

// writeFlows seals fc into the flow cookie, or deletes the cookie when no
// flow is left. The flow cookie is always SameSite=Lax: the login server's
// redirect back is a cross-site top-level navigation, which Lax still
// sends a cookie on and Strict does not.
func (c *Client) writeFlows(ctx context.Context, w http.ResponseWriter, r *http.Request, fc flowCookie) error {
	cw := cookieWriter{opts: c.set.cookie}
	name := c.set.cookie.flowName()
	if len(fc.Flows) == 0 {
		cw.clear(w, r, name)
		return nil
	}
	plain, err := json.Marshal(fc)
	if err != nil {
		return err
	}
	sealed, err := c.set.sealer.Seal(ctx, plain, name)
	if err != nil {
		return err
	}
	now := c.set.now()
	cw.set(w, name, sealed, fc.Flows[len(fc.Flows)-1].CreatedAt.Add(flowTTL), now, http.SameSiteLaxMode)
	return nil
}

// takeFlow removes and returns the flow whose state is state, compared in
// constant time against every pending flow so the time taken says nothing
// about which, if any, matched.
func (fc *flowCookie) takeFlow(state string) (pendingFlow, bool) {
	found := -1
	for i, f := range fc.Flows {
		if subtle.ConstantTimeCompare([]byte(f.State), []byte(state)) == 1 && state != "" {
			found = i
		}
	}
	if found < 0 {
		return pendingFlow{}, false
	}
	f := fc.Flows[found]
	fc.Flows = slices.Delete(fc.Flows, found, found+1)
	return f, true
}

// addFlow appends f, dropping the oldest beyond maxPendingFlows.
func (fc *flowCookie) addFlow(f pendingFlow) {
	fc.Flows = append(fc.Flows, f)
	if len(fc.Flows) > maxPendingFlows {
		fc.Flows = fc.Flows[len(fc.Flows)-maxPendingFlows:]
	}
}
