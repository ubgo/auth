// Package agentclient is the agent side of the Agent Auth Protocol: a Go
// program (an agent runtime, a CLI, an MCP server) that holds a host key
// discovers a provider, registers agents, waits for the user's approval,
// and executes capabilities with short-lived, request-bound JWTs. It covers
// the parts of the protocol plugin/agentauth serves, and Tools exposes it as
// MCP-style tools.
//
// The client keeps no state of its own: the host key is the caller's, and
// Connect returns an Agent (its id, key and provider) for the caller to
// keep wherever it keeps secrets.
package agentclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/agentauth"
)

// Protocol values the client signs and sends.
const (
	algEdDSA  = "EdDSA"
	keyTypeOK = "OKP"
	// tokenLifetime is how long a signed JWT lives: the server accepts
	// one no older than its JWTMaxAge, 60 seconds by default.
	tokenLifetime = 60 * time.Second
	// maxAnswerBytes bounds a provider answer the client reads.
	maxAnswerBytes = 10 << 20
	// jtiBytes is the random part of a JWT id.
	jtiBytes = 16
	// defaultPoll is the approval polling interval when the provider
	// names none.
	defaultPoll = 5 * time.Second
	headerAuth  = "Authorization"
	headerCT    = "Content-Type"
	jsonCT      = "application/json"
)

var b64 = base64.RawURLEncoding

// Key is an Ed25519 key pair in the protocol's JWK form.
type Key struct {
	Public  agentauth.PublicKey
	private ed25519.PrivateKey
}

// NewKey generates an Ed25519 key.
func NewKey() (Key, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Key{}, err
	}
	return KeyFrom(priv), nil
}

// KeyFrom wraps a stored Ed25519 private key.
func KeyFrom(priv ed25519.PrivateKey) Key {
	pub, _ := priv.Public().(ed25519.PublicKey) // an ed25519 key's public half is always ed25519.PublicKey
	return Key{Public: agentauth.PublicKey{KeyType: keyTypeOK, Curve: agentauth.AlgEd25519, X: b64.EncodeToString(pub)}, private: priv}
}

// PrivateKey is the key to store.
func (k Key) PrivateKey() ed25519.PrivateKey { return k.private }

// sign builds a compact JWS of typ over claims.
func (k Key) sign(typ string, claims map[string]any) (string, error) {
	if k.private == nil {
		return "", ErrNoKey
	}
	// A map of strings always encodes.
	h, _ := json.Marshal(map[string]string{"alg": algEdDSA, "typ": typ})
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	in := b64.EncodeToString(h) + "." + b64.EncodeToString(c)
	return in + "." + b64.EncodeToString(ed25519.Sign(k.private, []byte(in))), nil
}

// ErrNoKey is a Key without its private half.
var ErrNoKey = errors.New("agentclient: the key has no private key")

// Error is a provider's protocol error answer.
type Error struct {
	Status  int
	Code    string `json:"error"`
	Message string `json:"message"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("agentclient: %d %s: %s", e.Status, e.Code, e.Message)
}

// Client talks to providers for one host.
type Client struct {
	// optErrs collects what the options found while they ran, such as a
	// nil func or interface (auth.ErrNilOption); see OptionErr.
	optErrs  auth.OptionErrors
	host     Key
	hostName string
	http     *http.Client
	now      func() time.Time
}

// OptionErr is every error the options recorded, such as auth.ErrNilOption
// naming an option given nil (WithClock(nil)). The client has no start-up
// check of its own, so every call that signs a token returns it.
func (c *Client) OptionErr() error { return c.optErrs.OptionErr() }

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient sends requests with hc instead of http.DefaultClient.
func WithHTTPClient(hc *http.Client) Option { return func(c *Client) { c.http = hc } }

// WithHostName names the host to the provider and to the approving user.
func WithHostName(name string) Option { return func(c *Client) { c.hostName = name } }

// WithClock sets the time JWTs are issued at, for tests.
func WithClock(now func() time.Time) Option {
	return func(c *Client) {
		if c.optErrs.RefuseNil("agentclient.WithClock", now) {
			return
		}
		c.now = now
	}
}

// New builds a client for the host whose key is host.
func New(host Key, opts ...Option) *Client {
	c := &Client{host: host, http: http.DefaultClient, now: time.Now}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Provider is a provider's discovery document.
type Provider = agentauth.Configuration

// Discover reads the discovery document of the provider at providerURL
// (any URL on its origin).
func (c *Client) Discover(ctx context.Context, providerURL string) (Provider, error) {
	u, err := url.Parse(providerURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return Provider{}, fmt.Errorf("agentclient: %q is not an absolute URL", providerURL)
	}
	var p Provider
	err = c.do(ctx, http.MethodGet, u.Scheme+"://"+u.Host+agentauth.WellKnownConfiguration, "", nil, &p)
	return p, err
}

// Agent is a registered agent: what the caller stores to act as it later.
type Agent struct {
	ID       string
	HostID   string
	Key      Key
	Provider Provider
}

// ConnectRequest is what Connect registers.
type ConnectRequest struct {
	Name         string
	Capabilities []agentauth.CapabilityRequest
	Mode         agentauth.Mode
	Reason       string
	agentauth.ApprovalHints
	ForceApproval bool
}

// hostJWT signs a host token for aud carrying extra claims. Its iss is the
// host key's thumbprint, which the provider resolves to the host whether it
// was created by a user or registers dynamically.
func (c *Client) hostJWT(aud string, extra map[string]any) (string, error) {
	// An option given nil (WithClock(nil)) fails every signed call here,
	// before baseClaims would call the nil clock.
	if err := c.OptionErr(); err != nil {
		return "", err
	}
	claims := c.baseClaims(aud)
	id := c.host.Public.KeyID
	if id == "" {
		id = c.host.Public.Thumbprint()
	}
	claims["iss"], claims["sub"], claims["host_public_key"] = id, id, c.host.Public
	if c.hostName != "" {
		claims["host_name"] = c.hostName
	}
	for k, v := range extra {
		claims[k] = v
	}
	return c.host.sign(agentauth.TypeHostJWT, claims)
}

// baseClaims are the time and id claims every token carries. crypto/rand's
// Read never returns an error since Go 1.24 (it aborts the program instead),
// so there is no failure to pass on.
func (c *Client) baseClaims(aud string) map[string]any {
	jti := make([]byte, jtiBytes)
	_, _ = rand.Read(jti)
	now := c.now()
	return map[string]any{"aud": aud, "iat": now.Unix(), "exp": now.Add(tokenLifetime).Unix(), "jti": b64.EncodeToString(jti)}
}

// Connect registers a new agent with its own fresh key. The result says
// whether the agent is active or waits for the user (its Approval);
// WaitForApproval waits.
func (c *Client) Connect(ctx context.Context, p Provider, in ConnectRequest) (Agent, agentauth.RegisterResult, error) {
	key, err := NewKey()
	if err != nil {
		return Agent{}, agentauth.RegisterResult{}, err
	}
	tok, err := c.hostJWT(p.Issuer, map[string]any{"agent_public_key": key.Public})
	if err != nil {
		return Agent{}, agentauth.RegisterResult{}, err
	}
	body := agentauth.RegisterRequest{
		Name: in.Name, Capabilities: in.Capabilities, Reason: in.Reason, Mode: in.Mode, HostName: c.hostName,
		ForceApproval: in.ForceApproval, ApprovalHints: in.ApprovalHints,
	}
	var res agentauth.RegisterResult
	if err := c.do(ctx, http.MethodPost, p.Endpoints["register"], tok, body, &res); err != nil {
		return Agent{}, res, err
	}
	return Agent{ID: res.AgentID, HostID: res.HostID, Key: key, Provider: p}, res, nil
}

// Status reads the agent's status with the host's key.
func (c *Client) Status(ctx context.Context, a Agent) (agentauth.AgentStatusView, error) {
	tok, err := c.hostJWT(a.Provider.Issuer, nil)
	if err != nil {
		return agentauth.AgentStatusView{}, err
	}
	var out agentauth.AgentStatusView
	err = c.do(ctx, http.MethodGet, a.Provider.Endpoints["status"]+"?agent_id="+url.QueryEscape(a.ID), tok, nil, &out)
	return out, err
}

// WaitForApproval polls Status every interval (zero takes the provider's
// default of five seconds) until the agent is no longer pending or ctx
// ends.
func (c *Client) WaitForApproval(ctx context.Context, a Agent, interval time.Duration) (agentauth.AgentStatusView, error) {
	if interval <= 0 {
		interval = defaultPoll
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		st, err := c.Status(ctx, a)
		if err != nil || st.Status != agentauth.AgentPending {
			return st, err
		}
		select {
		case <-ctx.Done():
			return st, ctx.Err()
		case <-t.C:
		}
	}
}

// SignAgentJWT signs an agent token for aud, bound to the request when
// method and target are set (htm, htu) and to its body when body is not
// nil (ath). It is what an app route that verifies agents with
// VerifyAgentRequest receives.
func SignAgentJWT(a Agent, now time.Time, aud, method, target string, body []byte) (string, error) {
	c := &Client{now: func() time.Time { return now }}
	return c.agentJWT(a, aud, method, target, body)
}

func (c *Client) agentJWT(a Agent, aud, method, target string, body []byte) (string, error) {
	// An option given nil (WithClock(nil)) fails every signed call here,
	// before baseClaims would call the nil clock.
	if err := c.OptionErr(); err != nil {
		return "", err
	}
	claims := c.baseClaims(aud)
	claims["sub"] = a.ID
	if method != "" {
		claims["htm"] = method
	}
	if target != "" {
		u, err := url.Parse(target)
		if err != nil {
			return "", err
		}
		u.RawQuery, u.Fragment = "", ""
		claims["htu"] = u.String()
	}
	if body != nil {
		sum := sha256.Sum256(body)
		claims["ath"] = b64.EncodeToString(sum[:])
	}
	return a.Key.sign(agentauth.TypeAgentJWT, claims)
}

// agentCall sends a request signed by the agent and bound to it.
func (c *Client) agentCall(ctx context.Context, a Agent, method, target, aud string, in, out any) error {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	tok, err := c.agentJWT(a, aud, method, target, body)
	if err != nil {
		return err
	}
	return c.send(ctx, method, target, tok, body, out)
}

// Execute runs a capability. location is
// the capability's own Location, or "" for the provider's execute
// endpoint; the token's audience follows it. The capability's result is
// returned as the provider sent it.
func (c *Client) Execute(ctx context.Context, a Agent, capability, location string, args map[string]any) (json.RawMessage, error) {
	target := a.Provider.DefaultLocation
	if location != "" {
		target = location
	}
	var out struct {
		Data json.RawMessage `json:"data"`
	}
	err := c.agentCall(ctx, a, http.MethodPost, target, target, map[string]any{"capability": capability, "arguments": args}, &out)
	return out.Data, err
}

// RequestCapability asks for more capabilities for the agent.
func (c *Client) RequestCapability(ctx context.Context, a Agent, caps []agentauth.CapabilityRequest, reason string, hints agentauth.ApprovalHints) (agentauth.RequestCapabilityResult, error) {
	var out agentauth.RequestCapabilityResult
	in := agentauth.RequestCapabilityRequest{Capabilities: caps, Reason: reason, ApprovalHints: hints}
	err := c.agentCall(ctx, a, http.MethodPost, a.Provider.Endpoints["request_capability"], a.Provider.Issuer, in, &out)
	return out, err
}

// ListCapabilities lists the provider's capabilities; with an agent, each
// says whether the agent holds it.
func (c *Client) ListCapabilities(ctx context.Context, p Provider, a *Agent) (agentauth.CapabilityList, error) {
	var out agentauth.CapabilityList
	if a != nil {
		err := c.agentCall(ctx, *a, http.MethodGet, p.Endpoints["capabilities"], p.Issuer, nil, &out)
		return out, err
	}
	tok, err := c.hostJWT(p.Issuer, nil)
	if err != nil {
		return out, err
	}
	err = c.do(ctx, http.MethodGet, p.Endpoints["capabilities"], tok, nil, &out)
	return out, err
}

// DescribeCapability returns one capability with its schemas.
func (c *Client) DescribeCapability(ctx context.Context, p Provider, name string) (agentauth.CapabilityView, error) {
	tok, err := c.hostJWT(p.Issuer, nil)
	if err != nil {
		return agentauth.CapabilityView{}, err
	}
	var out agentauth.CapabilityView
	err = c.do(ctx, http.MethodGet, p.Endpoints["describe_capability"]+"?name="+url.QueryEscape(name), tok, nil, &out)
	return out, err
}

// Disconnect revokes the agent.
func (c *Client) Disconnect(ctx context.Context, a Agent) error {
	var out agentauth.RevokeResult
	return c.agentCall(ctx, a, http.MethodPost, a.Provider.Endpoints["revoke"], a.Provider.Issuer, map[string]any{}, &out)
}

// CIBAAuthorize asks the user named by loginHint to approve the host's
// agent through CIBA.
func (c *Client) CIBAAuthorize(ctx context.Context, a Agent, loginHint, bindingMessage string, caps []string) (agentauth.CIBAAuthorizeResult, error) {
	tok, err := c.hostJWT(a.Provider.Issuer, nil)
	if err != nil {
		return agentauth.CIBAAuthorizeResult{}, err
	}
	in := agentauth.CIBAAuthorizeRequest{LoginHint: loginHint, BindingMessage: bindingMessage, Capabilities: caps, AgentID: a.ID}
	var out agentauth.CIBAAuthorizeResult
	err = c.do(ctx, http.MethodPost, a.Provider.Issuer+agentauth.PathCIBAAuthorize, tok, in, &out)
	return out, err
}

// do sends in as JSON (nil: no body) with bearer tok and decodes the
// answer into out.
func (c *Client) do(ctx context.Context, method, target, tok string, in, out any) error {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	return c.send(ctx, method, target, tok, body, out)
}

// send performs one request and decodes a success into out, or a
// protocol error answer into *Error. Every endpoint answers a JSON body,
// so out is never nil.
func (c *Client) send(ctx context.Context, method, target, tok string, body []byte, out any) error {
	if target == "" {
		return errors.New("agentclient: the provider does not serve this endpoint")
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, rd)
	if err != nil {
		return err
	}
	if tok != "" {
		req.Header.Set(headerAuth, "Bearer "+tok)
	}
	if body != nil {
		req.Header.Set(headerCT, jsonCT)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxAnswerBytes))
	if err != nil {
		return err
	}
	if res.StatusCode >= http.StatusBadRequest {
		e := &Error{Status: res.StatusCode}
		if json.Unmarshal(raw, e) != nil || e.Code == "" {
			e.Code, e.Message = http.StatusText(res.StatusCode), strings.TrimSpace(string(raw))
		}
		return e
	}
	return json.Unmarshal(raw, out)
}
