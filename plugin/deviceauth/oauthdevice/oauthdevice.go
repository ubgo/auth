// Package oauthdevice serves the device authorization grant (RFC 8628) of
// plugin/oauthprovider with plugin/deviceauth, better-auth's
// oauthDeviceAuthorization: a registered OAuth client (a CLI, a TV app)
// asks for a device code, the user approves on the approval page, and the
// client polls the provider's token endpoint with grant_type
// urn:ietf:params:oauth:grant-type:device_code for access, refresh and ID
// tokens instead of a session.
//
//	dev := oauthdevice.New("https://app.example.com/auth/device/code")
//	dp := deviceauth.New(deviceauth.WithGrant(dev))
//	op := oauthprovider.New(jw, oauthprovider.WithGrant(dev.ExtensionGrant()),
//		oauthprovider.DeviceAuthorizationEndpoint(dev.Endpoint()))
//	auth.WithPlugins(..., dp, op, dev)
//
// At /device/code a client the provider knows is authenticated as at its
// token endpoint (client_secret_basic, client_secret_post, private_key_jwt,
// or none for a public client), must have registered the device grant, and
// may ask only for scopes and a resource it is allowed. Its codes are bound
// to the grant: they are redeemed only at the provider's token endpoint,
// never for a session at /device/token. A client id the provider does not
// know falls through to deviceauth's standalone flow and its
// ValidateClient, as better-auth's does.
package oauthdevice

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/deviceauth"
	"github.com/ubgo/auth/plugin/oauthprovider"
)

// PluginName is the plugin's permanent identity.
const PluginName = "oauthdevice"

// GrantName is the name codes bound by this grant carry.
const GrantName = "oauth"

// errorNamespace is the code prefix the provider strips on the wire, so
// the codes below answer their RFC 8628 names.
const errorNamespace = "oauthdevice"

// Wire errors of the token endpoint, under errorNamespace: the provider
// answers "authorization_pending", "slow_down", "expired_token" and
// "access_denied" for them (RFC 8628 §3.5).
var (
	ErrAuthorizationPending = auth.NewError(errorNamespace+".authorization_pending", http.StatusBadRequest, "The user has not approved the request yet.")
	ErrSlowDown             = auth.NewError(errorNamespace+".slow_down", http.StatusBadRequest, "Polling too often. Wait longer between requests.")
	ErrExpiredToken         = auth.NewError(errorNamespace+".expired_token", http.StatusBadRequest, "The device code has expired.")
	ErrAccessDenied         = auth.NewError(errorNamespace+".access_denied", http.StatusBadRequest, "The user denied the request.")
)

// ErrNoEndpoint is a configuration error: New needs the absolute URL of the
// device authorization endpoint (the assertion audience and the discovery
// value).
var ErrNoEndpoint = errors.New("oauthdevice: New needs the absolute URL of /device/code")

// Integration joins the two plugins. Build it with New, pass it to
// deviceauth.WithGrant and its ExtensionGrant to oauthprovider.WithGrant,
// and register it beside both.
type Integration struct {
	endpoint string
	device   *deviceauth.Plugin
	provider *oauthprovider.Plugin
}

// Compile-time proof of each capability.
var (
	_ deviceauth.Grant = (*Integration)(nil)
	_ auth.Initializer = (*Integration)(nil)
	_ auth.Validator   = (*Integration)(nil)
	_ auth.Dependent   = (*Integration)(nil)
)

// New builds the integration for the device authorization endpoint at
// endpoint.
func New(endpoint string) *Integration { return &Integration{endpoint: endpoint} }

// Name returns PluginName.
func (g *Integration) Name() string { return PluginName }

// Requires names both plugins.
func (g *Integration) Requires() []string {
	return []string{deviceauth.PluginName, oauthprovider.PluginName}
}

// Validate refuses a relative endpoint.
func (g *Integration) Validate(*auth.Config) error {
	u, err := url.Parse(g.endpoint)
	if err != nil || !u.IsAbs() || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return ErrNoEndpoint
	}
	return nil
}

// Init finds both plugins. Requires has the core refuse a missing one
// before Init runs, so neither lookup fails in practice; both errors are
// still returned rather than assumed away.
func (g *Integration) Init(a *auth.Auth) error {
	var errDevice, errProvider error
	g.device, errDevice = auth.PluginOf[*deviceauth.Plugin](a)
	g.provider, errProvider = auth.PluginOf[*oauthprovider.Plugin](a)
	return errors.Join(errDevice, errProvider)
}

// Endpoint is the device authorization endpoint's URL, for
// oauthprovider.DeviceAuthorizationEndpoint.
func (g *Integration) Endpoint() string { return g.endpoint }

// ExtensionGrant is the device_code grant for oauthprovider.WithGrant.
//
//ds:def id=oauthdevice-extensiongrant-8k2wq5vn owner=@khanakia stability=stable
func (g *Integration) ExtensionGrant() oauthprovider.ExtensionGrant {
	return oauthprovider.ExtensionGrant{Type: deviceauth.GrantType, Handle: g.redeem, ErrorNamespace: errorNamespace}
}

// wireError carries an RFC code for deviceauth's RFC handlers, and unwraps
// to the provider's coded error for the library's JSON.
type wireError struct {
	err  error
	code string
}

func (e wireError) Error() string   { return e.err.Error() }
func (e wireError) Unwrap() error   { return e.err }
func (e wireError) RFCCode() string { return e.code }

// providerCodes maps the provider's refusals to their RFC codes.
var providerCodes = []struct {
	err  error
	code string
}{
	{oauthprovider.ErrInvalidClient, "invalid_client"},
	{oauthprovider.ErrInvalidRequest, "invalid_request"},
	{oauthprovider.ErrInvalidScope, "invalid_scope"},
	{oauthprovider.ErrInvalidTarget, "invalid_target"},
	{oauthprovider.ErrUnauthorizedClient, "unauthorized_client"},
}

// wire wraps a provider error with its RFC code.
func wire(err error) error {
	for _, m := range providerCodes {
		if errors.Is(err, m.err) {
			return wireError{err: err, code: m.code}
		}
	}
	return err
}

// AuthorizeCode authorizes a /device/code request for a client the
// provider knows, and leaves any other to the standalone flow.
func (g *Integration) AuthorizeCode(ctx context.Context, c *auth.Call, in deviceauth.CodeRequest) (deviceauth.Binding, error) {
	cred, err := credentials(c.Header("Authorization"), in)
	if err != nil {
		return deviceauth.Binding{}, wire(err)
	}
	if cred.ID == "" {
		return deviceauth.Binding{}, deviceauth.ErrInvalidRequest
	}
	if _, err := g.provider.Client(ctx, cred.ID); err != nil {
		if errors.Is(err, oauthprovider.ErrClientNotFound) {
			return deviceauth.Binding{}, nil
		}
		return deviceauth.Binding{}, err
	}
	client, err := g.provider.AuthenticateClient(ctx, cred, g.endpoint)
	if err != nil {
		return deviceauth.Binding{}, wire(err)
	}
	if !contains(client.GrantTypes, deviceauth.GrantType) {
		return deviceauth.Binding{}, wire(oauthprovider.ErrUnauthorizedClient)
	}
	scopes := strings.Fields(in.Scope)
	if len(scopes) == 0 {
		scopes = strings.Fields(client.Scope)
	}
	// The registry decides here as at the token step (which checks again,
	// in case the resource or the link changed while the user approved):
	// the stored scope is the narrowed one, so approval shows what will be
	// granted.
	scopes, err = g.provider.CheckScopes(ctx, client, scopes, in.Resource)
	if err != nil {
		return deviceauth.Binding{}, wire(err)
	}
	return deviceauth.Binding{Grant: GrantName, Resource: in.Resource, Scope: strings.Join(scopes, " ")}, nil
}

// redeem is the token endpoint's device_code grant.
func (g *Integration) redeem(ctx context.Context, client oauthprovider.Client, in oauthprovider.TokenRequest) (oauthprovider.GrantDecision, error) {
	red, err := g.device.Redeem(ctx, in.DeviceCode, client.ClientID, GrantName)
	switch {
	case err == nil:
		return oauthprovider.GrantDecision{UserID: red.UserID, Scopes: strings.Fields(red.Scope), Resource: red.Resource}, nil
	case errors.Is(err, deviceauth.ErrAuthorizationPending):
		return oauthprovider.GrantDecision{}, ErrAuthorizationPending
	case errors.Is(err, deviceauth.ErrPollingTooFrequently):
		return oauthprovider.GrantDecision{}, ErrSlowDown
	case errors.Is(err, deviceauth.ErrExpiredDeviceCode):
		return oauthprovider.GrantDecision{}, ErrExpiredToken
	case errors.Is(err, deviceauth.ErrAccessDenied):
		return oauthprovider.GrantDecision{}, ErrAccessDenied
	case errors.Is(err, deviceauth.ErrInvalidRequest):
		return oauthprovider.GrantDecision{}, oauthprovider.ErrInvalidRequest
	case errors.Is(err, deviceauth.ErrInvalidDeviceCode), errors.Is(err, deviceauth.ErrServerError):
		return oauthprovider.GrantDecision{}, oauthprovider.ErrInvalidGrant
	}
	return oauthprovider.GrantDecision{}, err
}

// credentials reads the client's credentials as the provider's token
// endpoint does: a private_key_jwt assertion, an Authorization: Basic
// header (form-encoded parts), a client_secret in the body, or a client_id
// alone. Two methods at once is invalid_request.
func credentials(header string, in deviceauth.CodeRequest) (oauthprovider.ClientCredentials, error) {
	if in.ClientAssertion != "" || in.ClientAssertionType != "" {
		if header != "" || in.ClientSecret != "" {
			return oauthprovider.ClientCredentials{}, oauthprovider.ErrInvalidRequest
		}
		if in.ClientAssertionType != oauthprovider.ClientAssertionType || in.ClientAssertion == "" {
			return oauthprovider.ClientCredentials{}, oauthprovider.ErrInvalidClient
		}
		return oauthprovider.ClientCredentials{ID: in.ClientID, Method: oauthprovider.AuthMethodPrivateKeyJWT, Assertion: in.ClientAssertion}, nil
	}
	if header == "" {
		cred := oauthprovider.ClientCredentials{ID: in.ClientID, Secret: in.ClientSecret, Method: oauthprovider.AuthMethodNone}
		if cred.Secret != "" {
			cred.Method = oauthprovider.AuthMethodPost
		}
		return cred, nil
	}
	scheme, rest, _ := strings.Cut(header, " ")
	if !strings.EqualFold(scheme, "Basic") {
		return oauthprovider.ClientCredentials{}, oauthprovider.ErrInvalidClient
	}
	if in.ClientSecret != "" {
		return oauthprovider.ClientCredentials{}, oauthprovider.ErrInvalidRequest
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest))
	if err != nil {
		return oauthprovider.ClientCredentials{}, oauthprovider.ErrInvalidClient
	}
	encID, encSecret, ok := strings.Cut(string(raw), ":")
	id, err1 := url.QueryUnescape(encID)
	secret, err2 := url.QueryUnescape(encSecret)
	if !ok || err1 != nil || err2 != nil {
		return oauthprovider.ClientCredentials{}, oauthprovider.ErrInvalidClient
	}
	if in.ClientID != "" && in.ClientID != id {
		return oauthprovider.ClientCredentials{}, oauthprovider.ErrInvalidRequest
	}
	return oauthprovider.ClientCredentials{ID: id, Secret: secret, Method: oauthprovider.AuthMethodBasic}, nil
}

// contains reports whether list holds s.
func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
