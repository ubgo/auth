package authtest

import (
	"context"
	"net/http"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

// Session is a signed-in session for a test, in every form a request can
// carry it: a cookie, a bearer header, or a Go context. It comes from
// Env.SignIn; the raw token is in Token for a test that builds its own
// request.
//
//ds:def id=authtest-session-9fn3qk7t owner=@khanakia stability=stable
type Session struct {
	env *Env
	// Session is the row as the core created it.
	Session auth.Session
	// Token is the raw session token.
	Token auth.Token
}

// Client is the client a session created by SignIn records: a documentation
// address and a user agent that names the harness.
var client = auth.Client{IP: "203.0.113.1", UserAgent: "authtest"}

// SignIn creates a session for userID through the core, the way a sign-in
// plugin does after it checked a credential, so a user's second factor
// still applies: a user who must pass one gets a pending session. For a
// test that needs the whole sign-in flow, call the plugin's operation.
//
//ds:def id=authtest-signin-5tw8mn2c owner=@khanakia stability=stable
func (e *Env) SignIn(userID string) *Session {
	e.T.Helper()
	s, tok, err := e.Auth.CreateSession(context.Background(), userID, client)
	if err != nil {
		e.T.Fatalf("authtest: sign in %s: %v", userID, err)
	}
	return &Session{env: e, Session: s, Token: tok}
}

// Cookie returns the session cookie a browser would hold: the name the
// net/http transport reads, Secure, path /.
func (s *Session) Cookie() *http.Cookie {
	return &http.Cookie{Name: authhttp.CookieName, Value: s.Token.Reveal(), Path: "/", Secure: true, HttpOnly: true}
}

// bearerPrefix is the Authorization scheme the net/http transport reads.
const bearerPrefix = "Bearer "

// Authorization returns the header value a bearer client sends.
func (s *Session) Authorization() string { return bearerPrefix + s.Token.Reveal() }

// Apply adds the session cookie to req, and the Origin a page of the app
// sends, so a mutation passes the origin check.
func (s *Session) Apply(req *http.Request) {
	req.AddCookie(s.Cookie())
	req.Header.Set(headerOrigin, s.env.BaseURL)
}

// ApplyBearer adds the session as an Authorization header, the way an app
// without cookies sends it; no Origin is needed for a bearer credential.
func (s *Session) ApplyBearer(req *http.Request) {
	req.Header.Set(headerAuthorization, s.Authorization())
}

// Context returns ctx as a request from a browser holding the session, so a
// Go call (a.SignOut(ctx), a plugin's typed method) runs as the signed-in
// user with the effects recorded on it; auth.RequestEffects reads them.
//
//ds:def id=authtest-sessioncontext-7hq4rv2x owner=@khanakia stability=stable
func (s *Session) Context(ctx context.Context) context.Context {
	return s.env.request(ctx, auth.CredentialCookie, s.Token)
}

// BearerContext is Context with the token presented as a bearer credential,
// which the origin check leaves alone and the session policy treats as an
// app.
func (s *Session) BearerContext(ctx context.Context) context.Context {
	return s.env.request(ctx, auth.CredentialBearer, s.Token)
}

// Anonymous returns ctx as a signed-out browser request from the app's own
// origin: what a public operation (sign-in, forgot password) sees.
//
//ds:def id=authtest-anonymous-3gk6xp9w owner=@khanakia stability=stable
func (e *Env) Anonymous(ctx context.Context) context.Context {
	return e.request(ctx, auth.CredentialNone, "")
}

// request builds the request every Context method shares.
func (e *Env) request(ctx context.Context, cred auth.Credential, tok auth.Token) context.Context {
	c := client
	c.Origin = e.BaseURL
	return e.Auth.WithRequest(ctx, auth.Request{Transport: auth.TransportHTTP, Client: c, Credential: cred, Token: tok})
}

// Request header names the harness sets.
const (
	headerOrigin        = "Origin"
	headerAuthorization = "Authorization"
)
