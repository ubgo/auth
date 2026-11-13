// Package oidcclient signs people in to a Go web app through any OpenID
// Connect server (ubgo/auth's plugin/oauthprovider, Google, Keycloak, Entra)
// and keeps them signed in for days, while the login server keeps the final
// say on every request.
//
// The model has two clocks. The session lives long (Lifetimes: 7 days idle,
// 30 days absolute by default), so closing the browser does not sign anyone
// out. The login server is asked again at most every recheck interval (1
// minute by default) while the person is active, by refreshing the token
// (or by introspection, userinfo, or back-channel logout alone). A "no"
// from the server ends the session at the next request, whatever cookie
// the browser still holds; a copy of an old cookie is worth nothing once
// the server refuses its refresh token.
//
// The minimal setup is New with a Config, then mounting Client.Handler for
// the login, callback, logout and back-channel routes and wrapping the
// app's handlers with Client.Require. Every policy (session storage,
// sealing, user mapping, authorization, the re-check method, the outage
// grace, lifetimes, responses, return URLs, cookies, routes and plumbing)
// is one typed option with a safe default. The protocol floors (PKCE S256,
// state, nonce, the ID token signature under an allow-listed algorithm,
// iss, aud, exp and azp, constant-time comparisons, same-site return URLs,
// hook errors failing closed) have no option at all: there is nothing to
// turn off.
//
// The package depends only on the Go standard library, so an app that
// imports it downloads nothing else. DESIGN.md beside this file explains
// the request lifecycle and why each seam has the shape it has.
package oidcclient
