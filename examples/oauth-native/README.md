# OAuth: native sign-in, an error page, flow data and provider logout

The OAuth features a native app and a polished web app need once the redirect dance works: a phone app signing in with the provider's ID token instead of a browser; a failed callback landing on the sign-in page with the error code instead of a JSON body; a referral code carried through the flow and read in a hook; and a sign-out that ends the session at the provider too.

It needs no provider account. A small OpenID Connect issuer for development runs in the same process on `http://localhost:8083`: discovery (with `jwks_uri` and `end_session_endpoint`), a key set, an authorize endpoint that consents at once, a token endpoint that returns an ID token signed with the issuer's key, userinfo, an end-session endpoint, and `/mint`, which stands in for a native SDK handing the app an ID token for the issuer's "iOS" client id.

## Run it

```sh
cd examples
go run ./oauth-native
```

It creates `oauth-native.db` (SQLite) and serves the app on `http://localhost:8081`. Set `TOKEN_KEY` to 32 bytes (base64url, no padding) to keep the stored ID token readable across restarts; unset, a key is generated and the log says so. Run the tests with `go test ./oauth-native`.

```text
2026/10/02 21:48:53 TOKEN_KEY is not set: sealing provider tokens with a new key; tokens stored before a restart will not open
2026/10/02 21:48:53 issuer listening on http://localhost:8083, signing in idp-1 <carol@example.com>; GET http://localhost:8083/mint?nonce=… mints an ID token like a native SDK
2026/10/02 21:48:53 app listening on http://localhost:8081; callback URL http://localhost:8081/auth/oauth/corp/callback
```

## Walkthrough

### A native app signs in with an ID token

On a phone the provider's SDK signs the person in and hands the app an ID token; the issuer's `/mint` route plays that part here, with the nonce the app chose. The app posts the token in bearer mode and gets a session token in a header, with no browser and no redirect.

```sh
TOKEN=$(curl -s 'localhost:8083/mint?nonce=n-1' | sed -E 's/.*"id_token":"([^"]+)".*/\1/')
curl -si -X POST localhost:8081/auth/oauth/corp/id-token -H 'Auth-Token-Mode: bearer' -d "{\"idToken\":\"$TOKEN\",\"nonce\":\"n-1\"}"
```

```text
HTTP/1.1 200 OK
Content-Type: application/json
Set-Auth-Token: 7omD4mSXqh9L1JLomDwytpy6LbAy45qC8OVaPdcoBIY
Set-Auth-Token-Expires: 2026-10-09T16:18:53Z
Date: Fri, 02 Oct 2026 16:18:53 GMT
Content-Length: 158

{"user":{"id":"usr_2xabw53wt57njnijguzc2ojf","name":"Carol","image":""},"created":true,"linked":false,"redirectTo":"","secondFactorRequired":false,"data":""}
```

The same subject signing in again is the same user. A wrong nonce, a forged signature, an expired token and a token for another audience all answer one code:

```sh
curl -s -X POST localhost:8081/auth/oauth/corp/id-token -d "{\"idToken\":\"$TOKEN\",\"nonce\":\"other\"}"
{"error":{"code":"oauth.id_token_invalid","message":"The sign-in token was not accepted."}}
curl -s -X POST localhost:8081/auth/oauth/corp/id-token -d "{\"idToken\":\"${TOKEN%????}AAAA\",\"nonce\":\"n-1\"}"   # one byte of the signature changed
{"error":{"code":"oauth.id_token_invalid","message":"The sign-in token was not accepted."}}
```

### A failed callback lands on the sign-in page

The plugin is wired with `oauth.ErrorURL("/sign-in")`, so a provider that refuses, or a callback opened in a browser that never started the flow, redirects there with the error code instead of answering JSON:

```sh
curl -si 'localhost:8081/auth/oauth/corp/callback?error=access_denied&state=x'
HTTP/1.1 302 Found
Location: /sign-in?error=oauth.denied
Date: Fri, 02 Oct 2026 16:18:53 GMT
Content-Length: 0

curl -si 'localhost:8081/auth/oauth/corp/callback?code=the-code&state=stale'
HTTP/1.1 302 Found
Location: /sign-in?error=oauth.state_invalid
Date: Fri, 02 Oct 2026 16:18:53 GMT
Content-Length: 0
```

### A referral code travels through the flow

The sign-in link carries `data=ref%3Dfriend-42`. It travels in the state row, comes back in `CallbackResult.Data`, and the app reads it in an After hook on the callback operation, the one place an app sees a callback's result over HTTP. Carol already signed in natively above, so this flow reaches her existing account (`created: false`):

```sh
curl -si -c ck.txt 'localhost:8081/auth/oauth/corp/start?returnTo=/me&data=ref%3Dfriend-42'
HTTP/1.1 302 Found
Location: http://localhost:8083/authorize?client_id=dev-client&code_challenge=o1m0oWGTOVbAPjtf615BQU56i0hGxMnTsrT7z0GyS98&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A8081%2Fauth%2Foauth%2Fcorp%2Fcallback&response_type=code&scope=openid+email+profile&state=Uy8LV6Ss_ThxV_WlHMH3YmYOEbYoZOqFlLtDmmY4dsk
Set-Cookie: __Host-auth_flow=Uy8LV6Ss_ThxV_WlHMH3YmYOEbYoZOqFlLtDmmY4dsk; Path=/; Expires=Fri, 02 Oct 2026 16:28:53 GMT; HttpOnly; Secure; SameSite=Lax
Date: Fri, 02 Oct 2026 16:18:53 GMT
Content-Length: 0

curl -si 'http://localhost:8083/authorize?client_id=dev-client&code_challenge=o1m0oWGTOVbAPjtf615BQU56i0hGxMnTsrT7z0GyS98&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A8081%2Fauth%2Foauth%2Fcorp%2Fcallback&response_type=code&scope=openid+email+profile&state=Uy8LV6Ss_ThxV_WlHMH3YmYOEbYoZOqFlLtDmmY4dsk'   # the issuer consents at once
HTTP/1.1 302 Found
Location: http://localhost:8081/auth/oauth/corp/callback?code=the-code&state=Uy8LV6Ss_ThxV_WlHMH3YmYOEbYoZOqFlLtDmmY4dsk

curl -si -b ck.txt -c ck.txt 'http://localhost:8081/auth/oauth/corp/callback?code=the-code&state=Uy8LV6Ss_ThxV_WlHMH3YmYOEbYoZOqFlLtDmmY4dsk'
HTTP/1.1 302 Found
Location: /me
Set-Cookie: __Host-auth_flow=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax
Set-Cookie: __Host-auth_session=lgEZWN66zocgnREgH8RVc7wjQcfYzbfGzOo25nU6c5I; Path=/; Expires=Fri, 09 Oct 2026 16:18:53 GMT; HttpOnly; Secure; SameSite=Lax
Date: Fri, 02 Oct 2026 16:18:53 GMT
Content-Length: 0

curl -s -b ck.txt localhost:8081/me
{"id":"usr_2xabw53wt57njnijguzc2ojf","name":"Carol"}
```

```text
2026/10/02 21:48:53 user usr_2xabw53wt57njnijguzc2ojf (created: false) arrived with data "ref=friend-42"
```

### Sign out here and at the provider

`POST /auth/oauth/corp/logout` ends the session here first, then sends the browser to the issuer's `end_session_endpoint` with the stored ID token as `id_token_hint`, the client id and the post-logout URL (the base URL by default; `oauth.PostLogoutURL` changes it, and it must be registered at the provider). The issuer ends its own session and sends the browser home.

```sh
2026/10/02 21:48:53 user usr_2xabw53wt57njnijguzc2ojf (created: false) arrived with data "ref=friend-42"OUT
```

## What it shows

- `oauth.OIDC` picks up `jwks_uri` and `end_session_endpoint` from discovery, so ID-token sign-in and provider logout need no extra field; `IDToken.Audiences` adds the native client id.
- The ID token is verified (signature against the key set, issuer, audience, lifetime, nonce) before anyone is signed in; every refusal is `401 oauth.id_token_invalid`, and the log says why.
- `oauth.ErrorURL` turns callback errors into a redirect with `?error=<code>`; the id-token route, an API, keeps answering the error itself.
- `StartRequest.Data` is untrusted client input: the hook logs it, a real app would validate it before acting.
- The logout's local sign-out does not depend on the provider: a provider that is down answers `502 oauth.provider_failed` and the session is still ended.

## Files

- `main.go`: the app, its routes and the hook.
- `issuer.go`: the development issuer.
- `main_test.go`: the four flows above, end to end.
