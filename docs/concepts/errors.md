# Errors

Every error a client can see has a stable code, an HTTP status and a message for people. This page explains how errors travel from an operation to a response, how to match them in Go, and lists every code the library and its plugins return.

## Before you start

- A client matches the **code**, never the message: messages are for end users and may be reworded or translated. The status is what HTTP answers.
- An error that is not one of these — a database failure, a bug — is answered as `auth.internal` (500) with no detail, on purpose: its text could contain SQL, a table name or a value. The transport logs the original.

## Step 1 — The shape on the wire

Every transport answers the same JSON, with the status from the error:

```json
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

A rate-limited answer also carries `Retry-After` in whole seconds. The shape is `auth.ErrorInfo`; `auth.ErrorOf` produces it from any error, and `authhttp.WriteError` writes it. The envelope is replaceable: an API with its own error contract (RFC 9457 `application/problem+json`, a house shape) passes [`authhttp.EncodeErrors(enc)`](ds:block?id=authhttp-encodeerrors-2hv7kc4p) to `Handler`, `Middleware` and the gin, echo and fiber adapters, and every error body is then the encoder's; the status and `Retry-After` stay the library's. See [net/http, Step 7](../integrations/net-http.md#step-7--know-the-error-json).

<!-- ds:block id=core-errorinfo-wjvs3c6f -->
**ErrorInfo** · [`errorcode.go:114-124`](../../errorcode.go#L114-L124)

```go
type ErrorInfo struct {
	Code    string `json:"code"`
	Status  int    `json:"-"`
	Message string `json:"message"`
	// OriginalMessage is the declared English message when Message was
	// translated by the WithMessages catalogue, as better-auth's i18n plugin
	// answers it, so a log or a support screen can show the text the
	// reference documents; empty (and left out of the JSON) when Message is
	// the declared one.
	OriginalMessage string `json:"originalMessage,omitempty"`
}
```
<!-- /ds:block hash=fd704f -->

<!-- ds:block id=core-errorof-pdarrq6t -->
**ErrorOf** · [`errorcode.go:135-141`](../../errorcode.go#L135-L141)

```go
func ErrorOf(err error) ErrorInfo {
	var e *Error
	if errors.As(err, &e) {
		return ErrorInfo{Code: e.Code, Status: e.Status, Message: e.Message}
	}
	return ErrorInfo{Code: ErrInternal.Code, Status: ErrInternal.Status, Message: ErrInternal.Message}
}
```
<!-- /ds:block hash=719f55 -->

<!-- ds:block id=authhttp-writeerror-bdjg7zqy -->
**WriteError** · [`authhttp/authhttp.go:1568-1572`](../../authhttp/authhttp.go#L1568-L1572)

```go
func WriteError(w http.ResponseWriter, err error) {
	SetRetryAfter(w, err)
	info := auth.ErrorOf(err)
	writeJSON(w, info.Status, errorBody{Error: info})
}
```
<!-- /ds:block hash=e17a3d -->

## Step 2 — Match errors in Go

Errors are `*auth.Error` values made with `auth.NewError`. `errors.Is` matches by code, so a wrapped error (`fmt.Errorf("sign-up: %w", err)`) still matches its sentinel:

<!-- ds:block id=core-error-u6547ehr -->
**Error** · [`errorcode.go:26-30`](../../errorcode.go#L26-L30)

```go
type Error struct {
	Code    string
	Status  int
	Message string
}
```
<!-- /ds:block hash=0bb5f3 -->

<!-- ds:block id=core-error-is-czm58ubw -->
**Error.Is** · [`errorcode.go:103-109`](../../errorcode.go#L103-L109)

```go
func (e *Error) Is(target error) bool {
	var t *Error
	if !errors.As(target, &t) {
		return false
	}
	return t.Code == e.Code
}
```
<!-- /ds:block hash=d863b0 -->

An app handler that calls the typed Go API matches the result with `errors.Is` and answers in its own shape. This one, from `examples/translated-errors`, keeps the message in the user's language through `a.ErrorInfo`, and logs only what is not a client error:

<!-- ds:block id=translated-errors-errors-is-handler-rpcnvudj -->
**login** · [`examples/translated-errors/main.go:249-270`](../../examples/translated-errors/main.go#L249-L270)

```go
func login(a *auth.Auth, pw *password.Plugin) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in loginRequest
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeJSON(w, http.StatusBadRequest, loginAnswer{Reason: reasonBadRequest})
			return
		}
		res, err := pw.SignIn(r.Context(), password.SignInRequest{Identifier: in.Email, Password: password.Secret(in.Password)})
		msg := a.ErrorInfo(r.Context(), err).Message
		switch {
		case err == nil:
			writeJSON(w, http.StatusOK, loginAnswer{OK: true, UserID: res.User.ID})
		case errors.Is(err, password.ErrInvalidCredentials):
			writeJSON(w, http.StatusUnauthorized, loginAnswer{Reason: reasonWrongPassword, Message: msg})
		case errors.Is(err, auth.ErrRateLimited):
			writeJSON(w, http.StatusTooManyRequests, loginAnswer{Reason: reasonSlowDown, Message: msg})
		default:
			log.Printf("sign-in failed: %v", err) // the log is the only record of an internal error's detail
			writeJSON(w, auth.ErrorOf(err).Status, loginAnswer{Reason: reasonFailed, Message: msg})
		}
	}
}
```
<!-- /ds:block hash=ec764f -->

`auth.RetryAfter(err)` reads the wait out of a rate-limit error when the handler wants to say how long. Try it, with a wrong password and then the right one:

```sh
curl -s -X POST localhost:8096/api/login -H 'Origin: http://localhost:8096' -H 'Accept-Language: de' \
  -d '{"email":"alice@example.com","password":"wrong password!!"}'
curl -s -c cookies.txt -X POST localhost:8096/api/login -H 'Origin: http://localhost:8096' \
  -d '{"email":"alice@example.com","password":"correct horse battery staple"}'
```

```json
{"ok":false,"reason":"wrong_password","message":"E-Mail-Adresse oder Passwort stimmen nicht. Versuchen Sie es noch einmal."}
{"ok":true,"userId":"usr_2rycv5oncrpapwcjfregt3kc"}
```

Check: `TestLogin_AppHandlerMatchesErrorsIs` and `TestErrorsIs_MatchesByCode` in `examples/translated-errors`; the second shows a copy of a declared error made with `auth.NewError` and the same code matching the sentinel.

Your own handler answers an error with `authhttp.WriteError(w, err)`, which picks the status and sets `Retry-After`; an error that is not an `*auth.Error` becomes `auth.internal`.

## Step 3 — Translate the messages

The code is the contract and the message is presentation, so a message can be rendered in the user's language without any plugin knowing about languages. `auth.WithMessages(catalogue)` sets a `MessageCatalog`; `auth.Messages` is one held in memory, a map of locale tag, then code, then text, which is exactly the shape a JSON translation file unmarshals into. The lookup is the exact tag, then its base language (`de-CH` falls back to `de`), compared without regard to case, so one `de` block serves every German-speaking region and a `de-CH` entry overrides a single code. A locale or a code the catalogue lacks gets the declared English text; the code and the status never change.

<!-- ds:block id=core-messages-2hv8kr4m -->
**Messages** · [`messages.go:38`](../../messages.go#L38-L38)

```go
type Messages map[string]map[string]string
```
<!-- /ds:block hash=51fe0d -->

<!-- ds:block id=opt-withmessages-9kd4ht7p -->
**WithMessages** · [`messages.go:68-75`](../../messages.go#L68-L75)

```go
func WithMessages(c MessageCatalog) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithMessages", c) {
			return
		}
		s.messages = c
	}
}
```
<!-- /ds:block hash=b617a6 -->

The request's locale is `Client.Locale`, which `authhttp` fills from `Accept-Language` or the locale cookie, then `auth.WithDefaultLocale`; `a.Locale(ctx)` is that one rule, shared with the templates of mail and SMS. A transport renders an error with `auth.ErrorInfoFor(ctx, err)`, which is `ErrorOf` plus the translation when the request has one; with no request in the context it is `ErrorOf`. `authhttp` does this in `WriteErrorFor(w, r, err)`, which `Handler`, `Middleware` and `RequireFunc` answer through; `WriteError(w, err)` stays English for a handler with no request.

<!-- ds:block id=core-locale-5mz7wq3n -->
**Auth.Locale** · [`messages.go:102-111`](../../messages.go#L102-L111)

```go
func (a *Auth) Locale(ctx context.Context) string {
	st := stateFrom(ctx)
	if l := a.storedLocale(ctx, st); l != "" {
		return l
	}
	if st != nil && st.req.Client.Locale != "" {
		return st.req.Client.Locale
	}
	return a.defaultLocale
}
```
<!-- /ds:block hash=839815 -->

<!-- ds:block id=core-auth-errorinfo-3xn6pv8q -->
**Auth.ErrorInfo** · [`messages.go:165-174`](../../messages.go#L165-L174)

```go
func (a *Auth) ErrorInfo(ctx context.Context, err error) ErrorInfo {
	info := ErrorOf(err)
	if a.messages == nil {
		return info
	}
	if msg, ok := a.messages.Message(a.Locale(ctx), info.Code); ok && msg != info.Message {
		info.OriginalMessage, info.Message = info.Message, msg
	}
	return info
}
```
<!-- /ds:block hash=f19e07 -->

<!-- ds:block id=core-errorinfofor-8tq2wm5c -->
**ErrorInfoFor** · [`messages.go:195-200`](../../messages.go#L195-L200)

```go
func ErrorInfoFor(ctx context.Context, err error) ErrorInfo {
	if st := stateFrom(ctx); st != nil && st.a != nil {
		return st.a.ErrorInfo(ctx, err)
	}
	return ErrorOf(err)
}
```
<!-- /ds:block hash=22d749 -->

```json
{"de": {"auth.signed_out": "Bitte anmelden.", "auth.rate_limited": "Zu viele Versuche. Warten Sie einen Moment."},
 "de-CH": {"auth.signed_out": "Bitte anmelde."}}
```

Ready translations ship in [`github.com/ubgo/auth/i18n`](../../i18n/README.md): every code in the 21 languages better-auth's i18n plugin ships beside English (Arabic, Bengali, German, Spanish, Persian, French, Hindi, Indonesian, Italian, Japanese, Korean, Dutch, Polish, Portuguese, Russian, Swedish, Thai, Turkish, Ukrainian, Vietnamese, Chinese), as one `auth.Messages`: `auth.WithMessages(i18n.Messages())`, or `i18n.MessagesFor("de", "fr")` for a few. The map is fresh on every call, so an app overrides any entry in its own voice before passing it. To write your own, start from [`reference/error-codes.json`](../reference/error-codes.json): every code with its English message.

A translated answer also carries the declared English text as `originalMessage`, as better-auth's i18n plugin answers, so a log or a support screen shows the message this page documents; an untranslated answer leaves the field out:

```json
{"error":{"code":"auth.signed_out","message":"Bitte anmelden.","originalMessage":"Sign in to continue."}}
```

Check: with the catalogue above, `GET /auth/session` without a cookie and `Accept-Language: de-AT` answers `{"error":{"code":"auth.signed_out","message":"Bitte anmelden."}}` and status 401; with `Accept-Language: fr` the message is the English one.

### Replace one message with your own wording

`i18n.Messages()` returns a fresh map, so the app edits it before passing it. Key the entry by the error's declared `Code`, never a typed string, so a typo cannot leave the override unused:

<!-- ds:block id=translated-errors-catalog-override-4yx294mh -->
**messages** · [`examples/translated-errors/main.go:142-146`](../../examples/translated-errors/main.go#L142-L146)

```go
func messages() auth.Messages {
	m := i18n.Messages()
	m[localeGerman][password.ErrInvalidCredentials.Code] = ourWrongPasswordDE
	return m
}
```
<!-- /ds:block hash=ff3341 -->

Try it: the same wrong password with no language, with `de` (the override) and with `fr-CA` (no entry of its own, so the shipped French):

```json
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
{"error":{"code":"password.invalid_credentials","message":"E-Mail-Adresse oder Passwort stimmen nicht. Versuchen Sie es noch einmal.","originalMessage":"The sign-in details are not right."}}
{"error":{"code":"password.invalid_credentials","message":"Les identifiants de connexion sont incorrects.","originalMessage":"The sign-in details are not right."}}
```

Check: `TestErrors_FollowTheRequestLanguage` in `examples/translated-errors`.

### Pick the language: WithDefaultLocale and WithUserLocale

Use these when the language must not depend on the browser alone: a user who chose German in their settings should get German errors and mail on any device, and an app whose users mostly share one language wants it for requests that name none. The locale of a request is the first of these that gives one:

1. The user's stored language, from the `WithUserColumns` text column named by [`auth.WithUserLocale(column)`](ds:block?id=opt-withuserlocale-6kq2wn8x). It is read once the session is resolved, so it never applies to a signed-out request or to the session lookup's own error; an empty or malformed value is skipped.
2. `authhttp.LocaleFunc`, a rule of the app's own, when given.
3. The locale cookie, when `authhttp.LocaleCookie` is given ([`auth_locale`](ds:block?id=authhttp-defaultlocalecookiename-4hpr8wnz) by default), which an app's language picker sets.
4. The first tag of `Accept-Language`.
5. [`auth.WithDefaultLocale(tag)`](ds:block?id=opt-withdefaultlocale-5wc4ae9h).
6. Nothing: the declared English message.

The same locale picks mail and SMS templates: [`email.TemplatesByLocale`](ds:block?id=templatesbylocale-mexdnb77) maps a language to a template function, and a language with none gets the plugin's English:

<!-- ds:block id=translated-errors-german-mail-56uy8n8b -->
**germanMail** · [`examples/translated-errors/main.go:334-346`](../../examples/translated-errors/main.go#L334-L346)

```go
func germanMail(m auth.Message) (subject, text string) {
	if m.Purpose == auth.PurposeVerify {
		return "Bitte bestätigen Sie Ihre E-Mail-Adresse", "Öffnen Sie diesen Link, um die Adresse zu bestätigen:\n\n" + m.Link + "\n"
	}
	text = "Eine Nachricht zu Ihrem Konto.\n"
	if m.Link != "" {
		text += "\nLink: " + m.Link + "\n"
	}
	if m.Code != "" {
		text += "\nCode: " + m.Code + "\n"
	}
	return "Eine Nachricht zu Ihrem Konto", text
}
```
<!-- /ds:block hash=7f62df -->

`examples/translated-errors` wires all of it:

<!-- ds:block id=translated-errors-newauth-w57j7swr -->
**newAuth** · [`examples/translated-errors/main.go:154-169`](../../examples/translated-errors/main.go#L154-L169)

```go
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.Multiple(), email.WithMailer(m),
				email.TemplatesByLocale(map[string]email.TemplateFunc{localeGerman: germanMail})),
			password.New(),
			magiclink.New(magiclink.VerifyByGET()),
		),
		auth.WithMessages(messages()),
		auth.WithUserColumns(localeColumn),
		auth.WithUserLocale(colLocale),
		auth.WithErrorURL(authPrefix+authhttp.ErrorPagePath),
	)
}
```
<!-- /ds:block hash=e8c61d -->

<!-- ds:block id=translated-errors-locale-column-sk97jqwe -->
**localeColumn** · [`examples/translated-errors/main.go:125`](../../examples/translated-errors/main.go#L125-L125)

```go
var localeColumn = auth.ColumnExtension{Name: colLocale, Type: auth.ColumnText, Default: "''"}
```
<!-- /ds:block hash=51b836 -->

The app's own route stores the choice, accepting only languages it ships, because an unknown tag is ignored at read time and the user would silently get the browser's language:

<!-- ds:block id=translated-errors-store-user-locale-v35bz7mj -->
**setLocale** · [`examples/translated-errors/main.go:292-306`](../../examples/translated-errors/main.go#L292-L306)

```go
func setLocale(a *auth.Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in localeRequest
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || !slices.Contains(supportedLocales, in.Locale) {
			writeJSON(w, http.StatusBadRequest, loginAnswer{Reason: reasonUnsupportedLocale})
			return
		}
		if err := auth.SetUserColumn(r.Context(), a, auth.AppName, authhttp.MustUser(r).ID, UserLocale, in.Locale); err != nil {
			log.Printf("store locale: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, localeAnswer{Locale: in.Locale})
	}
}
```
<!-- /ds:block hash=cea678 -->

`authhttp.Middleware` needs the same locale rule as `Handler`, or an app handler and a library route answer the same user in different languages; the example passes one `localeRule` to both:

<!-- ds:block id=translated-errors-newhandler-yu5wmag9 -->
**newHandler** · [`examples/translated-errors/main.go:201-213`](../../examples/translated-errors/main.go#L201-L213)

```go
func newHandler(a *auth.Auth) (http.Handler, error) {
	pw, err := auth.PluginOf[*password.Plugin](a)
	if err != nil {
		return nil, err
	}
	withAuth := authhttp.Middleware(a, localeRule)
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authRoutes(a))
	mux.Handle("POST "+loginPath, withAuth(login(a, pw)))
	mux.Handle("POST "+localePath, withAuth(authhttp.RequireUser(setLocale(a))))
	mux.Handle("GET "+mePath, withAuth(authhttp.RequireUser(me(a))))
	return mux, nil
}
```
<!-- /ds:block hash=d8f137 -->

Try it: after `POST /api/locale {"locale":"de"}`, the user's requests answer in German even from a browser that asks for English, and the verification mail for an added address uses the German template:

```sh
curl -s -b cookies.txt -X POST localhost:8096/auth/email/add -H 'Origin: http://localhost:8096' -H 'Accept-Language: en' -d '{"email":"not an address"}'
```

```json
{"error":{"code":"auth.identifier_invalid","message":"Das sieht nicht richtig aus. Bitte prüfen Sie die Eingabe und versuchen Sie es erneut.","originalMessage":"This does not look right. Check it and try again."}}
```

Check: `TestStoredLocale_WinsForTheSignedInUser` (the stored language beats `Accept-Language` for errors and mail, and after sign-out the browser's language applies again) and `TestErrors_LocaleCookieBeatsAcceptLanguage` in `examples/translated-errors`.

## Step 4 — Land a browser on an error page

A browser flow that fails, such as an OAuth callback, answers JSON unless it is told where to go. `auth.WithErrorURL("/auth/error")` is that page for every flow that names none of its own (`oauth.ErrorURL`, a start request's `errorTo`), with the code in the query (`?error=oauth.denied`), as better-auth's `onAPIError.errorURL` is; `auth.New` refuses a page that is not a same-site path or on a trusted origin. `authhttp.ErrorPage(authhttp.ErrorPageOptions{})` serves one at `<prefix>/error`, better-auth's `/api/auth/error`: the code, its message in the request's language and the provider's `error_description`, escaped. `Template` replaces the page (any `html/template` over `authhttp.ErrorPageData`), `Redirect` sends the request on to the app's own page with the same parameters, and `Nonce` puts a CSP nonce on the page's style.

Which flows use it: those that call `Call.RedirectOnError` with no page of their own, which today are magic links and email verification links opened over GET (`magiclink.VerifyByGET`, `email.VerifyByGET`), OAuth callbacks, and SSO sign-ins when the SSO plugin has no `WithErrorURL` of its own. A link whose callback the app does not trust lands there too, with that callback's error code. The redirect is a `302` with `?error=<code>`, or `&error=` when the URL already has a query.

`examples/translated-errors` points the option at the built-in page, and mounts that page with the same locale rule as every other route:

<!-- ds:block id=translated-errors-error-page-ab7ax3sy -->
**authRoutes** · [`examples/translated-errors/main.go:182-184`](../../examples/translated-errors/main.go#L182-L184)

```go
func authRoutes(a *auth.Auth) http.Handler {
	return authhttp.Handler(a, authhttp.Prefix(authPrefix), localeRule, authhttp.ErrorPage(authhttp.ErrorPageOptions{}))
}
```
<!-- /ds:block hash=b1bec0 -->

Try it, with a link whose token is wrong:

```sh
curl -s -i 'localhost:8096/auth/magiclink/verify?token=bogus' -H 'Accept-Language: de'
curl -s 'localhost:8096/auth/error?error=auth.token_invalid' -H 'Accept-Language: de'
```

```text
HTTP/1.1 302 Found
Location: /auth/error?error=auth.token_invalid
Content-Length: 0

<body><main><h1>Something went wrong</h1><p>Dieser Link oder Code ist nicht mehr gültig.</p><p><code>auth.token_invalid</code></p><p><a href="/">Back to the start</a></p></main></body></html>
```

The message comes from the library's declaration of the code, in the request's language, never from the link, so a crafted URL cannot put text on the page. The built-in page's title, heading and link translate through the same `WithMessages` catalogue under the codes `authhttp.ErrorPageTitleCode`, `ErrorPageHeadingCode` and `ErrorPageBackCode` (`authhttp.error_page.title`, `.heading`, `.back`), and the page's `lang` is the request's locale when the heading is translated, `en` otherwise; pass `Template` for a page in your own words. Check: `TestErrorURL_FailedLinkLandsOnTheErrorPage` in `examples/translated-errors`; without the option the same request answers `400` JSON.

## Step 5 — Why some errors say so little

Some codes deliberately cover several causes. `auth.signed_out` is an expired, a revoked and a missing session alike; `password.invalid_credentials` is a wrong password and an unknown account alike; `auth.token_invalid` is a wrong, used, expired and wrong-purpose token alike; `auth.code_invalid` likewise for one-time codes. The reason is enumeration: an answer that told a stranger which accounts exist, or which link was once valid, would be a tool for them. Hashing happens even for an unknown account, so the timing says no more than the message. See [Security](security.md).

## Every error code

Codes from the core carry the `auth.` prefix (`auth.internal`, `auth.rate_limited` and `auth.origin_not_trusted` included, renamed from their unprefixed forms on 2026-10-09). A plugin's codes carry the plugin's name. The same list is generated from the declarations by `task docs:api` as [`reference/error-codes.md`](../reference/error-codes.md), [`error-codes.json`](../reference/error-codes.json) and [`error-codes.ts`](../reference/error-codes.ts) (a `const` object keyed by code, the `AuthErrorCode` union and an `isAuthErrorCode` guard, for a TypeScript frontend; [`TestErrorCodes_ListsEveryPluginAndRenders`](ds:block?id=testerrorcodes-listseverypluginandrenders-rg5ftw6v&assert=true) checks the three agree), and `task check` fails when a declared code has no row below, so the generated list says what a code is and this page says when it is returned. In Go, `auth.Errors()` is the list and `auth.ErrorCodeConflicts()` names any code two packages declared differently.

### Core

| Code | Status | Message | When |
| --- | --- | --- | --- |
| `auth.internal` | 500 | Something went wrong. Try again. | any error that is not an `*auth.Error` |
| `auth.signed_out` | 401 | Sign in to continue. | no valid session: missing, expired, revoked, or pending a second factor |
| `auth.fresh_session_required` | 403 | Sign in again to continue. | a `FreshSignIn` operation with a session neither created nor [re-authenticated](sessions.md#prove-it-is-still-you-re-authentication) within the fresh window |
| `auth.reauthentication_ticket_invalid` | 400 | Confirm your password or passkey again. | the second step of a re-authentication with a wrong, spent or expired ticket, or one issued to another session |
| `auth.reauthentication_unsupported` | 501 | Confirming your identity is not available here. Sign in again to continue. | a re-authentication on a custom `SessionStore` without `auth.SessionReauthStore` |
| `auth.impersonation_refused` | 403 | This cannot be done while acting as another user. | a `FreshSignIn` operation on an impersonation session |
| `auth.api_key_refused` | 403 | This cannot be done with an API key. | an auth operation (sign-out, password change, session list) called with an API key |
| `auth.session_task_pending` | 403 | Finish setting up your account to continue. | an operation or `RequireUser` route called by a session whose [session tasks](session-tasks.md) do not allow it |
| `auth.origin_not_trusted` | 403 | This request came from a site that is not trusted. | a cookie-authenticated mutation from an untrusted origin, or with no `Origin` |
| `auth.bad_request` | 400 | The request is not valid. | the input did not decode |
| `auth.unknown_operation` | 404 | Not found. | a route no plugin registered |
| `auth.method_not_allowed` | 405 | This method is not allowed here. | `GET` on a mutation or `POST` on a query (`authhttp`) |
| `auth.missing_scope` | 403 | This key does not allow this. | `authhttp.RequireScope` on an API key without the scope |
| `auth.rate_limited` | 429 | Too many attempts. Wait a moment and try again. | a rate rule refused the call; `Retry-After` says how long |
| `auth.challenge_required` | 428 | Complete the challenge and try again. | a `RateChallenge` rule is over its limit, or a geo rule with that action is violated, and the call carried no proof; send the captcha token (`X-Captcha-Response`) or the proof of work (`X-Pow-Proof`) and call again |
| `auth.geo_blocked` | 403 | Sign-in is not available from your location. | `auth.WithGeoRules` with the block action: a sign-in from a denied country, outside the allowed ones, or (with `DenyUnknown`) from an address the locator does not know; checked before the credentials, so the answer is the same for a right and a wrong password ([geo rules](geo-rules.md)) |
| `auth.ip_blocked` | 403 | This request cannot be completed from your network. | `auth.WithIPReputation` with the block action: the check flagged the caller's address; checked before the credentials, so a right and a wrong password get the same answer ([risk signals](risk-signals.md)) |
| `auth.bot_blocked` | 403 | This request looks automated. Try again from a browser. | `auth.WithBotCheck` with the block action flagged the request ([risk signals](risk-signals.md)) |
| `auth.signup_blocked` | 403 | We could not create this account. Contact support if you think this is a mistake. | `auth.WithTrialAbuseCheck` with the block action flagged the new account; the sign-up fails and the user it created is rolled back ([risk signals](risk-signals.md)) |
| `auth.risk_check_unavailable` | 503 | This request cannot be checked right now. Try again shortly. | a risk check returned an error and its policy is `RiskFailClosed`; the default `RiskFailOpen` lets the call through instead ([risk signals](risk-signals.md)) |
| `auth.impossible_travel` | 403 | This sign-in looks unusual. Try again later or contact support. | `auth.WithImpossibleTravel` with the block action: the sign-in is too far from the user's previous one for the time between them; checked after the credentials, and no session is created ([geo rules](geo-rules.md)) |
| `auth.user_not_found` | 404 | Not found. | no user with this id |
| `auth.identity_not_found` | 404 | Not found. | no such identity, or not this user's |
| `auth.identity_taken` | 409 | This is already in use by another account. | a verified identity with this value exists on another account |
| `auth.identifier_invalid` | 400 | This does not look right. Check it and try again. | the value is not a valid email, number or handle, or its kind is unknown |
| `auth.token_invalid` | 400 | This link or code is not valid any more. | a verification token that is wrong, used, expired or for another purpose |
| `auth.code_invalid` | 400 | This code is not right, or it has expired. | a one-time code that is wrong, spent, expired or out of attempts |
| `auth.field_invalid` | 400 | A field in this request cannot be set, or has the wrong type. | a sign-up `fields` entry that `auth.WithSignUpFields` does not list, or whose value is not of the column's type; it names neither |
| `auth.last_sign_in_method` | 409 | Add another way to sign in before you remove this one. | removing the only verified way into the account |
| `auth.not_verified` | 409 | Verify this first. | making an unverified identity primary, or an action that needs a verified one |
| `auth.no_recovery_channel` | 409 | This account has no verified way to receive a message. | a reset or notice with nowhere to go |
| `auth.profile_invalid` | 400 | Use a shorter name, and an image address that starts with https://. | `UpdateProfile` with a name over 100 characters or a non-https image |
| `auth.no_scope` | 400 | The request does not name a workspace. | a tenant-scoped kind used without `auth.WithScope` in the context |
| `auth.sessions_unavailable` | 409 | Sessions cannot be listed or ended one by one here. | stateless sessions: only the current session can be shown or ended |
| `auth.session_data_unavailable` | 409 | This request has no session to hold data. | `auth.SetSessionData` or `sessiondata.Plugin.Set` on a request signed in with an API key, which has no session row |
| `auth.too_many_device_sessions` | 409 | Too many accounts are signed in on this device. Sign one out first. | a sign-in on a device that already holds `WithMultiSession`'s maximum |
| `auth.resource_not_found` | 404 | Not found. | `Call.RequireOwner` or `Call.RequireOwnerRow` on a row that does not exist, or by default one that belongs to another user |
| `auth.resource_forbidden` | 403 | This belongs to another account. | `Call.RequireOwner` on another user's row when the `Ownership` sets `Forbidden` (better-auth's behaviour); off by default, since it tells a caller which ids exist |
| `auth.device_session_not_found` | 404 | That account is not signed in on this device. | a device-sessions switch or revoke naming a session the device does not hold, whether unknown, expired or another device's |

### Plugins

| Code | Status | Message |
| --- | --- | --- |
| `password.invalid_credentials` | 401 | The sign-in details are not right. |
| `password.too_short` | 400 | Choose a longer password. |
| `password.too_long` | 400 | Choose a shorter password. |
| `password.weak` | 400 | Choose a stronger password. |
| `password.breached` | 400 | This password has appeared in a data breach. Choose another one. |
| `password.hash_unrecognized` | 400 | `ImportHash` (Go only) with a string that neither the `Hasher` nor any `AcceptLegacyHashes` verifier recognizes. |
| `password.has_password` | 409 | `ImportHash` (Go only) for a user who already has a password; `SetPassword` is the deliberate replacement. |
| `password.redirect_invalid` | 400 | This page cannot receive a reset link. |
| `password.reused` | 400 | Choose a password you have not used recently. |
| `password.expired` | 403 | Your password has expired. Choose a new one. |
| `password.not_expired` | 400 | This password has not expired. Sign in and change it from your account. |
| `email.single_address` | 409 | This account can have one email address. Change it instead. |
| `email.callback_invalid` | 400 | This page cannot be opened after verifying. |
| `email.address_rejected` | 400 | This email address cannot be used. Use another one. |
| `phone.has_number` | 409 | This account already has a phone number. Remove it first. |
| `username.reserved` | 409 | This username is not available. |
| `username.immutable` | 409 | Your username cannot be changed. |
| `username.display_invalid` | 400 | This display username is not valid for the username. |
| `magiclink.callback_invalid` | 400 | This page cannot be opened after signing in. |
| `anonymous.already` | 409 | You already have a guest session. |
| `anonymous.not_anonymous` | 403 | This is not a guest account. |
| `twofactor.code_invalid` | 400 | This code is not right. |
| `twofactor.locked` | 429 | Too many wrong codes. Wait and try again. |
| `twofactor.already_enabled` | 409 | Two-factor sign-in is already on. |
| `twofactor.secret_invalid` | 400 | `ImportTOTP` (Go only) with a secret that is not base32 or shorter than `MinImportSecretBytes`. |
| `handoff.challenge_invalid` | 400 | The challenge is not a base64url SHA-256. |
| `handoff.verifier_invalid` | 400 | The verifier must be 43 to 128 unreserved characters. |
| `twofactor.not_enrolled` | 409 | Start two-factor setup first. |
| `passkey.ceremony_invalid` | 400 | This passkey request has expired. Try again. |
| `passkey.invalid` | 401 | This passkey could not be verified. |
| `passkey.not_found` | 404 | Not found. |
| `passkey.none` | 400 | Add a passkey first, or confirm with your password. |
| `passkey.authenticator_not_allowed` | 403 | This kind of passkey is not accepted here. Use another one. |
| `oauth.state_invalid` | 400 | This sign-in link has expired. Start again. |
| `oauth.denied` | 400 | Sign-in was cancelled at the provider. |
| `oauth.provider_failed` | 502 | The provider could not be reached. Try again. |
| `oauth.account_exists` | 409 | An account with this email already exists. Sign in, then link this provider in settings. |
| `oauth.linked_elsewhere` | 409 | This provider account is linked to another user. |
| `oauth.not_linked` | 404 | Not found. |
| `oauth.reauth_not_linked` | 403 | Continue with the provider account that is linked to this account. |
| `oauth.bad_return_to` | 400 | The return address must be a path on this site. |
| `oauth.refresh_failed` | 502 | The provider did not renew access. Link the account again. |
| `oauth.no_tokens` | 404 | No provider tokens are stored for this account. |
| `apikey.unknown_scope` | 400 | A scope in this request does not exist. |
| `apikey.too_many` | 409 | This account has too many keys. Revoke one first. |
| `apikey.not_found` | 404 | Not found. |
| `organization.not_member` | 404 | Not found. |
| `organization.forbidden` | 403 | Your role does not allow this. |
| `organization.slug_taken` | 409 | This address is already in use. |
| `organization.bad_slug` | 400 | Use lowercase letters, digits and dashes. |
| `organization.bad_role` | 400 | This role does not exist. |
| `organization.last_owner` | 409 | An organization needs at least one owner. |
| `organization.invite_invalid` | 404 | This invitation is not valid any more. |
| `admin.forbidden` | 403 | Only an administrator can do this. |
| `admin.admin_target` | 409 | Remove this user's admin rights first. |
| `admin.banned_target` | 409 | This user is banned. |
| `admin.last_admin` | 409 | Keep at least one administrator. |
| `admin.not_impersonating` | 409 | This session is not an impersonation. |
| `admin.bad_filter` | 400 | A filter is true, false or absent. |
| `admin.bad_sort` | 400 | This sort order does not exist. |
| `admin.bad_search_field` | 400 | This search field does not exist. |
| `admin.bad_search_operator` | 400 | This search operator does not exist. |
| `admin.search_value` | 400 | Search for one to 320 characters. |
| `admin.self_target` | 409 | You cannot do this to yourself. |
| `apikey.name_required` | 400 | Give the key a name. |
| `apikey.expiry_out_of_range` | 400 | The expiry is outside what this app allows. |
| `apikey.metadata_disabled` | 400 | This app does not keep metadata on keys. |
| `apikey.bad_metadata` | 400 | Metadata must be a JSON object of at most 4096 bytes. |
| `apikey.no_changes` | 400 | Nothing to update. |
| `apikey.usage_exceeded` | 429 | This key has used up its quota. |
| `apikey.bad_list` | 400 | The list options are not valid. |
| `apikey.bad_name` | 400 | The name is too short or too long. |
| `apikey.missing_scope` | 403 | This key does not allow this. |
| `apikey.unknown_config` | 400 | This key configuration does not exist. |
| `apikey.bad_prefix` | 400 | The key prefix is not allowed. |
| `apikey.invalid_key` | 401 | Invalid API key. |
| `apikey.key_disabled` | 401 | This API key is disabled. |
| `apikey.key_expired` | 401 | This API key has expired. |
| `apikey.invalid_owner` | 401 | The account behind this API key no longer exists. |
| `apikey.owner_blocked` | 401 | The account behind this API key cannot sign in. |
| `apikey.organization_id_required` | 400 | Organization ID is required for organization-owned API keys. |
| `apikey.not_organization_config` | 400 | This key configuration does not make organization keys. |
| `apikey.not_organization_member` | 403 | You are not a member of the organization that owns this API key. |
| `apikey.organization_permission` | 403 | You do not have permission to perform this action on organization API keys. |
| `apikey.organization_key` | 401 | An organization API key does not sign in as a user. |
| `apikey.permissions_off` | 400 | This app does not keep permissions on keys. |
| `apikey.bad_permissions` | 400 | A permission in this request does not exist. |
| `apikey.permission_denied` | 403 | This key does not allow this. |
| `apikey.expiry_conflict` | 400 | Give the expiry in seconds or in days, not both. |
| `oauth.bad_scope` | 400 | A requested scope is not available for this provider. |
| `oauth.bad_param` | 400 | A requested sign-in parameter is not available for this provider. |
| `oauth.data_too_long` | 400 | The data to carry through sign-in is too long. |
| `oauth.params_unsupported` | 400 | This provider does not take sign-in options. |
| `oauth.sign_up_disabled` | 403 | Sign-up with this provider is not open. Sign in to an existing account first. |
| `oauth.email_unverified` | 403 | The provider has not verified your email address. |
| `oauth.email_not_found` | 403 | The provider did not share an email address. Allow access to your email and try again. |
| `oauth.email_not_verified` | 403 | Verify your email address, then sign in again. |
| `oauth.email_mismatch` | 409 | The provider account uses an address that is not on this account. |
| `oauth.id_token_unsupported` | 400 | This provider does not accept sign-in tokens. |
| `oauth.id_token_invalid` | 401 | The sign-in token was not accepted. |
| `oauth.id_token_replayed` | 401 | This sign-in token was already used. Sign in with the provider again. |
| `oauth.nonce_required` | 401 | The sign-in token carries no nonce. |
| `oauth.logout_provider` | 400 | Name the provider to sign out of. |
| `oauth.logout_unsupported` | 404 | This provider has no sign-out endpoint. |
| `oauth.sign_up_not_requested` | 403 | No account is linked to this provider account. Use sign-up to create one. |
| `oauth.profile_refused` | 403 | This account cannot sign in here. |
| `oauth.cannot_refresh` | 404 | This account's tokens cannot be refreshed. |
| `oauth.profile_unsupported` | 404 | This provider does not offer a profile to read. |
| `organization.create_forbidden` | 403 | You cannot create an organization. |
| `organization.limit_reached` | 409 | You have reached the number of organizations you can own. |
| `organization.members_limit` | 409 | This organization is full. |
| `organization.bad_query` | 400 | This sort or filter is not supported. |
| `organization.no_active` | 400 | No organization is active. |
| `organization.already_member` | 409 | This user is already a member. |
| `organization.invitation_limit` | 409 | This organization has too many pending invitations. |
| `organization.bad_metadata` | 400 | Metadata must be a JSON object of at most 16 KiB. |
| `organization.team_not_found` | 404 | Not found. |
| `organization.teams_limit` | 409 | This organization has reached its number of teams. |
| `organization.team_members_limit` | 409 | This team is full. |
| `organization.last_team` | 409 | An organization needs at least one team. |
| `organization.role_not_found` | 404 | This role does not exist. |
| `organization.role_taken` | 409 | A role with this name already exists. |
| `organization.roles_limit` | 409 | This organization has reached its number of roles. |
| `organization.role_in_use` | 409 | Members still hold this role. |
| `organization.bad_permission` | 400 | This permission cannot be granted. |
| `organization.already_invited` | 409 | This address already has a pending invitation. |
| `organization.no_active_team` | 400 | No team is active. |
| `organization.predefined_role` | 400 | This role is part of the configuration and cannot be changed here. |
| `organization.invite_address` | 400 | Name the person by one address of a kind this app invites by. |
| `audit.no_query_backend` | 501 | The audit log cannot be read here. |
| `passkey.attachment_invalid` | 400 | Choose platform or cross-platform. |
| `password.no_usernames` | 400 | Usernames are not available. |
| `twofactor.method_invalid` | 400 | Choose an available two-factor method. |
| `twofactor.no_channel` | 409 | Verify an email address or phone number first. |
| `twofactor.not_code_method` | 409 | Your authenticator app has the code. |
| `twofactor.trust_disabled` | 400 | Remembering this device is not available. |
| `twofactor.device_not_found` | 404 | Not found. |
| `twofactor.issuer_invalid` | 400 | The issuer name is not valid. |
| `twofactor.trust_needs_session` | 400 | A device can only be remembered when signing in. |
| `twofactor.not_totp` | 409 | Your second factor is not an authenticator app. |
| `twofactor.recovery_codes_hidden` | 409 | These recovery codes cannot be shown again. Make a new set. |
| `twofactor.secret_unreadable` | 503 | Two-factor codes cannot be checked right now. A recovery code still works; otherwise contact support. |
| `admin.banned` | 403 | This account is banned. (or the app's `admin.BannedMessage`) |
| `admin.no_password_plugin` | 409 | No password plugin is registered. |
| `admin.no_email_plugin` | 409 | No email plugin is registered. |
| `admin.email_required` | 400 | An email address is required. |
| `admin.no_audit_plugin` | 409 | No audit plugin is registered. |
| `admin.no_two_factor_plugin` | 409 | No two-factor plugin is registered. |
| `admin.bad_role` | 400 | This role does not exist. |
| `admin.bad_filter_field` | 400 | This filter field does not exist. |
| `admin.bad_filter_operator` | 400 | This filter operator does not apply to this field. |
| `admin.bad_filter_value` | 400 | This filter value does not fit the field. |
| `admin.sessions_not_listable` | 409 | Sessions are not kept in the database, so they cannot be listed together. |
| `admin.no_user_data` | 400 | There is nothing to update. |
| `admin.field_not_editable` | 400 | This field cannot be changed here. |
| `admin.bad_user_data` | 400 | A value does not fit its field. |
| `terms.not_accepted` | 403 | Accept the current terms to continue. |
| `terms.stale_version` | 409 | The terms changed. Read the current version and accept again. |
| `captcha.missing` | 400 | Complete the captcha and try again. |
| `captcha.failed` | 403 | The captcha could not be verified. Try again. |
| `captcha.unavailable` | 503 | The captcha service is not available. Try again in a moment. |
| `pow.proof_invalid` | 403 | The proof of work was not accepted. |
| `pow.challenge_invalid` | 400 | The challenge has expired. Request a new one. |
| `authui.origin_refused` | 403 | This form was sent from another site. Open the page again and retry. |
| `authgate.not_allowed` | 403 | This account is not allowed here. |
| `authgate.cookie_too_large` | 500 | The sign-in could not be saved. Contact the site's owner. |
| `authgate.bad_return_to` | 400 | The return address must be a path on this site. |
| `authgate.unknown_provider` | 404 | This sign-in method is not offered here. |
| `authgate.cross_site` | 403 | This request came from another site. |
| `authgate.method_not_allowed` | 405 | This sign-in method does not answer by form post. |
| `oauthprovider.invalid_request` | 400 | The request is missing a parameter, repeats one, or is otherwise malformed. |
| `oauthprovider.invalid_client` | 401 | Client authentication failed. |
| `oauthprovider.invalid_grant` | 400 | The grant is invalid, expired, revoked, or was issued to another client. |
| `oauthprovider.unauthorized_client` | 400 | This client may not use this grant type. |
| `oauthprovider.unsupported_grant_type` | 400 | The grant type is not supported. |
| `oauthprovider.unsupported_response_type` | 400 | Only response_type=code is supported. |
| `oauthprovider.invalid_scope` | 400 | A requested scope is unknown or not allowed for this client. |
| `oauthprovider.access_denied` | 403 | The user or the server denied the request. |
| `oauthprovider.login_required` | 401 | The user must sign in. |
| `oauthprovider.consent_required` | 403 | The user must consent. |
| `oauthprovider.invalid_token` | 401 | The access token is invalid, expired or revoked. |
| `oauthprovider.insufficient_scope` | 403 | The access token lacks a required scope. |
| `oauthprovider.invalid_redirect_uri` | 400 | A redirect URI is not an absolute https URL, a loopback http URL or a private-use scheme, or carries a fragment. |
| `oauthprovider.invalid_client_metadata` | 400 | The client metadata is not valid. |
| `oauthprovider.registration_closed` | 403 | Dynamic client registration is not open. |
| `oauthprovider.invalid_redirect_target` | 400 | The client is unknown or the redirect URI is not registered for it. |
| `oauthprovider.invalid_target` | 400 | The requested resource is unknown or not allowed. |
| `oauthprovider.request_not_supported` | 400 | Request objects are not supported. |
| `oauthprovider.request_uri_not_supported` | 400 | request_uri is not supported. |
| `oauthprovider.invalid_request_uri` | 400 | request_uri is invalid or expired. |
| `oauthprovider.invalid_dpop_proof` | 400 | The DPoP proof is missing or invalid. |
| `oauthprovider.resource_exists` | 409 | This resource is already registered. |
| `oauthprovider.temporarily_unavailable` | 429 | Client metadata cannot be fetched now. Try again shortly. |
| `oauthprovider.invalid_signature` | 401 | The authorization request was altered or has expired. |
| `oauthprovider.forbidden` | 403 | You may not do this with this client. |
| `oauthprovider.account_selection_required` | 403 | The user must choose an account. |
| `oauthprovider.interaction_required` | 403 | The user must complete a step before this authorization. |
| `oauthprovider.client_disabled` | 400 | The client is disabled. |
| `oauthprovider.invalid_user` | 400 | The user of this grant no longer exists. |
| `oauthprovider.not_found` | 404 | Not found. |
| `oauthprovider.secret_not_recoverable` | 404 | This client's secret cannot be read back. |
| `oauthprovider.unsupported_prompt_select_account` | 400 | This server cannot show an account picker. |
| `oauthprovider.unsupported_token_type` | 400 | This token type cannot be revoked; it expires on its own. |
| `agentauth.invalid_request` | 400 | Malformed request, missing required fields, or invalid parameter types. |
| `agentauth.invalid_jwt` | 401 | JWT is invalid, expired, or signature failed. |
| `agentauth.jti_replay` | 401 | JWT has already been used. |
| `agentauth.request_binding_mismatch` | 401 | Request binding does not match the JWT. |
| `agentauth.invalid_public_key` | 400 | Public key is invalid or malformed. |
| `agentauth.unsupported_algorithm` | 400 | Key algorithm is not in the server's supported set. |
| `agentauth.unsupported_mode` | 400 | Requested mode is not supported by this server. |
| `agentauth.authentication_required` | 401 | An agent JWT, a host JWT or a signed-in user is required. |
| `agentauth.unauthorized` | 403 | Caller is not authorized for this operation. |
| `agentauth.agent_not_found` | 404 | Agent not found. |
| `agentauth.agent_revoked` | 403 | Agent has been revoked. |
| `agentauth.agent_pending` | 403 | Agent is still pending approval. |
| `agentauth.agent_rejected` | 403 | Agent registration was denied. |
| `agentauth.agent_claimed` | 403 | Agent has been claimed and is no longer active. |
| `agentauth.agent_expired` | 401 | Agent session has expired. |
| `agentauth.absolute_lifetime_exceeded` | 403 | Agent's absolute lifetime has elapsed. |
| `agentauth.agent_exists` | 409 | An agent with this public key is already registered. |
| `agentauth.agent_limit_reached` | 400 | Maximum number of active agents per user reached. |
| `agentauth.autonomous_owner_required` | 401 | Autonomous agents require an owner to be resolved. |
| `agentauth.host_not_found` | 404 | Host not found. |
| `agentauth.host_revoked` | 403 | Host has been revoked. |
| `agentauth.host_already_linked` | 409 | Host is already linked to a different user. |
| `agentauth.dynamic_host_registration_disabled` | 403 | Dynamic host registration is disabled: enable AllowDynamicHostRegistration, or create the host first with the create_host operation. |
| `agentauth.invalid_capabilities` | 400 | One or more requested capability names don't exist. |
| `agentauth.capability_blocked` | 400 | One or more requested capabilities are blocked by server policy. |
| `agentauth.capability_not_found` | 404 | Capability does not exist. |
| `agentauth.already_granted` | 409 | All requested capabilities are already granted. |
| `agentauth.capability_not_granted` | 403 | Agent does not have an active grant for this capability. |
| `agentauth.grant_revoked` | 403 | Capability grant has been revoked. |
| `agentauth.constraint_violated` | 403 | One or more capability constraints were violated. |
| `agentauth.unknown_constraint_operator` | 400 | Constraint contains an unrecognized operator. |
| `agentauth.execute_not_configured` | 501 | Server has not configured a capability execution handler. |
| `agentauth.capability_request_not_found` | 404 | Capability request not found. |
| `agentauth.capability_request_already_resolved` | 412 | Capability request has already been resolved. |
| `agentauth.capability_request_owner_mismatch` | 403 | Capability request does not belong to this user. |
| `agentauth.invalid_user_code` | 403 | The user code is missing or does not match. |
| `agentauth.approval_expired` | 403 | The approval request has expired. |
| `agentauth.enrollment_token_invalid` | 401 | The enrollment token is invalid or was already used. |
| `agentauth.enrollment_token_expired` | 401 | The enrollment token has expired. |
| `agentauth.jwks_url_disabled` | 400 | This server does not accept JWKS URLs; send a public key. |
| `agentauth.invalid_jwks_url` | 400 | The JWKS URL must be a public https URL. |
| `agentauth.webauthn_not_enrolled` | 403 | No passkeys registered. Register a passkey before approving capabilities that require proof of physical presence. |
| `agentauth.webauthn_verification_failed` | 403 | WebAuthn verification failed. |
| `agentauth.webauthn_not_enrolled` | 403 | No passkeys registered. Register a passkey before approving capabilities that require proof of physical presence. |
| `agentauth.webauthn_verification_failed` | 403 | WebAuthn verification failed. |
| `device.invalid_request` | 400 | The request is missing a parameter or has a bad one. |
| `device.unsupported_grant_type` | 400 | The grant type is not supported. |
| `device.invalid_client` | 400 | The client is not allowed to use device authorization. |
| `device.invalid_device_code` | 400 | The device code is not valid. |
| `device.expired_device_code` | 400 | The device code has expired. |
| `device.authorization_pending` | 400 | The user has not approved the request yet. |
| `device.polling_too_frequently` | 400 | Polling too often. Wait longer between requests. |
| `device.access_denied` | 400 | The user denied the request. |
| `device.not_owner` | 403 | This code belongs to another account. |
| `device.invalid_user_code` | 400 | This code is not valid. Check it and try again. |
| `device.expired_user_code` | 400 | This code has expired. Start again on your device. |
| `device.already_processed` | 400 | This code was already used. |
| `device.not_claimed` | 400 | Open this code on the approval page first. |
| `device.server_error` | 500 | The request could not be completed. |
| `oauthproxy.invalid_state` | 400 | The sign-in could not be completed. Start again. |
| `oauthproxy.invalid_code` | 400 | The sign-in could not be completed. Start again. |
| `oauthpopup.untrusted_origin` | 403 | This page may not open a sign-in popup. |
| `sso.provider_not_found` | 404 | No sign-in provider was found for this account. |
| `sso.provider_exists` | 422 | A sign-in provider with this id already exists. |
| `sso.provider_id_reserved` | 422 | This provider id is reserved. |
| `sso.bad_provider` | 400 | The provider configuration is not valid. |
| `sso.registration_disabled` | 403 | Sign-in provider registration is disabled. |
| `sso.providers_limit` | 403 | You have reached the maximum number of sign-in providers. |
| `sso.forbidden` | 403 | You cannot manage this sign-in provider. |
| `sso.not_member` | 400 | You are not a member of this organization. |
| `sso.target_required` | 400 | Give an email, a domain, an organization or a provider id. |
| `sso.domain_unverified` | 401 | This provider's domain has not been verified. |
| `sso.protocol_unavailable` | 400 | This provider does not offer that sign-in protocol. |
| `sso.bad_params` | 400 | A sign-in parameter is not allowed. |
| `sso.bad_return_to` | 400 | The return address must be a path on this site or a trusted origin. |
| `sso.state_invalid` | 400 | This sign-in link has expired. Start again. |
| `sso.provider_changed` | 409 | The sign-in provider changed during sign-in. Start again. |
| `sso.denied` | 400 | Sign-in was cancelled at the provider. |
| `sso.provider_failed` | 502 | The sign-in provider could not be reached. Try again. |
| `sso.account_exists` | 409 | An account with this email already exists. Sign in, then link this provider. |
| `sso.linked_elsewhere` | 409 | This provider account is linked to another user. |
| `sso.sign_up_disabled` | 403 | No account exists for you here. Ask for an invitation or sign up first. |
| `sso.user_rejected` | 403 | This account cannot sign in here. |
| `sso.boundary_locked` | 409 | Cannot change a provider's identity fields while accounts are linked to it. |
| `sso.mutation_rejected` | 409 | This change to the sign-in provider was refused. |
| `sso.saml_invalid` | 400 | The sign-in response was not accepted. |
| `sso.saml_replay` | 400 | This sign-in response was already used. |
| `sso.saml_unsolicited` | 400 | Sign-in must start on this site. |
| `sso.saml_too_large` | 400 | The sign-in response is too large. |
| `sso.no_identity` | 400 | The provider sent no user id or email. |
| `sso.domain_verified` | 409 | This domain is already verified. |
| `sso.domain_not_proven` | 502 | The domain's DNS record was not found. It can take a while to appear. |
| `sso.identifier_too_long` | 400 | The provider id is too long for a DNS verification record. |
| `sso.issuer_mismatch` | 400 | The provider's discovery document names another issuer. |
| `sso.discovery_incomplete` | 400 | The provider's discovery document lacks a required endpoint. |
| `sso.discovery_not_found` | 400 | The provider's discovery document was not found. |
| `sso.discovery_timeout` | 502 | The provider did not answer in time. |
| `sso.discovery_invalid_url` | 400 | A provider URL is not valid; it must be https. |
| `sso.discovery_private_host` | 400 | A provider URL points at a private address. |
| `sso.discovery_invalid_json` | 400 | The provider's discovery document is not valid JSON. |
| `sso.endpoint_redirect` | 400 | A provider endpoint answered with a redirect. |
| `sso.unsupported_token_auth` | 400 | The provider supports no token authentication method this app can use. |
| `sso.discovery_failed` | 502 | The provider's discovery document could not be read. |
| `sso.token_not_verified` | 401 | The provider's sign-in token was not accepted. |
| `sso.token_response_error` | 502 | The provider did not complete the sign-in. Try again. |
| `sso.no_pending_verification` | 404 | No domain verification is pending for this provider. Request a new token. |
| `sso.discovery_untrusted_origin` | 400 | A provider URL is not on this app's list of trusted identity providers. |
| `sso.field_not_allowed` | 400 | A provider field may not be set here. |
| `sso.sp_metadata_mismatch` | 400 | The SP metadata does not match the provider's settings. |
| `sso.idp_slo_unsupported` | 400 | This identity provider does not support single logout. |
| `sso.saml_session_not_found` | 404 | This session did not start with SAML single sign-on. |
| `sso.invalid_logout_request` | 400 | The logout request was not accepted. |
| `sso.invalid_logout_response` | 400 | The logout response was not accepted. |
| `sso.logout_failed_at_idp` | 502 | The identity provider could not sign you out. |
| `sso.no_private_key_available` | 500 | The sign-in key for this provider is not available. |
| `sso.token_response_not_found` | 502 | The provider's answer carried no sign-in token. |
| `scim.connection_decommissioned` | 409 | The SCIM connection is decommissioned. |
| `scim.connection_not_found` | 404 | No such SCIM connection. |
| `scim.creation_request_conflict` | 409 | This creation request was already used. |
| `scim.credential_not_found` | 404 | No such active credential. |
| `scim.deactivated` | 403 | This account has been deactivated by your organization. |
| `scim.too_many_credentials` | 409 | The connection has the most active credentials it may have. |
| `emailchallenge.invalid` | 400 | This sign-in request is not valid or has expired. |
| `emailchallenge.wrong_browser` | 403 | Open this link in the browser where you started signing in. |
| `invite.invalid` | 400 | This invitation is not valid or has expired. |
| `invite.required` | 403 | An invitation is required to sign up. |
| `invite.forbidden` | 403 | You cannot create this invitation. |
| `referral.invalid_code` | 400 | This referral code is not valid. |
| `referral.unknown_step` | 400 | This referral step is not configured. |
| `referral.not_found` | 404 | This user was not referred. |
| `ldap.credentials_invalid` | 401 | The username or password is incorrect. | an unknown username, a wrong password, an empty or oversized one: the same answer for all |
| `ldap.directory_unavailable` | 503 | Sign-in is unavailable right now. Please try again later. | the directory could not be reached or could not decide; the cause is logged |
| `ldap.account_exists` | 409 | An account with this email already exists. Sign in to it first. | `UntrustedEmail` is on and a user holds the directory entry's address |
| `ldap.sign_up_disabled` | 403 | This directory account has no account here. | `NoSignUp` and the entry is not linked to a user |
| `ldap.profile_refused` | 403 | This account may not sign in here. | the app's `MapProfile` refused the entry |
| `ldap.sign_in_conflict` | 409 | Another sign-in for this account is in progress. Please try again. | two first sign-ins of one entry raced |
| `siwe.message_invalid` | 400 | The sign-in message is not valid. | not an ERC-4361 message, or its address, chain or nonce disagree with the request |
| `siwe.domain_invalid` | 400 | The sign-in message is for another site. | the message's URI or domain is not one of the app's origins |
| `siwe.chain_invalid` | 400 | This network is not accepted. | the chain id is not in `siwe.Chains` |
| `siwe.message_expired` | 400 | The sign-in message has expired or is not valid yet. | outside the message's time window |
| `siwe.nonce_invalid` | 400 | The sign-in request has expired. Please try again. | the nonce is unknown, spent, expired or was issued for another wallet |
| `siwe.signature_invalid` | 401 | The signature is not valid. | the signature is not the address's |
| `siwe.address_invalid` | 400 | That is not an Ethereum address. | the wallet address does not parse |
| `siwe.email_required` | 400 | An email address is required to create the account. | `RequireEmail` and a first sign-in without one |
| `siwe.email_not_accepted` | 400 | This app does not take an email address here. | an email was sent but the email plugin is not registered |
| `siwe.sign_up_disabled` | 403 | This wallet is not linked to an account. | `NoSignUp` and the wallet is not linked |
| `siwe.wallet_linked_elsewhere` | 409 | This wallet belongs to another account. | linking a wallet another user owns |
| `siwe.wallet_not_found` | 404 | No such wallet. | unlinking a wallet the caller does not own |
| `jwt.unknown_template` | 404 | This token template does not exist. |
| `metadata.invalid` | 400 | Metadata must be a JSON object. |
| `metadata.too_large` | 413 | The metadata is too large. |
| `metadata.forbidden` | 403 | You may not manage this user's metadata. |
| `organization.domain_not_found` | 404 | Not found. |
| `organization.bad_domain` | 400 | Enter a domain such as example.com. |
| `organization.public_domain` | 400 | This is a public email domain and cannot belong to an organization. |
| `organization.domain_taken` | 409 | This domain is already in use. |
| `organization.domains_limit` | 409 | This organization has reached the number of domains it can add. |
| `organization.domain_not_verified` | 409 | The domain is not verified yet. Publish the TXT record and try again. |
| `organization.domain_check_failed` | 503 | The domain could not be checked. Try again later. |
| `organization.bad_enrollment` | 400 | This enrollment mode does not exist. |
| `organization.domain_role` | 400 | A domain cannot grant this role. |
| `organization.request_invalid` | 404 | This request is not valid any more. |
| `twofactor.factor_not_enrolled` | 400 | This two-factor method is not set up for your account. |
| `twofactor.factor_not_found` | 404 | Not found. |
| `twofactor.proof_required` | 400 | Confirm with your current two-factor method first. |
| `twofactor.security_key_invalid` | 401 | This security key could not be verified. |
| `samlidp.invalid_request` | 400 | The SAML request is malformed. |
| `samlidp.unknown_service_provider` | 400 | The service provider is not registered. |
| `samlidp.acs_not_registered` | 400 | The assertion consumer service URL is not registered for this service provider. |
| `samlidp.unsupported_binding` | 400 | Only the HTTP-POST binding is supported for the response. |
| `samlidp.wrong_destination` | 400 | The request is addressed to another endpoint. |
| `samlidp.request_expired` | 400 | The SAML request is too old or issued in the future. |
| `samlidp.request_replayed` | 400 | The SAML request was already used. |
| `samlidp.signature_required` | 400 | This service provider must sign its requests. |
| `samlidp.invalid_signature` | 400 | The request signature does not verify. |
| `samlidp.invalid_name_id_policy` | 400 | The requested NameID format is not the one configured for this service provider. |
| `samlidp.request_not_found` | 400 | The sign-in request is unknown, used or expired. Start again from the application. |
| `samlidp.idp_initiated_disabled` | 403 | IdP-initiated sign-on is not enabled for this service provider. |
| `samlidp.name_id_unavailable` | 403 | Your account has no verified value for the identifier this service needs. |
| `samlidp.access_denied` | 403 | You may not sign in to this service. |
| `samlidp.relay_state_too_long` | 400 | The RelayState is too long. |
| `samlidp.message_too_large` | 413 | The SAML message is too large. |
| `samlidp.unsupported_signature_algorithm` | 400 | The signature algorithm is not accepted. |
| `samlidp.missing_request` | 400 | SAMLRequest is missing. |
| `webhook.endpoint_not_found` | 404 | The webhook endpoint does not exist. |
| `webhook.delivery_not_found` | 404 | The webhook delivery does not exist. |
| `webhook.bad_url` | 400 | The webhook URL must be an absolute https URL without credentials. |
| `webhook.destination_refused` | 400 | The webhook URL points at a private or local address. |
| `webhook.bad_event_type` | 400 | The event type or filter is not valid. |
| `webhook.bad_secret` | 400 | The webhook secret must be whsec_ and base64 of 24 to 64 bytes. |
| `webhook.bad_description` | 400 | The webhook description is too long. |
| `webhook.too_many_endpoints` | 409 | There are too many webhook endpoints. |
| `webhook.endpoint_disabled` | 409 | The webhook endpoint is disabled. |
| `webhook.no_encryption_key` | 500 | Webhook secrets cannot be sealed. |

`plugin/magiclink` returns the core's codes (`auth.token_invalid`, `auth.signed_out`), and so does `plugin/jwt` apart from `jwt.unknown_template`. The `webhook.*` codes come from `plugin/webhook`'s Go API only; it serves no route. Each plugin's README lists which of its operations return which code.

## What can go wrong

- A `500` where you expected a code — the operation, a hook or your handler returned a plain Go error. Declare the errors a client should see with `auth.NewError`, with your own prefix.
- `errors.Is(err, auth.ErrSignedOut)` is false but the response says `auth.signed_out` — you compared against the wrong sentinel, or a transport-level check (`RequireUser`) answered before the operation ran.
- A message that changed between versions — match the code. Messages are not part of the contract.
- A translation that never appears — the catalogue's locale key must be a language tag (`de`, `de-CH`); `auth.New` refuses `de_CH` and an empty key, and an empty translation counts as none.
- A signed-in user's stored language ignored on one error — the error came before the session was resolved, or the request was signed out; `WithUserLocale` applies only after the lookup.
- A library route and an app handler answering the same user in different languages — `authhttp.Middleware` was built without the `LocaleCookie` or `LocaleFunc` that `Handler` has; pass the same options to both.
- `auth.New` fails on `WithUserLocale` — the column is not a text column declared with `WithUserColumns`.
- `auth.New` fails on `WithErrorURL` — the page is neither a same-site path nor on a trusted origin.

## Next

- [Security](security.md): why the uniform answers are what they are.
- [Rate limits](rate-limits.md): `auth.rate_limited` and `Retry-After`.
- [examples/translated-errors](../../examples/translated-errors): errors in the caller's language, one message replaced, a stored language per user, `errors.Is` in an app handler, and the error page, end to end.
