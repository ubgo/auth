# Email challenge: passwordless sign-in across devices

You will have a passwordless sign-in where one mail carries both a link and a code, and the session always lands in the browser that asked, even when the mail is opened on a phone.

Use this plugin for an app whose users start on a laptop and read mail on a phone, where a plain [magic link](magiclink.md) would sign in the phone instead of the screen they are working on, or wherever a link and a typed code should both finish the same sign-in.

## Before you start

- An app with an identifier plugin that can deliver, usually `plugin/email` with a mailer, as in [your first app](../start/first-app.md).
- How it differs from [magic links](magiclink.md): a magic link signs in whichever browser opens it. Here the browser that starts the challenge keeps a poll token, the link only approves, and the poll of that browser is what creates the session.
- The example program this guide is built from, with a `main_test.go` that drives the same steps on two devices and a `README.md` with the same transcript: [`examples/email-challenge`](../../examples/email-challenge/).
- What the plugin stores: one table, `auth_email_challenge`, one row per open challenge, deleted when it completes and swept when it expires. Every secret in it is a hash; the code is a core one-time code (`auth_code`) bound to the challenge.

## Step 1 — Wire the plugin, and serve the approval page

The example wires email and the challenge, and nothing else. `emailchallenge.New()` is a sign-in method by itself, so no password plugin is needed; `SignUp()` lets a completed challenge create the account for an address nobody has verified.

<!-- ds:block id=newauth-ec7chl01 -->
**newAuth** · [`examples/email-challenge/main.go:92-101`](../../examples/email-challenge/main.go#L92-L101)

```go
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			emailchallenge.New(emailchallenge.SignUp()),
		),
	)
}
```
<!-- /ds:block hash=273beb -->

The link in the mail opens a page of your app, `DefaultPage` (`/email-challenge`) under `auth.WithBaseURL`, with the approval token in the query. Mount the library's routes and that page:

<!-- ds:block id=newhandler-ec7chl02 -->
**newHandler** · [`examples/email-challenge/main.go:107-113`](../../examples/email-challenge/main.go#L107-L113)

```go
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.HandleFunc("GET "+emailchallenge.DefaultPage, approvalPage)
	mux.Handle("/me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux
}
```
<!-- /ds:block hash=edf9fc -->

The page asks the `context` route what to show and approves only when the person presses Confirm, so a mail scanner that fetches the link approves nothing:

<!-- ds:block id=approvalpagehtml-ec7chl03 -->
**approvalPageHTML** · [`examples/email-challenge/main.go:121-144`](../../examples/email-challenge/main.go#L121-L144)

```go
const approvalPageHTML = `<!doctype html>
<meta charset="utf-8">
<title>Approve sign-in</title>
<p id="msg">Checking…</p>
<button id="ok" hidden>Confirm</button>
<script>
const token = new URLSearchParams(location.search).get("token");
const api = "` + authPrefix + `/emailchallenge";
const msg = document.getElementById("msg"), ok = document.getElementById("ok");
fetch(api + "/context?token=" + encodeURIComponent(token)).then(r => r.json()).then(c => {
  if (c.state === "needs-confirmation") {
    msg.textContent = "Sign in as " + c.identifier + " from " + c.userAgent + " (" + c.ipAddress + ")?";
    ok.hidden = false;
  } else if (c.state === "approved") msg.textContent = "Approved. Go back to your other tab.";
  else if (c.state === "wrong-browser") msg.textContent = "Open this link in the browser where you started.";
  else msg.textContent = "This sign-in request is not valid any more.";
});
ok.onclick = async () => {
  const res = await fetch(api + "/approve", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({token})});
  ok.hidden = true;
  msg.textContent = res.ok ? "Approved. Go back to your other tab." : (await res.json()).error.message;
};
</script>
`
```
<!-- /ds:block hash=2df88a -->

`auth.New` refuses a setup that could never complete a challenge:

| Error | Cause |
|---|---|
| `emailchallenge: no identifier kind can receive a challenge; add a Verifiable sign-in kind whose plugin delivers, such as email` (`ErrNoKinds`) | no sign-in kind with a verification flow whose plugin delivers; a username alone, for example |
| `emailchallenge: a kind given to Kinds must be registered, sign-in capable, verifiable and owned by a plugin that delivers` (`ErrBadKinds`) | a kind named in `Kinds` fails one of those |
| `emailchallenge: links need auth.WithBaseURL or emailchallenge.Links` (`ErrNoBase`) | neither set |
| `ErrBadTTL`, `ErrBadAttempt`, `ErrBadMode` | `WithTTL` or `WithMaxAttempts` not positive, or a `WithLinkMode` that is neither `CrossDevice` nor `SameDevice` |

Check: `go run ./email-challenge` in `examples/` prints `listening on http://localhost:8081`. The program, its test and the same transcript are in [`examples/email-challenge`](../../examples/email-challenge/).

## Step 2 — Start a challenge from the sign-in page

`POST /auth/emailchallenge/start {"identifier":"ada@example.com"}` answers `{"state":"pending","pollToken":…,"expiresAt":"…"}` and sets the cookie `__Host-auth_email_challenge` to the poll token. A browser uses the cookie. A client that keeps no cookies (a native app) reads `pollToken` from the answer and sends it back in the `pollToken` field of `poll` and `verify-otp`; a Go caller gets it in `Result.PollToken` from `Start` and passes it to `Poll` and `VerifyOTP`. The field is an `auth.WireToken`: it encodes as its value in JSON and prints `[redacted]` in a log.

```sh
O='Origin: http://localhost:8081'
curl -s -c laptop.txt -X POST localhost:8081/auth/emailchallenge/start -H "$O" -H 'User-Agent: Firefox on a laptop' -d '{"identifier":"ada@example.com"}'
```

```json
{"state":"pending","pollToken":"4Vt9-2YZSRbL0zu03mJiIR-wHlFRdBz7FBStCqdBciU","expiresAt":"2026-10-09T04:55:58.957929Z"}
```

The server log shows the mail, with the link, the code, and the browser and IP that asked, so the person can refuse a request they did not make:

```text
2026/10/09 08:35:24 mail to=ada@example.com subject="Your sign-in request"
To sign in, open this link and confirm:
http://localhost:8081/email-challenge?token=giwgvy5xdIkNOji0rkFZpi_dNMZbGShE2_D6rygnx3Y

Or type this code in the page that asked: 505527

The request came from Firefox on a laptop (127.0.0.1). If you did not ask to sign in, ignore this message.
```

The answer is the same for an address with no account: the challenge is stored but never mailed, and its poll stays `pending` until it expires, exactly like a challenge nobody clicked, so neither the answer nor the poll tells a stranger whether an account exists. With `SignUp()` the mail goes out and a completed challenge creates the account with the `name` the form sent.

## Step 3 — Poll, or type the code

The page that asked polls `POST /auth/emailchallenge/poll` every second or two. It answers `pending` until the challenge is approved, then `completed` with the user, and issues the session in the same response; `expired` means start again.

The mail also carries a code. `POST /auth/emailchallenge/verify-otp {"otp":"123456"}` from the asking browser signs in at once. The code is checked against that challenge only, and three wrong codes spend it (`WithMaxAttempts`). The same code typed in any other browser is refused, because that browser holds no poll token:

```sh
curl -s -c l2.txt -X POST localhost:8081/auth/emailchallenge/start -H "$O" -d '{"identifier":"ada@example.com"}'
curl -s -b l2.txt -X POST localhost:8081/auth/emailchallenge/verify-otp -H "$O" -d '{"otp":"000000"}'
curl -s -b l2.txt -c l2.txt -X POST localhost:8081/auth/emailchallenge/verify-otp -H "$O" -d '{"otp":"520611"}'
curl -s -X POST localhost:8081/auth/emailchallenge/verify-otp -H "$O" -d '{"otp":"520611"}'
```

```json
{"state":"pending","pollToken":"15UZwXO0TCEhgME5c7fGi5TcYFtge2vFgKPhYprXXtw","expiresAt":"2026-10-09T04:55:58.977647Z"}
{"error":{"code":"auth.code_invalid","message":"This code is not right, or it has expired."}}
{"state":"completed","user":{"id":"usr_ofbntffetaakxkcx3iuaf7v4","name":"","image":""}}
{"error":{"code":"emailchallenge.invalid","message":"This sign-in request is not valid or has expired."}}
```

Check: `TestEmailChallenge_CodeSignsInAndWrongCodesSpendIt` and `TestEmailChallenge_CodeNeedsThePollToken` in the example.

## Step 4 — The approval page the link opens

The link opens `DefaultPage` (`/email-challenge?token=…`, or your own with `Links`). The page calls `GET /auth/emailchallenge/context?token=…` and renders by `state`:

| State | Meaning | What the page shows |
|---|---|---|
| `needs-confirmation` | Opened on another device | Who asked (`identifier`, `ipAddress`, `userAgent`) and a Confirm button that POSTs `/auth/emailchallenge/approve {"token":"…"}` |
| `approved` | Opened in the asking browser, or already confirmed | "Approved, go back to your other tab" |
| `wrong-browser` | Another device under `WithLinkMode(SameDevice)` | "Open this link in the browser where you started" |
| `invalid` | Unknown, spent or expired | One generic message |

The run from the first mail: the phone opens the link and sees who asked, the laptop is still pending, the phone confirms, and the laptop's next poll creates the account and gets the session cookie. The poll cookie is cleared in the same answer:

```sh
curl -s 'localhost:8081/auth/emailchallenge/context?token=giwgvy5xdIkNOji0rkFZpi_dNMZbGShE2_D6rygnx3Y'
curl -s -b laptop.txt -X POST localhost:8081/auth/emailchallenge/poll -H "$O"
curl -s -X POST localhost:8081/auth/emailchallenge/approve -H "$O" -d '{"token":"giwgvy5xdIkNOji0rkFZpi_dNMZbGShE2_D6rygnx3Y"}'
curl -si -b laptop.txt -c laptop.txt -X POST localhost:8081/auth/emailchallenge/poll -H "$O"
curl -s -b laptop.txt localhost:8081/me
```

```text
{"state":"needs-confirmation","identifier":"ada@example.com","ipAddress":"127.0.0.1","userAgent":"Firefox on a laptop","expiresAt":"2026-10-09T03:10:24.87951Z"}
{"state":"pending"}
{"state":"approved"}
HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: __Host-auth_session=f41UG8mo_ezknf2EzSstlXMYjRNQ9_IVX5XdSsi23ps; Path=/; Expires=Fri, 16 Oct 2026 03:05:25 GMT; HttpOnly; Secure; SameSite=Lax
Set-Cookie: __Host-auth_email_challenge=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax
Date: Fri, 09 Oct 2026 03:05:25 GMT
Content-Length: 103

{"state":"completed","user":{"id":"usr_ofbntffetaakxkcx3iuaf7v4","name":"","image":""},"created":true}
{"id":"usr_ofbntffetaakxkcx3iuaf7v4"}
```

Check: `TestEmailChallenge_LinkOnPhoneSignsInLaptop` in the example asserts each of those answers, that the phone never holds a session cookie, and that a third poll answers `expired`.

`context` changes nothing for another device, so a mail scanner that fetches every link approves nothing; only the Confirm POST does. Opened in the asking browser, `context` approves at once, because only that browser holds the poll token:

<!-- ds:block id=plugin-docontext-kx8psdmg -->
**Plugin.doContext** · [`plugin/emailchallenge/emailchallenge.go:746-770`](../../plugin/emailchallenge/emailchallenge.go#L746-L770)

```go
func (p *Plugin) doContext(ctx context.Context, c *auth.Call, in TokenRequest) (ContextResult, error) {
	r, ok, err := p.live(ctx, c, in.Token.Token())
	if err != nil {
		return ContextResult{}, err
	}
	if !ok {
		return ContextResult{State: StateInvalid}, nil
	}
	_, value, _ := strings.Cut(r.identifier, identifierSeparator)
	out := ContextResult{Identifier: value, IP: r.ip, UserAgent: r.userAgent, ExpiresAt: &r.expiresAt}
	switch {
	case sameBrowser(c, r, in.PollToken.Token()):
		if err := p.approveRow(ctx, c, r); err != nil {
			return ContextResult{}, err
		}
		out.State = StateApproved
	case r.status == StatusApproved:
		out.State = StateApproved
	case p.mode == SameDevice:
		out.State = StateWrongBrowser
	default:
		out.State = StateNeedsConfirmation
	}
	return out, nil
}
```
<!-- /ds:block hash=3704b7 -->

Approval never creates a session. The poll spends the approved challenge with a conditional delete, so of two polls racing for one approval exactly one signs in:

<!-- ds:block id=plugin-complete-w73yta9q -->
**Plugin.complete** · [`plugin/emailchallenge/emailchallenge.go:670-705`](../../plugin/emailchallenge/emailchallenge.go#L670-L705)

```go
func (p *Plugin) complete(ctx context.Context, c *auth.Call, r row, from Status) (Result, error) {
	n, err := c.Auth.Exec(ctx, sqlb.NewDelete(c.Auth.Dialect()).From(TableChallenge).
		Where(sqlb.Eq(ChallengeID, r.id), sqlb.Eq(ChallengeStatus, from)))
	if err != nil {
		return Result{}, err
	}
	if n != 1 {
		return Result{}, ErrInvalid
	}
	kindName, value, _ := strings.Cut(r.identifier, identifierSeparator)
	if r.scope != "" {
		if s, ok := auth.ScopeFrom(ctx); ok && s != r.scope {
			return Result{}, ErrInvalid
		}
		ctx = auth.WithScope(ctx, r.scope)
	}
	var create *auth.NewUser
	if p.signUp {
		create = &auth.NewUser{Name: r.name}
	}
	in, err := c.SignInProvenAs(ctx, auth.IdentifierKindName(kindName), value, create)
	if errors.Is(err, auth.ErrIdentityNotFound) {
		// The owner went away, or (without SignUp) never existed and the
		// code was guessed: the same answer as a spent challenge.
		return Result{}, ErrInvalid
	}
	if err != nil {
		return Result{}, err
	}
	if err := c.Effects.SetCookie(CookieName, "", time.Time{}); err != nil {
		return Result{}, err
	}
	view := auth.ViewOf(in.User)
	return Result{State: StateCompleted, User: &view, Created: in.Created,
		SecondFactorRequired: in.Session.SecondFactorPending, Token: in.Token}, nil
}
```
<!-- /ds:block hash=8593f6 -->

The whole flow runs end to end in [TestP3CommunityEmailChallenge_CrossDevice](ds:block?id=testp3communityemailchallenge-crossdevice-m4avx27a) on SQLite, Postgres and MySQL.

## Options you may want

| Option | What it does | Default |
|---|---|---|
| `SignUp()` | A completed challenge creates an account for an address nobody has verified | off |
| `Kinds(kinds...)` | Limits challenges to these identifier kinds | every verifiable sign-in kind that delivers |
| `WithTTL(d)` | How long a challenge lives | [5 minutes](ds:block?id=defaultttl-55ds4pcc) |
| `WithMaxAttempts(n)` | Wrong codes a challenge survives | 3 |
| `WithLinkMode(m)` | `CrossDevice` (confirm on another device) or `SameDevice` (only the asking browser's click approves) | `CrossDevice` |
| `Links(fn)` | Builds the link from the approval token | `BaseURL + /email-challenge?token=…` |

## Routes, errors and limits

| Route | Go method | Rate limit |
|---|---|---|
| `POST /auth/emailchallenge/start` `{identifier, name?}` | `Start` | 3 per identifier per 15 minutes, 20 per IP per hour |
| `POST /auth/emailchallenge/poll` `{pollToken?}` | `Poll` | 120 per IP per minute |
| `POST /auth/emailchallenge/verify-otp` `{otp, pollToken?}` | `VerifyOTP` | 10 per IP per 15 minutes |
| `GET /auth/emailchallenge/context?token=` | `Context` | 120 per IP per minute |
| `POST /auth/emailchallenge/approve` `{token}` | `Approve` | 10 per IP per 15 minutes |

| Code | Status | When |
|---|---|---|
| `emailchallenge.invalid` | 400 | An unknown, spent or expired challenge, or a code without the poll token |
| `emailchallenge.wrong_browser` | 403 | `approve` from another device under `SameDevice` |
| `auth.code_invalid` | 400 | A wrong, spent or exhausted code |
| `auth.identifier_invalid` | 400 | `start` with something that is not an address of an allowed kind |

The message purpose is `emailchallenge.sign_in`, with `Link`, `Code` and an English `DefaultText` naming the browser and IP that asked; give your mailer a template for it to brand the mail.

## From TypeScript

Use this when the sign-in page that waits for the mail, and the approval page the mail's link opens, run in a browser or an app. The [typed client](../client/README.md) has the five routes on `client.emailchallenge`; list `emailchallenge()` in `plugins`. The two pages are two different callers: the asking page starts and polls, the page on the other device shows who asked and approves.

The asking page starts a challenge and polls until it is approved, or takes the code from the mail:

<!-- ds:block id=tsp-emailchallenge-poll-9kw4nq3m -->
**signInByApproval** · [`clients/ts/examples/plugin-signin.ts:91-100`](../../clients/ts/examples/plugin-signin.ts#L91-L100)

```typescript
export async function signInByApproval(address: string): Promise<"completed" | "expired"> {
  const started = await auth.emailchallenge.start({ identifier: address });
  if (started.error) return "expired";
  for (;;) {
    await new Promise((resolve) => setTimeout(resolve, 2000));
    const { data, error } = await auth.emailchallenge.poll({});
    if (error || data.state === "expired") return "expired";
    if (data.state === "completed") return "completed";
  }
}
```
<!-- /ds:block hash=4ab87b -->

<!-- ds:block id=tsp-emailchallenge-otp-3xq8mw2k -->
**finishWithCode** · [`clients/ts/examples/plugin-signin.ts:105-108`](../../clients/ts/examples/plugin-signin.ts#L105-L108)

```typescript
export async function finishWithCode(code: string): Promise<boolean> {
  const { data, error } = await auth.emailchallenge.verifyOtp({ otp: code });
  return !error && data.state === "completed";
}
```
<!-- /ds:block hash=1f4803 -->

The approval page renders by `state`, as the table in Step 4 lists, and confirms only after the person saw who asked:

<!-- ds:block id=tsp-emailchallenge-page-5nw2kq7x -->
**onApprovalPage** · [`clients/ts/examples/plugin-signin.ts:112-122`](../../clients/ts/examples/plugin-signin.ts#L112-L122)

```typescript
export async function onApprovalPage(confirm: (who: string) => Promise<boolean>): Promise<string> {
  const token = new URLSearchParams(location.search).get("token") ?? "";
  const { data, error } = await auth.emailchallenge.context({ token });
  if (error) return error.message;
  if (data.state === "approved") return "Approved. Go back to the tab where you started.";
  if (data.state === "wrong-browser") return "Open this link in the browser where you started.";
  if (data.state !== "needs-confirmation") return "This sign-in request is not valid any more.";
  if (!(await confirm(`${data.identifier ?? ""} from ${data.userAgent ?? "an unknown browser"} (${data.ipAddress ?? ""})`))) return "Ignored.";
  const approved = await auth.emailchallenge.approve({ token });
  return approved.error ? approved.error.message : "Approved. Go back to the tab where you started.";
}
```
<!-- /ds:block hash=720e8a -->

The codes a frontend handles, explained in [Routes, errors and limits](#routes-errors-and-limits) and [What can go wrong](#what-can-go-wrong): `auth.code_invalid` on a wrong code (three wrong codes spend the challenge), `emailchallenge.invalid` for an unknown, spent or expired challenge or a code typed in another browser, `emailchallenge.wrong_browser` under `WithLinkMode(SameDevice)`, `auth.rate_limited`. A `poll` answers `state: "expired"` rather than an error when the challenge ran out: start again.

There is no runnable TypeScript example for approve-by-mail; the blocks above are type-checked by `task ts:check`, and Steps 2 to 4 show the same calls with curl, from a laptop and a phone.

Pitfalls:

- **A browser keeps the poll token in a cookie; anything else must send it.** A native app or a Node client reads `pollToken` from `start`'s answer and passes it in every `poll` and `verifyOtp` (`{ pollToken }`), because it keeps no cookie.
- **Poll every second or two, not in a tight loop**: the poll route is rate limited, and the session arrives with the first poll after the approval anyway.
- **The answer to `start` is the same for an address with no account**; its poll stays `pending` until it expires. The page should say "check your inbox", never "no such account".

Every method with its route and types: [TypeScript client reference › emailchallenge](../reference/ts-client.md#emailchallenge).

## What can go wrong

| Symptom | Why | Fix |
|---|---|---|
| The poll stays `pending` and no mail arrives | The address has no verified owner and `SignUp()` is off: the challenge is stored but never mailed, on purpose, so the answer tells nobody which addresses have accounts. | Expected. Turn on `SignUp()` if a challenge may create the account; check the mail log in development. |
| `emailchallenge.invalid` (400) on `verify-otp` with the right code | The request did not carry the poll token: another browser, a client that dropped the cookie, or a cookie that never stuck because the page was served over plain HTTP to a non-localhost host (`__Host-` cookies need HTTPS). | Type the code in the browser that started; serve the app over HTTPS. |
| `auth.code_invalid` (400) on the right code | Three wrong codes (`WithMaxAttempts`) already spent the challenge, or it expired. | Start again. |
| The poll answers `expired` right after the phone confirmed | The challenge outlived `WithTTL` ([5 minutes](ds:block?id=defaultttl-55ds4pcc)), or another poll already completed it: one approval signs in once. | Start again; poll only from one tab. |
| `emailchallenge.wrong_browser` (403) on `approve` | `WithLinkMode(SameDevice)` and the link was opened on another device. | Open the link in the browser that asked, or use the default `CrossDevice`. |
| `auth.rate_limited` (429) on `start` | More than 3 starts per identifier in 15 minutes, or 20 per IP an hour. | Wait; the answer carries `Retry-After`. |

Known limits:

- Whoever reads the mailbox can approve a challenge someone else started, which is why the mail and the approval page name the browser and IP that asked. A person who presses Confirm on a request they did not make signs that stranger in.
- Mail is sent after the transaction commits, in the background. A delivery error is logged, not returned, so `start` answers `pending` for a mail that failed.

## Next

- [Magic links](magiclink.md): one link that signs in whichever browser opens it.
- [Email addresses](email.md): the plugin that delivers the mail, its templates and `email.SignInWithCode`, a code without a link.
- [Two-factor](twofactor.md): a completed challenge answers `secondFactorRequired` when a policy asks for a second step.
- The package [README](../../plugin/emailchallenge/README.md) is the full reference; the Go reference is on [pkg.go.dev](https://pkg.go.dev/github.com/ubgo/auth/plugin/emailchallenge).

## Not ported

A link mode where the click signs in the tab that opened it is [`plugin/magiclink`](magiclink.md); its built-in HTML confirmation page is left to the app's own page or to `authui`, because the library serves JSON.
