# Referrals

You will have user-to-user referrals: every user has a code, a sign-up that brings one records who referred whom, a referral completes once the steps you require are recorded (sign-up always, then your own such as a first purchase), your code grants the reward exactly once, and each user sees a dashboard and the list of people they referred.

Use this plugin for a "give $10, get $10" program, a waitlist that moves people up when their friends join, or any growth loop where a reward depends on what the referred person does after signing up. It does not close sign-up: for that, see [invites](invite.md).

## Before you start

- An app with sign-in, as in [your first app](../start/first-app.md).
- The example program this guide is built from, with a `main_test.go` that drives the same steps and a `README.md` with the same transcript: [`examples/referral`](../../examples/referral/). `go run ./referral` in `examples/` serves it on `localhost:8081`.
- The plugin is its own module, `github.com/ubgo/auth/plugin/referral`, because referrals are not authentication: an app without them never compiles it. `go get github.com/ubgo/auth/plugin/referral`.
- What it stores: `auth_referral_code` (one code per user), `auth_referral` (one row per referred user, unique) and `auth_referral_step` (one row per step reached, with the metadata you pass).
- The reference for every option, route and error is the package's [README](../../plugin/referral/README.md).

## Step 1 — Wire the plugin with your steps and your reward

A step is a name of your choosing for something the referred user must do before the referral pays out. The example has one, a first purchase; the name is stored with each step, so it must not change once referrals are recorded:

<!-- ds:block id=stepfirstpurchase-me5ky9sj -->
**StepFirstPurchase** · [`examples/referral/main.go:59`](../../examples/referral/main.go#L59-L59)

```go
"first_purchase"
```
<!-- /ds:block hash=cb4408 -->

<!-- ds:block id=newapp-s4mxwkng -->
**newApp** · [`examples/referral/main.go:126-139`](../../examples/referral/main.go#L126-L139)

```go
func newApp(db *sql.DB, m email.Mailer) (*app, error) {
	x := &app{db: db}
	x.referrals = referral.New(
		referral.Steps(StepFirstPurchase),
		referral.AfterCompleted(x.reward),
	)
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(m)), password.New(), x.referrals),
	)
	x.auth = a
	return x, err
}
```
<!-- /ds:block hash=099cbc -->

`auth.New` refuses steps that repeat, are empty or untrimmed, or name the reserved `sign_up`.

`AfterCompleted` is where the reward goes. It runs once per referral, after the step that completed it commits, so a balance update there cannot pay twice; it cannot fail the referral either, which has already happened, so log a failure for a retry rather than dropping it:

<!-- ds:block id=app-reward-zr85bp6m -->
**app.reward** · [`examples/referral/main.go:147-154`](../../examples/referral/main.go#L147-L154)

```go
func (x *app) reward(ctx context.Context, e referral.Event) {
	_, err := x.db.ExecContext(ctx,
		`INSERT INTO app_credit (user_id, cents) VALUES (?, ?) ON CONFLICT (user_id) DO UPDATE SET cents = cents + excluded.cents`,
		e.Referrer.ID, rewardCents)
	if err != nil {
		log.Printf("referral %s: credit %s: %v", e.ReferralID, e.Referrer.ID, err)
	}
}
```
<!-- /ds:block hash=548878 -->

## Step 2 — Sign up with a code

Every new user gets a code of eight letters and digits, read from `GET /auth/referral/dashboard`. A sign-up brings someone's code in the [`Referral-Code`](ds:block?id=referralheader-dmcrtk6w) header, in any case, or, for an OAuth sign-up whose callback carries no header, through `POST /auth/referral/remember {"code"}` first, which keeps it in the cookie `__Host-auth_referral` for an hour. A code that names nobody refuses the sign-up with `400 referral.invalid_code`:

<!-- ds:block id=plugin-datahooks-h9da73gq -->
**Plugin.DataHooks** · [`plugin/referral/referral.go:375-397`](../../plugin/referral/referral.go#L375-L397)

```go
func (p *Plugin) DataHooks() auth.DataHooks {
	return auth.DataHooks{User: auth.TableHooks[auth.User]{AfterCreate: func(ctx context.Context, _ sqlb.DBTX, u *auth.User) error {
		code := requestCode(ctx)
		var referrer string
		if code != "" {
			id, ok, err := p.owner(ctx, code)
			if err != nil {
				return err
			}
			if !ok {
				return ErrInvalidCode
			}
			referrer = id
		}
		if _, err := p.codeOf(ctx, u.ID); err != nil {
			return err
		}
		if referrer == "" {
			return nil
		}
		return p.refer(ctx, referrer, *u, code)
	}}}
}
```
<!-- /ds:block hash=dc3035 -->

```sh
O='Origin: http://localhost:8081'
P='"password":"correct horse battery staple"'
curl -s -c alice.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -d "{\"identifier\":\"alice@example.com\",$P,\"name\":\"Alice\"}"
curl -s -b alice.txt localhost:8081/auth/referral/dashboard
curl -s -c bob.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -H 'Referral-Code: WIDCY3VM' -d "{\"identifier\":\"bob@example.com\",$P,\"name\":\"Bob\"}"
curl -s -c carol.txt -b carol.txt -X POST localhost:8081/auth/referral/remember -H "$O" -d '{"code":"WIDCY3VM"}'
curl -s -c carol.txt -b carol.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -d "{\"identifier\":\"carol@example.com\",$P,\"name\":\"Carol\"}"
curl -s -X POST localhost:8081/auth/password/sign-up -H "$O" -H 'Referral-Code: ZZZZZZZZ' -d "{\"identifier\":\"dave@example.com\",$P,\"name\":\"Dave\"}"
```

The dashboard, Bob's sign-up, Carol's `remember`, and Dave's refusal (Alice's and Carol's sign-up answers left out):

```json
{"code":"WIDCY3VM","stats":{"total":0,"completed":0,"pending":0,"joinedToday":0}}
{"user":{"id":"usr_5atbm7kou77jizlsosyp7xfy","name":"Bob","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"ok":true}
{"error":{"code":"referral.invalid_code","message":"This referral code is not valid."}}
```

## Step 3 — Record the steps that complete a referral

A step is your statement that a reward was earned, so it is recorded from Go only, never by a client. The example's purchase handler records the order, then the step; a buyer nobody referred answers `referral.ErrNotFound`, which is not an error for a purchase:

<!-- ds:block id=app-handler-3gwp4pzy -->
**app.handler** · [`examples/referral/main.go:160-169`](../../examples/referral/main.go#L160-L169)

```go
func (x *app) handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(x.auth, authhttp.Prefix(authPrefix)))
	signedIn := func(h http.HandlerFunc) http.Handler {
		return authhttp.Middleware(x.auth)(authhttp.RequireUser(h))
	}
	mux.Handle("POST /purchase", signedIn(x.purchase))
	mux.Handle("GET /credit", signedIn(x.credit))
	return mux
}
```
<!-- /ds:block hash=13fe6a -->

<!-- ds:block id=app-purchase-fbp9p3q5 -->
**app.purchase** · [`examples/referral/main.go:189-218`](../../examples/referral/main.go#L189-L218)

```go
func (x *app) purchase(w http.ResponseWriter, r *http.Request) {
	var in purchaseRequest
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Item == "" {
		http.Error(w, "item is required", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	u := authhttp.MustUser(r)
	res, err := x.db.ExecContext(ctx, `INSERT INTO app_purchase (user_id, item) VALUES (?, ?)`, u.ID, in.Item)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	out := purchaseResponse{}
	if out.OrderID, err = res.LastInsertId(); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	step, err := x.referrals.MarkStep(ctx, u.ID, StepFirstPurchase, map[string]string{"item": in.Item})
	switch {
	case errors.Is(err, referral.ErrNotFound):
	case err != nil:
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	default:
		out.ReferralStatus = step.Status
		out.ReferralCompleted = !step.AlreadyCompleted && step.Status == referral.StatusCompleted
	}
	writeJSON(w, out)
}
```
<!-- /ds:block hash=4fd805 -->

Recording a step twice changes nothing and runs no callback; the step that completes the referral runs `AfterCompleted` once, after the commit:

<!-- ds:block id=plugin-markstep-sk2dyp6p -->
**Plugin.MarkStep** · [`plugin/referral/referral.go:556-583`](../../plugin/referral/referral.go#L556-L583)

```go
func (p *Plugin) MarkStep(ctx context.Context, referredUserID, step string, metadata map[string]string) (StepResult, error) {
	if p.core == nil {
		return StepResult{}, auth.ErrOperationNotWired
	}
	known := false
	for _, s := range p.Required() {
		known = known || s == step
	}
	if !known {
		return StepResult{}, ErrUnknownStep
	}
	var out StepResult
	err := p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		var r ref
		err := p.core.One(ctx, p.core.Select().Columns(sqlb.Bind(ReferralID, &r.id), sqlb.Bind(ReferralReferrer, &r.referrer),
			sqlb.Bind(ReferralReferred, &r.referred), sqlb.Bind(ReferralStatus, &r.status)).
			From(TableReferral).Where(sqlb.Eq(ReferralReferred, referredUserID)).Limit(1))
		if errors.Is(err, sqlb.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		out, err = p.markStep(ctx, r, step, metadata)
		return err
	})
	return out, err
}
```
<!-- /ds:block hash=9b1ac0 -->

```sh
curl -s -b bob.txt -X POST localhost:8081/purchase -H "$O" -d '{"item":"book"}'
curl -s -b bob.txt -X POST localhost:8081/purchase -H "$O" -d '{"item":"pen"}'
curl -s -b alice.txt localhost:8081/credit
```

```json
{"orderId":1,"referralCompleted":true,"referralStatus":"completed"}
{"orderId":2,"referralCompleted":false,"referralStatus":"completed"}
{"cents":1000}
```

Check: `TestReferral_FirstPurchaseCompletesAndRewardsOnce` in the example, and [TestP3CommunityReferral](ds:block?id=testp3communityreferral-ht6p5vdu), which runs the whole flow on SQLite, Postgres and MySQL.

## Step 4 — The dashboard and the list

| Route | Go method | Answer |
|---|---|---|
| `GET /auth/referral/dashboard` | `MyDashboard` | `{code, stats{total, completed, pending, joinedToday}}`; creates the code of a user from before the plugin |
| `GET /auth/referral/list` | `List` | `{code, referrals[{id, status, completedAt, createdAt, progress, referredUser{id, name, email, image}}], total, limit, offset}`, newest first, twenty per page |

```sh
curl -s -b alice.txt localhost:8081/auth/referral/list
```

```json
{"code":"WIDCY3VM","referrals":[{"id":"rfl_s6x6hlbvlgyc2ihtjxg4i7ro","status":"pending","completedAt":null,"createdAt":"2026-10-09T03:10:53.740006Z","progress":{"requiredSteps":["sign_up","first_purchase"],"completedSteps":["sign_up"],"remainingSteps":["first_purchase"],"completed":1,"total":2,"isCompleted":false},"referredUser":{"id":"usr_ctrz74ie5pj2eh23e77hni2s","name":"Carol","email":"c***@example.com"}},{"id":"rfl_56miyovkjeoj67n7qsbyy3gn","status":"completed","completedAt":"2026-10-09T03:10:53.917931Z","createdAt":"2026-10-09T03:10:53.601388Z","progress":{"requiredSteps":["sign_up","first_purchase"],"completedSteps":["sign_up","first_purchase"],"remainingSteps":[],"completed":2,"total":2,"isCompleted":true},"referredUser":{"id":"usr_5atbm7kou77jizlsosyp7xfy","name":"Bob","email":"b***@example.com"}}],"total":2,"limit":20,"offset":0}
```

Referred users' addresses read `b***@example.com` unless `ShowEmails()`: the referrer did not need the address to refer them.

## Options you may want

| Situation | Option | What it changes |
|---|---|---|
| A referral pays out only after more than the sign-up | `Steps(steps...)` | Steps after sign-up a referral needs to complete. Default none: sign-up completes it |
| Referrers must see who joined | `ShowEmails()` | Unmasked addresses in `list` |
| Vanity or branded codes | `GenerateCode(fn)` | Output must be eight letters and digits; a taken or malformed draw is drawn again, ten failures are `ErrNoCode` |
| Notify, grant or track | `AfterSignUp(fn)`, `AfterStep(fn)`, `AfterCompleted(fn)` | Run after the commit; they cannot fail what already happened |

## From TypeScript

Use this when the landing page, the sign-up form and the "invite your friends" page run in a browser or an app. The [typed client](../client/README.md) has the routes as `client.referral.dashboard`, `list` and `remember`; list `referral()` in `plugins`. A sign-up carries the referrer's code in the `Referral-Code` header, through the per-call `headers` option, and any sign-up method records it; before an OAuth sign-up, whose callback carries no header, the landing page calls `remember`:

<!-- ds:block id=tsp-referral-signup-6nx2qk8w -->
**signUpReferred** · [`clients/ts/examples/plugin-headers.ts:82-88`](../../clients/ts/examples/plugin-headers.ts#L82-L88)

```typescript
export async function signUpReferred(address: string, secret: string, code: string): Promise<boolean> {
  const { error } = await auth.password.signUp(
    { identifier: address, password: secret },
    { headers: { "Referral-Code": code } },
  );
  return error === null;
}
```
<!-- /ds:block hash=ee3d1c -->

The referrer's page shows the code to share and the people who joined with it:

<!-- ds:block id=tsp-referral-dashboard-2wq9kn4x -->
**referralSummary** · [`clients/ts/examples/plugin-headers.ts:97-103`](../../clients/ts/examples/plugin-headers.ts#L97-L103)

```typescript
export async function referralSummary(): Promise<string> {
  const board = await auth.referral.dashboard();
  if (board.error) return board.error.message;
  const list = await auth.referral.list({ limit: 20 });
  const names = (list.data?.referrals ?? []).map((r) => `${r.referredUser.name} (${r.progress.completed}/${r.progress.total})`);
  return `Code ${board.data.code}: ${board.data.stats.completed} of ${board.data.stats.total} completed. ${names.join(", ")}`;
}
```
<!-- /ds:block hash=28990e -->

The codes a frontend handles, explained in [What can go wrong](#what-can-go-wrong): `referral.invalid_code` (the code names nobody; the sign-up is refused rather than completed without the referral, so check it with `remember` on the landing page first), `referral.not_found`, `auth.rate_limited`.

There is no runnable TypeScript example for referrals; the blocks above are type-checked by `task ts:check`, and Step 2 shows the same calls with curl.

Pitfalls:

- **A bad code fails the whole sign-up.** Send `Referral-Code` only when a code was given, and validate it with `remember` when the visitor lands, not at submit.
- **`remember` keeps the code for an hour in a cookie**, so it reaches an OAuth sign-up started in the same browser; a sign-up on another device, or later, is not referred.
- **`list` takes `limit` and `offset` as numbers**, unlike most query inputs, because the Go struct declares them as integers.

Every method with its route and types: [TypeScript client reference › referral](../reference/ts-client.md#referral).

## What can go wrong

| Symptom | Cause | Fix |
|---|---|---|
| `400 referral.invalid_code` at sign-up | The code names nobody; the sign-up is refused rather than completed without the referral | Call `remember` first on the landing page, which refuses a bad code before the visitor fills the form |
| An OAuth sign-up is not recorded as referred | The provider's callback carries no `Referral-Code` header | `POST /auth/referral/remember` before the redirect, so the cookie travels with the callback; it lasts an hour |
| `referral.unknown_step` from `MarkStep` | A step that was not passed to `Steps` | Add it to `Steps`; names must match exactly |
| `referral.not_found` from `MarkStep` | The user was not referred | Treat it as "nothing to record", as the example's purchase handler does |
| The reward is paid twice | The grant runs in `AfterStep` or in your purchase code instead of `AfterCompleted` | Grant in `AfterCompleted`, which runs once per referral even when two steps race |
| A reward is missing after an error | `AfterCompleted` runs after the commit and cannot fail the referral | Log or queue the failure and retry from your own job; the referral row stays `completed` |
| `400 auth.bad_request` from `MarkStep` | The metadata encodes to more than 4096 bytes of JSON | Store an order id, not the order |
| `429` from `remember` | It allows 30 calls per IP per minute | Wait for the window to pass |

## Next

- [Invites](invite.md): close sign-up to people an existing member vouched for.
- [Audit log](audit.md): who signed up when, for a referral dispute.
- [Write a plugin](../extending/01-plugin-anatomy.md): [`examples/custom-plugin`](../../examples/custom-plugin/) builds a smaller referral plugin from scratch, as a lesson in writing one.
