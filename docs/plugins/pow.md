# Proof of work

You will have a rate rule (or a geo rule) that, instead of refusing a suspicious call, asks the client to spend CPU time on a hashcash puzzle first. No captcha provider is in the loop, nobody is tracked and nothing leaves your server: the client hashes, the server checks the result with one hash.

Use it where a person behind a busy shared address (an office, a school, a carrier's NAT) should be slowed rather than shut out, and where a captcha is not welcome. It makes a flood of guesses cost the sender per guess. It is not a bot detector: an attacker with enough hardware pays the cost and carries on, so the rate limits stay, and a captcha is the tool when a human check is what you need.

## Before you start

- [Rate limits](../concepts/rate-limits.md), Step 5: the `RateChallenge` action this plugin answers.
- The example is [`examples/pow-challenge`](../../examples/pow-challenge/): password sign-in limited to three calls a minute per address, the fourth asked for work. `go run ./pow-challenge` in `examples/` serves it on `localhost:8081`; `go test ./pow-challenge` runs the flow below at 8 bits so it takes milliseconds.
- What the plugin stores: no table and no column. A challenge is a single-use verification token in the core's store (purpose `pow.challenge`, found by its hash), removed by `a.Sweep` once it expires; a spent challenge also leaves a short-lived marker in the rate store.
- It cannot be registered together with [`plugin/captcha`](captcha.md): both are rate challengers, and `auth.New` refuses two, because a client could not tell which one to satisfy.

## Step 1 — Register the plugin and challenge a rule

Registering the plugin makes it the app's `auth.RateChallenger`; nothing is challenged until a rule says so:

<!-- ds:block id=powchallenge-example-plugins-4vn8qk2w -->
**plugins** · [`examples/pow-challenge/main.go:104-110`](../../examples/pow-challenge/main.go#L104-L110)

```go
func plugins(difficulty int) []auth.Plugin {
	return []auth.Plugin{
		email.New(email.Login(), email.Recover(), email.WithMailer(email.MailerFunc(logMail))),
		password.New(),
		pow.New(pow.Difficulty(difficulty)),
	}
}
```
<!-- /ds:block hash=8ea967 -->

<!-- ds:block id=powchallenge-example-rule-7kq3wn5x -->
**signInRule** · [`examples/pow-challenge/main.go:93-95`](../../examples/pow-challenge/main.go#L93-L95)

```go
func signInRule() auth.RateRule {
	return auth.RateRule{Match: password.EndpointSignIn, Key: auth.ByIP, Limit: freeSignIns, Window: time.Minute, Action: auth.RateChallenge}
}
```
<!-- /ds:block hash=a81ee1 -->

Under the limit nothing changes and a proof sent is ignored. Over it, a call without a proof answers `428 auth.challenge_required`.

Check: `auth.New` with a `RateChallenge` rule and neither pow nor captcha registered fails with `rate rule for "password.sign-in" challenges, and no challenger is registered`.

## Step 2 — Issue and solve a challenge

`POST /auth/pow/challenge` (from Go, `Plugin.Challenge(ctx)`) issues a [`pow.Challenge`](ds:block?id=pow-challenge-6zt4qn8k): 128 random bits as hex, the difficulty, the algorithm (`sha256`, the only one) and the expiry. The route is public and limited to 60 calls a minute per address, since each call writes a row.

The client finds a decimal nonce, counting up from 0, such that SHA-256 of the text `<challenge>:<nonce>` starts with at least `difficulty` zero bits, and sends the call again with the header [`X-Pow-Proof`](ds:block?id=proofheader-pow-5qm8tk3w) set to `<challenge>.<nonce>`. At the default [20 bits](ds:block?id=pow-defaultdifficulty-2vk9wq6n) that is about a million hashes: a fraction of a second in Go, a second or two in a browser with `crypto.subtle.digest`. [`pow.Solve(ctx, ch)`](ds:block?id=pow-solve-3xq8wn5v) is the reference solver, for tests, a CLI or a desktop client; it stops when `ctx` ends.

Four sign-ins against the example; the fourth asks for work:

```sh
O='Origin: http://localhost:8081'
curl -s -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"ada@example.com","password":"correct horse battery staple","name":"Ada"}'
for i in 1 2 3 4; do curl -s -o /dev/null -w '%{http_code}\n' -X POST localhost:8081/auth/password/sign-in -H "$O" -d '{"identifier":"ada@example.com","password":"correct horse battery staple"}'; done
```

```json
{"error":{"code":"auth.challenge_required","message":"Complete the challenge and try again."}}
```

Fetch a challenge, solve it (Python stands in for the client's own loop) and send the call with the proof:

```sh
CH=$(curl -s -X POST localhost:8081/auth/pow/challenge -H "$O" -d '{}')
PROOF=$(echo "$CH" | python3 -c '
import hashlib, json, sys
c = json.load(sys.stdin); ch, d, n = c["challenge"], c["difficulty"], 0
while int.from_bytes(hashlib.sha256(f"{ch}:{n}".encode()).digest(), "big") >> (256 - d):
    n += 1
print(f"{ch}.{n}")')
curl -s -X POST localhost:8081/auth/password/sign-in -H "$O" -H "X-Pow-Proof: $PROOF" -d '{"identifier":"ada@example.com","password":"correct horse battery staple"}'
```

```text
{"challenge":"59e7cb96021fc4a1f5b9dac0736387ed","difficulty":20,"algorithm":"sha256","expiresAt":"2026-10-10T04:09:37.13947Z"}
59e7cb96021fc4a1f5b9dac0736387ed.654920
```

The sign-in answers 200 with the user and the session. The same proof sent again is refused:

```json
{"error":{"code":"pow.challenge_invalid","message":"The challenge has expired. Request a new one."}}
```

<!-- ds:block id=powchallenge-example-test-flow-9wq2kn6v -->
**TestPoW_ChallengeOnlyOverTheLimitAndEachProofOnce** · [`examples/pow-challenge/main_test.go:106-118`](../../examples/pow-challenge/main_test.go#L106-L118)

```go
func TestPoW_ChallengeOnlyOverTheLimitAndEachProofOnce(t *testing.T) {
	_, b := world(t)
	useFreeSignIns(t, b)
	over := signIn(t, b, "").Expect(http.StatusPreconditionRequired)
	if over.ErrorCode() != auth.ErrChallengeRequired.Code {
		t.Fatalf("over the limit: %s", over.Body)
	}
	proof := solve(t, challenge(t, b))
	signIn(t, b, proof).Expect(http.StatusOK)
	if code := signIn(t, b, proof).Expect(pow.ErrChallengeInvalid.Status).ErrorCode(); code != pow.ErrChallengeInvalid.Code {
		t.Fatalf("the same proof again: %s, want %s", code, pow.ErrChallengeInvalid.Code)
	}
}
```
<!-- /ds:block hash=c755d5 -->

Check: `go test ./pow-challenge` in `examples/` passes.

## Step 3 — Know how a proof is judged

[`PassChallenge`](ds:block?id=passchallenge-pow-4wn7qk2z) lets a direct Go call through (the app's own code is not the flood) and answers `auth.challenge_required` when the header is missing. A proof is then checked in the order that keeps a bad one cheap:

1. Its shape and its work, with one hash and no database, against the configured difficulty, so garbage and low-effort proofs never reach the store (`403 pow.proof_invalid`).
2. The challenge, in one single-use read: it must be one this server issued, unexpired and unspent (`400 pow.challenge_invalid`, one answer for the three), and the work must also meet the difficulty the challenge was issued at. The stricter of the two applies, so lowering the setting does not cheapen a challenge already out, and raising it applies at once.
3. A replay marker in the rate store, which survives the rollback of a transaction the proof was spent in, so a proof cannot be reused after the sign-in it was spent on failed.

A proof without enough work is refused before the challenge is touched, so the honest proof for the same challenge still works. One accepted proof serves every rule that challenges the same call (`pow.AnnotationVerified` is set on it), so a call that a rate rule and a geo rule both challenge does not need two. Nothing compares a secret: the challenge is found by its hash, never compared as plaintext.

Check: `TestPoW_RefusesProofsThatAreNotWorth` and `TestPoW_AProofSpentInARolledBackSignInIsStillSpent` in `integration/pow_test.go`, on every engine.

## Step 4 — Tune the work

| Option | What it does | Default |
|---|---|---|
| `pow.Difficulty(bits)` | Leading zero bits a proof needs, 1 to `pow.MaxDifficulty` (32). Each bit doubles the client's expected work; the server's cost stays one hash | `pow.DefaultDifficulty`, 20 |
| `pow.ChallengeTTL(d)` | How long a challenge can be solved and used, positive and at most `pow.MaxChallengeTTL` (one hour) | [`pow.DefaultChallengeTTL`](ds:block?id=pow-defaultchallengettl-8nr3xk5m), 5 minutes |
| `pow.WithHeader(name)` | Read the proof from another header; must be a valid HTTP header name | `X-Pow-Proof` (`pow.ProofHeader`) |

An option out of range makes `auth.New` fail naming it. Measure the difficulty on the slowest device you support: 2^32 hashes is beyond a phone and a browser tab, which is why 32 is the cap.

## Step 5 — Challenge by country or travel

A [geo rule](../concepts/geo-rules.md) with `Action: auth.RateChallenge` asks this plugin too:

```go
auth.WithGeoRules(auth.GeoRules{Deny: []string{"RU"}, Action: auth.RateChallenge})
```

The country rule asks before the credentials are read; impossible travel asks after them, where the session is created. Either way the client sees the same `428` and the same header.

## From TypeScript

Use this when a browser or app page has to answer a proof-of-work challenge. The [typed client](../client/README.md) has the one route as `client.pow.challenge`; list `pow()` in `plugins`. The challenged call is another plugin's method: when it answers `auth.challenge_required`, the page fetches a puzzle, solves it with `crypto.subtle`, and sends the same call again with the proof in the `X-Pow-Proof` header through the per-call `headers` option ([Reference › Per-call headers](../client/reference.md#per-call-headers)):

<!-- ds:block id=tsp-pow-retry-4mw8kq3x -->
**signInWithWork** · [`clients/ts/examples/plugin-headers.ts:45-54`](../../clients/ts/examples/plugin-headers.ts#L45-L54)

```typescript
export async function signInWithWork(identifier: string, secret: string): Promise<boolean> {
  const first = await auth.password.signIn({ identifier, password: secret });
  if (first.error?.code !== "auth.challenge_required") return first.error === null;
  const puzzle = await auth.pow.challenge();
  if (puzzle.error) return false;
  const nonce = await solve(puzzle.data.challenge, puzzle.data.difficulty);
  const proof = `${puzzle.data.challenge}.${nonce}`;
  const second = await auth.password.signIn({ identifier, password: secret }, { headers: { "X-Pow-Proof": proof } });
  return second.error === null;
}
```
<!-- /ds:block hash=098fac -->

The codes a frontend handles, explained in [Step 3](#step-3--know-how-a-proof-is-judged) and [What can go wrong](#what-can-go-wrong): `auth.challenge_required` (solve and retry), `pow.proof_invalid` (the proof is malformed or its work does not meet the difficulty: fetch a new puzzle once, and if it repeats the solver is wrong), `pow.challenge_invalid` (unknown, expired or already spent: fetch a new puzzle), `auth.rate_limited` on `challenge` itself.

There is no runnable TypeScript example for proof of work; the block is type-checked by `task ts:check`, and Step 2 shows the same exchange with curl and a Python solver.

Pitfalls:

- **A proof works once.** A retry after any failure, a network error included, needs a new challenge and a new solve.
- **Solve off the main thread for high difficulties.** At the default 20 bits the loop above takes a second or two in a browser and blocks input meanwhile; a Web Worker keeps the page responsive.
- **Count leading zero bits of the whole hash**, as the block does, not zero hex characters: a difficulty is in bits, so a solver that counts nibbles is wrong for any difficulty that is not a multiple of four.

Every method with its route and types: [TypeScript client reference › pow](../reference/ts-client.md#pow).

## What can go wrong

| Symptom | Cause | Fix |
|---|---|---|
| `428 auth.challenge_required` on a call that sent a proof | The header name differs (`pow.WithHeader`), or a proxy strips unknown headers | Send the configured header; let it through the proxy |
| `403 pow.proof_invalid` | The proof is not `<challenge>.<nonce>`, the nonce is not decimal, or the hash has too few zero bits for the configured or the issued difficulty | Hash the text `<challenge>:<nonce>`, not the bytes of either; count bits, not hex digits |
| `400 pow.challenge_invalid` | The challenge expired, was used, or was never issued by this server | Ask for a new challenge per call |
| `auth.New` fails naming two challengers | `plugin/pow` and `plugin/captcha` are both registered, or one of them and `auth.WithRateChallenger` | Keep one |
| Clients on old phones time out | The difficulty is too high for them | Lower `pow.Difficulty`; each bit halves the work |

## Next

- [Rate limits](../concepts/rate-limits.md): the actions and the rules this plugin answers.
- [Captcha](captcha.md): the other challenger, when a human check is what you need.
- [Geo rules](../concepts/geo-rules.md): country rules and impossible travel, which can challenge too.
- [Security events](../concepts/security-events.md): a challenged and a passed call are both reported.
