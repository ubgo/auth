# github.com/ubgo/auth/plugin/pow

A proof-of-work challenge: when a rate rule (or a geo rule) with the challenge action finds a call suspicious, the client must spend CPU time solving a hashcash puzzle before the call is let through. It is the `auth.RateChallenger` for an app that wants a challenge with no third party in the loop: no captcha provider, no tracking, nothing leaves your server. The guide is [docs/plugins/pow.md](../../docs/plugins/pow.md).

## Install

```sh
go get github.com/ubgo/auth
```

The package is in the core module `github.com/ubgo/auth`, so it brings no extra dependency beyond `github.com/ubgo/sqlb`.

## Wire it

Register the plugin and give a rate rule the challenge action. Under the limit nothing changes; over it, the call answers `428 auth.challenge_required` until it carries a proof:

```go
a, err := auth.New(
	auth.WithDB(db, sqlb.SQLiteDialect{}),
	auth.WithBaseURL(baseURL),
	auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(m)), password.New(), pow.New()),
	auth.WithRateRules(auth.RateRule{Match: password.EndpointSignIn, Key: auth.ByIP, Limit: 5, Window: time.Minute, Action: auth.RateChallenge}),
)
```

[`examples/pow-challenge`](../../examples/pow-challenge/) is a runnable program with a test.

The client's side:

1. `POST /auth/pow/challenge` answers `{"challenge":"<hex>","difficulty":20,"algorithm":"sha256","expiresAt":"…"}`.
2. Find a decimal nonce such that SHA-256 of `<challenge>:<nonce>` starts with at least `difficulty` zero bits. About a million hashes at the default: a fraction of a second in Go, a second or two in a browser.
3. Send the call again with the header `X-Pow-Proof: <challenge>.<nonce>`.

`pow.Solve(ctx, ch)` is the reference solver, for tests, a CLI or a desktop client; it stops when `ctx` ends. A browser runs the same loop in script.

The plugin also answers a geo rule (`auth.WithGeoRules` or `auth.WithImpossibleTravel`) whose `Action` is `auth.RateChallenge`. One proof serves every rule that challenges the same call (`pow.AnnotationVerified` is set on the call once it is accepted), so a call that a rate rule and a geo rule both challenge does not need two.

## Options

| Option | What it does | Default |
|---|---|---|
| `pow.New(opts...)` | The plugin | |
| `pow.Difficulty(bits)` | Leading zero bits a proof needs, 1 to `MaxDifficulty` (32). Each bit doubles the client's expected work; the server's cost stays one hash | `DefaultDifficulty`, 20 |
| `pow.ChallengeTTL(d)` | How long a challenge can be solved and used, positive and at most `MaxChallengeTTL` (one hour) | `DefaultChallengeTTL`, 5 minutes |
| `pow.WithHeader(name)` | Read the proof from another header; must be a valid HTTP header name | `X-Pow-Proof` (`pow.ProofHeader`) |

An option out of range makes `auth.New` fail naming the option. Registering the plugin together with `plugin/captcha` fails `auth.New` too: an app has one rate challenger.

## Routes and Go API

| Route | Go | What it does |
|---|---|---|
| `POST /auth/pow/challenge` | `(*Plugin).Challenge(ctx)` | Issues a challenge (`pow.Challenge`: `challenge`, `difficulty`, `algorithm`, `expiresAt`). Operation id `pow.challenge` (`pow.EndpointChallenge`); limited to 60 a minute per address, since each call writes a row |

| Function | Use |
|---|---|
| `pow.Solve(ctx, ch)` | Finds the proof for a challenge and returns the header value |
| `(*Plugin).PassChallenge(ctx, call)` | The `auth.RateChallenger` method the core calls; not called by apps |

## Tables and columns

None of its own. A challenge is a single-use verification token in the core's store (purpose `pow.challenge`, found by its hash), removed by `a.Sweep` once it expires; a spent challenge also leaves a short-lived marker in the rate store.

## Errors

| Error variable | Code | HTTP | When |
|---|---|---|---|
| `auth.ErrChallengeRequired` | `auth.challenge_required` | 428 | A challenged call carries no proof: fetch a challenge, solve it, send the call again |
| `ErrProofInvalid` | `pow.proof_invalid` | 403 | The proof is malformed or does not carry the work the challenge asked for |
| `ErrChallengeInvalid` | `pow.challenge_invalid` | 400 | The challenge is unknown, expired or already used, one answer for the three; ask for a new one |

## Security notes

| Property | Pinned by |
|---|---|
| The challenge, the proof header and the retry work over HTTP on every engine | `TestPoW_ChallengeFlowOverHTTP` (integration) |
| A malformed proof, a proof short of the difficulty and a reused or unknown challenge are refused | `TestPoW_RefusesProofsThatAreNotWorth` (integration) |
| A proof is judged by the stricter of the configured difficulty and the one the challenge was issued at, so lowering the setting does not cheapen an issued challenge and raising it applies at once | `TestPoW_ChallengeIsJudgedByTheStricterDifficulty` (integration) |
| A proof spent in a sign-in whose transaction rolled back cannot be used again | `TestPoW_AProofSpentInARolledBackSignInIsStillSpent` (integration) |
| One proof serves a rate rule and a geo rule on the same call | `TestPoW_OneProofServesTwoChallengingRules` (integration) |
| A direct Go call is never challenged | `TestPoW_AGoCallIsNotChallenged` (integration) |
| Every operation answers on the wire with proof of work as the challenger | `TestWireContract_ProofOfWork` (integration) |

Bad proofs are cheap to refuse: the shape and the work are checked with one hash before the store is read. The challenge is 128 random bits and is looked up by its hash, never compared as plaintext.

Limits: proof of work makes a flood cost the sender CPU time per attempt; it is not a bot detector. An attacker with enough hardware pays the cost and carries on, so keep the rate limits, and use a captcha where a human check is what you need.

## Example

- [`examples/pow-challenge`](../../examples/pow-challenge/): a runnable program with a README and a test.
- Guide: [docs/plugins/pow.md](../../docs/plugins/pow.md)
- API reference: https://pkg.go.dev/github.com/ubgo/auth/plugin/pow
