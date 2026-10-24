# Ask for proof of work instead of blocking

The same story as [rate-actions](../rate-actions), with `plugin/pow` as the rate challenger in place of a captcha: password sign-in is limited to three calls a minute per address, and the fourth must carry a solved proof-of-work challenge. No third party is in the loop and nobody is tracked; the client spends CPU time and the server checks the result with one hash. It makes a flood of sign-in guesses cost the sender per guess, which a person behind a busy shared address barely notices once. It is not a bot detector: an attacker with enough hardware pays and carries on, so the rate limits stay. The guide is the "Actions" section of [docs/concepts/rate-limits.md](../../docs/concepts/rate-limits.md).

## Run it

```sh
cd examples
go run ./pow-challenge
```

It creates `pow-challenge.db` (SQLite) and listens on `http://localhost:8081` (`PORT` overrides it). The program uses `pow.DefaultDifficulty`, 20 zero bits, about a million hashes: a fraction of a second in Go, a second or two in a browser. The tests use 8 bits so they run in milliseconds. Run the tests with `go test ./pow-challenge`.

`plugin/pow` and `plugin/captcha` are both rate challengers, and `auth.New` refuses an app that registers both. Each is configured with `pow.Difficulty` (1 to `pow.MaxDifficulty`), `pow.ChallengeTTL` (default `pow.DefaultChallengeTTL`, five minutes) and `pow.WithHeader` (default `pow.ProofHeader`, `X-Pow-Proof`).

## The hashing rule

A client in any language can solve a challenge:

1. `POST /auth/pow/challenge` (from Go, `Plugin.Challenge`) answers `{"challenge":"<32 hex chars>","difficulty":D,"algorithm":"sha256","expiresAt":"…"}`.
2. Find a decimal nonce, counting up from 0, such that SHA-256 of the text `<challenge>:<nonce>` starts with at least `D` zero bits.
3. Send the call again with the header `X-Pow-Proof: <challenge>.<nonce>`.

`pow.Solve` is the reference solver in Go, for tests, a CLI or a desktop app; a browser runs the same loop in script with `crypto.subtle.digest`. A challenge is single use and expires; a proof without enough work is refused before the challenge is touched, so the honest proof for it still works.

## Walkthrough

Sign up, then sign in four times:

```sh
O='Origin: http://localhost:8081'
curl -s -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"ada@example.com","password":"correct horse battery staple","name":"Ada"}'
for i in 1 2 3 4; do curl -s -o /dev/null -w '%{http_code}\n' -X POST localhost:8081/auth/password/sign-in -H "$O" -d '{"identifier":"ada@example.com","password":"correct horse battery staple"}'; done
```

The first three answer 200 and the fourth asks for work:

```json
{"error":{"code":"auth.challenge_required","message":"Complete the challenge and try again."}}
```

Fetch a challenge, solve it (here with Python, standing in for the client's own loop) and send the call with the proof:

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

The sign-in answers 200 with the user and session. The same proof sent a second time is refused:

```json
{"error":{"code":"pow.challenge_invalid","message":"The challenge has expired. Request a new one."}}
```

## What the tests prove

`main_test.go`: under the limit no proof is needed; over it a call without a proof is `428 auth.challenge_required`; a solved challenge goes through; the same proof used again is refused with `pow.challenge_invalid`; a nonce whose hash has too few zero bits (counted by the test itself, not by the plugin) is refused with `pow.proof_invalid` and leaves the challenge usable; a challenge sent after `pow.DefaultChallengeTTL` on the test clock is refused with `pow.challenge_invalid`. The plugin's other cases (a proof judged by the stricter of the issued and the configured difficulty, a proof spent inside a sign-in that rolled back, one proof for two challenging rules, Go calls never challenged) are walked in [integration/pow_test.go](../../integration/pow_test.go).
