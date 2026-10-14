# Sign-In with Ethereum

You will have people sign in with an Ethereum wallet: the page asks the server for a nonce, the wallet signs an ERC-4361 message that carries it, and the server checks the message and the signature before it signs the wallet's user in. A wallet can be the whole account, or the sign-in can ask for an email address; one user can hold many wallets. It is the Go counterpart of better-auth's SIWE plugin.

Use this plugin for a web3 app, a community that gates on wallets, or any product whose users already hold a key and would rather not make a password. It checks who controls an address, not what the address owns: token balances and NFTs are your app's business, read after sign-in.

## Before you start

- An app with sign-in, as in [your first app](../start/first-app.md). Add the [email plugin](email.md) if users should be able to add an address later, or for `RequireEmail`.
- The example program this guide is built from, with a `main_test.go` that signs with a fixed test key and a `README.md` with the same steps: [`examples/siwe-sign-in`](../../examples/siwe-sign-in/). `go run ./siwe-sign-in` in `examples/` serves a page on `localhost:8081` that works with a browser wallet such as MetaMask.
- The plugin is its own module, `github.com/ubgo/auth/plugin/siwe`, because it depends on a secp256k1 library: an app without wallets never compiles it. It does not depend on go-ethereum. `go get github.com/ubgo/auth/plugin/siwe`.
- What it stores: `auth_siwe_wallet`, one row per wallet and chain, owned by one user, address kept lower-case so every spelling of a wallet is one row. Nonces are core verification tokens, stored hashed.
- The reference for every option, route and error is the package's [README](../../plugin/siwe/README.md).

## Step 1 — Wire the plugin

The message must name your site, so the plugin needs `auth.WithBaseURL` (or `siwe.Origins`). Naming the chains you accept refuses a message signed for a test network; by default any chain is accepted, since one key controls the same address on every chain:

<!-- ds:block id=siwe-example-newauth-4k8m2q7w -->
**newAuth** · [`examples/siwe-sign-in/main.go:87-93`](../../examples/siwe-sign-in/main.go#L87-L93)

```go
func newAuth(db *sql.DB) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(plugins()...),
	)
}
```
<!-- /ds:block hash=89e855 -->

`auth.New` refuses the plugin when there is no site to check against (`siwe.ErrNoOrigin`) and `RequireEmail` without the email plugin; every option refuses a nil argument by name.

## Step 2 — The page asks for a nonce, the wallet signs

`POST /auth/siwe/nonce {"walletAddress","chainId"}` answers `{"nonce"}`. The nonce is single use, expires after 15 minutes (`WithNonceTTL`) and is bound to that wallet and chain, so a nonce issued for one wallet cannot sign in another. The page builds the ERC-4361 message with it and has the wallet sign it with `personal_sign`:

<!-- ds:block id=siwe-example-page-9t2w6n4x -->
**pageHTML** · [`examples/siwe-sign-in/main.go:122-146`](../../examples/siwe-sign-in/main.go#L122-L146)

```go
const pageHTML = `<!doctype html>
<meta charset="utf-8">
<title>Sign in with Ethereum</title>
<button id="go">Sign in with Ethereum</button>
<pre id="out"></pre>
<script>
const post = (path, body) => fetch("` + authPrefix + `/siwe" + path, {
  method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body),
}).then(r => r.json());
document.getElementById("go").onclick = async () => {
  const [address] = await ethereum.request({method: "eth_requestAccounts"});
  const chainId = parseInt(await ethereum.request({method: "eth_chainId"}), 16);
  const {nonce} = await post("/nonce", {walletAddress: address, chainId});
  // ERC-4361 asks for the EIP-55 checksummed address (viem's getAddress);
  // the server also accepts the lower-case form wallets return.
  const message = location.host + " wants you to sign in with your Ethereum account:\n" +
    address + "\n\nSign in to the example app.\n\nURI: " + location.origin +
    "\nVersion: 1\nChain ID: " + chainId + "\nNonce: " + nonce +
    "\nIssued At: " + new Date().toISOString();
  const signature = await ethereum.request({method: "personal_sign", params: [message, address]});
  const res = await post("/verify", {message, signature});
  document.getElementById("out").textContent = JSON.stringify(res, null, 2);
};
</script>
`
```
<!-- /ds:block hash=22fcff -->

A real app would build the message with a library such as viem's `createSiweMessage`; the server parses it strictly, so a message that does not follow the format is refused with `siwe.message_invalid`.

## Step 3 — Verify and sign in

`POST /auth/siwe/verify {"message","signature"}`, or `Plugin.Verify` from Go. In this order, the server checks that the message is for this site (its URI is one of your origins and its domain is that origin's host), that the chain is accepted, that the time window holds (issued not in the future and no older than the nonce lifetime, not expired, not before its start, with a minute of clock skew), that the signature recovers to the message's address, and only then consumes the nonce. A check that fails leaves the nonce unspent; a sign-in that happens spends it, so a captured message and signature cannot be replayed:

<!-- ds:block id=siwe-example-test-signin-6h3k9p2m -->
**TestSIWE_FirstSignInCreatesThenSignsIn** · [`examples/siwe-sign-in/main_test.go:80-95`](../../examples/siwe-sign-in/main_test.go#L80-L95)

```go
func TestSIWE_FirstSignInCreatesThenSignsIn(t *testing.T) {
	w := newWorld(t)
	first := w.signIn(t, w.key)
	if !first.Created || first.User.ID == "" || first.Wallet.Address != w.key.Address() || !first.Wallet.Primary {
		t.Fatalf("first sign-in = %+v", first)
	}
	var me meResponse
	w.b.Get("/me").Expect(http.StatusOK).Decode(&me)
	if me.ID != first.User.ID {
		t.Fatalf("/me = %+v", me)
	}
	again := w.signIn(t, w.key)
	if again.Created || again.User.ID != first.User.ID || again.Wallet.ID != first.Wallet.ID {
		t.Fatalf("second sign-in = %+v, want the same user and wallet", again)
	}
}
```
<!-- /ds:block hash=290443 -->

The answer is `{"user", "wallet", "created", "secondFactorRequired"}`, with the session cookie set. The address in the answer is the checksummed (EIP-55) form wallets display; a message may carry any case, because the plugin compares the normalized address.

| Refusal | Code | Status |
|---|---|---|
| Not an ERC-4361 message, or address, chain or nonce disagree with the request | `siwe.message_invalid` | 400 |
| Message for another site | `siwe.domain_invalid` | 400 |
| Chain not in `Chains` | `siwe.chain_invalid` | 400 |
| Outside the time window | `siwe.message_expired` | 400 |
| Unknown, spent, expired or other-wallet nonce | `siwe.nonce_invalid` | 400 |
| Signature is not the address's | `siwe.signature_invalid` | 401 |

None of them depends on whether the wallet has an account, so a refusal reveals nothing about who has signed in before. Nonce and verify are limited to 30 calls per address per minute.

## Step 4 — Several wallets per user

A signed-in user adds a wallet by signing a message for it: `POST /auth/siwe/link {"message","signature"}` (fresh sign-in required, as for any credential change), lists them with `GET /auth/siwe/wallets` and removes one with `POST /auth/siwe/unlink {"id"}`. A wallet another user owns answers `409 siwe.wallet_linked_elsewhere`, and the last way to sign in cannot be removed. A wallet that signs in on a second chain gets a row for that chain under the same user.

## Step 5 — Choose who may sign up

| Situation | Option | What it changes |
|---|---|---|
| A wallet alone is not enough to make an account | `RequireEmail()` | A first sign-in must carry `email`, stored unverified; without it `siwe.email_required`. Needs the email plugin |
| Only people who already have an account may use a wallet | `NoSignUp()` | A first sign-in answers `siwe.sign_up_disabled`; users add wallets with `link` |
| Smart-contract wallets (EIP-1271, EIP-6492) | `WithVerifier(v)` | Replaces the check of the signature. The default, `PersonalSign`, recovers an EIP-191 signature and covers every key-based account; a contract wallet has no key to recover and needs your RPC client |
| The profile should carry an ENS name and avatar | `WithNameResolver(r)` | Looked up for a user the plugin creates; a failed lookup is logged and the user is created without a name. The module ships no RPC client and no vendor connector |
| Domain, URI or lifetime differ from the defaults | `Origins(...)`, `Chains(...)`, `WithNonceTTL(d)` | The sites a message may name, the chains accepted, how long a nonce lives |

## From TypeScript

Use this when a dapp's page signs users in with their wallet. The [typed client](../client/README.md) has the routes as `client.siwe.nonce`, `verify`, `link`, `unlink` and `wallets`; list `siwe()` in `plugins`. The wallet part (`eth_requestAccounts`, `personal_sign`) stays with the wallet library you already use; the block takes it as a function:

<!-- ds:block id=tsp-siwe-signin-6mq2xk8w -->
**signInWithEthereum** · [`clients/ts/examples/plugin-signin.ts:67-84`](../../clients/ts/examples/plugin-signin.ts#L67-L84)

```typescript
export async function signInWithEthereum(address: string, chainId: number, sign: PersonalSign): Promise<boolean> {
  const nonce = await auth.siwe.nonce({ walletAddress: address, chainId });
  if (nonce.error) return false;
  const message = [
    `${location.host} wants you to sign in with your Ethereum account:`,
    address,
    "",
    "Sign in to the example app.",
    "",
    `URI: ${location.origin}`,
    "Version: 1",
    `Chain ID: ${chainId}`,
    `Nonce: ${nonce.data.nonce}`,
    `Issued At: ${new Date().toISOString()}`,
  ].join("\n");
  const { error } = await auth.siwe.verify({ message, signature: await sign(message, address) });
  return error === null; // siwe.signature_invalid, siwe.nonce_invalid, siwe.domain_invalid, ...
}
```
<!-- /ds:block hash=7c5e1e -->

The same message and signature posted to `link` (a fresh session) add the wallet to the signed-in account; `wallets` lists them and `unlink` removes one.

The codes a frontend handles, explained in [Step 3](#step-3--verify-and-sign-in) and [What can go wrong](#what-can-go-wrong): `siwe.message_invalid` (the message does not follow ERC-4361, or disagrees with the nonce request), `siwe.domain_invalid` (the URI or domain is not this site), `siwe.chain_invalid`, `siwe.message_expired`, `siwe.nonce_invalid` (spent, expired, or issued for another wallet: ask for a new nonce), `siwe.signature_invalid`, `siwe.email_required` when the server asks for an address at sign-up (send `email` with `verify`), `siwe.wallet_linked_elsewhere` on `link`.

There is no runnable TypeScript example for Sign-In with Ethereum; the block is type-checked by `task ts:check`, and the example's own page in Step 2 runs the same calls with `fetch` in a browser with a wallet.

Pitfalls:

- **Build the message with a library** (viem's `createSiweMessage`, or `siwe`): the server parses it strictly, and a hand-built string with a missing line or a wrong field order is `siwe.message_invalid`.
- **One nonce per attempt.** It is single use and bound to the wallet and chain it was asked for, so a user who switches account or chain in the wallet needs a new nonce.
- **The page's origin must be one of the server's trusted origins**, because the message's URI and domain are checked against them; a preview deployment on another host is refused with `siwe.domain_invalid`.

Every method with its route and types: [TypeScript client reference › siwe](../reference/ts-client.md#siwe).

## What can go wrong

| Symptom | Cause | Fix |
|---|---|---|
| `siwe.domain_invalid` in development | The page's host differs from `WithBaseURL` | Serve the page from the base URL's host and port, or list the origin in `Origins` |
| `siwe.signature_invalid` for a Safe or Argent wallet | A contract wallet has no key to recover | Pass `WithVerifier` with an EIP-1271 check |
| `siwe.message_expired` right after signing | The server clock is more than a minute off the client's | Fix the clock; the skew allowed is one minute |
| `siwe.nonce_invalid` on a second try | The first attempt reached the nonce check and succeeded, or the nonce expired | Ask for a new nonce for every sign-in attempt |
| Two accounts for one person | They signed up with two wallets | Sign in with the first and `link` the second |

## Next

- [Passkeys](passkey.md): a key the browser holds instead of a wallet.
- [Two-factor](twofactor.md): a second step after a wallet.
- [Admin](admin.md): ban a wallet's user like any other.
