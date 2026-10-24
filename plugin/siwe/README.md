# github.com/ubgo/auth/plugin/siwe

Sign-In with Ethereum (ERC-4361). The guide is [docs/plugins/siwe.md](../../docs/plugins/siwe.md).

## Install

```sh
go get github.com/ubgo/auth/plugin/siwe
```

A separate module: it depends on a secp256k1 library (decred's), never go-ethereum, so an app without wallets never compiles it.

## What it does

- `POST /auth/siwe/nonce {walletAddress, chainId}` gives a single-use, expiring nonce bound to the wallet and chain; `POST /auth/siwe/verify {message, signature}` checks the message (site, chain, time window, nonce) and the signature, then signs in the wallet's user or creates one.
- `POST /auth/siwe/link`, `GET /auth/siwe/wallets` and `POST /auth/siwe/unlink` manage the several wallets of a signed-in user, in `auth_siwe_wallet`.
- Signature checking is a `Verifier`; the default, `PersonalSign`, recovers an EIP-191 signature. A smart-contract wallet (EIP-1271, EIP-6492) needs your RPC client behind `WithVerifier`.
- ENS lookup is the optional `NameResolver`; the module ships no RPC client and no vendor connector.
- `siwe/siwetest` signs messages with a fixed test key, for tests.

## Options

`RequireEmail()`, `NoSignUp()`, `WithVerifier(v)`, `WithNameResolver(r)`, `WithNonceTTL(d)`, `Origins(...)`, `Chains(...)`. Every option refuses a nil or invalid argument by name.

## Errors

`siwe.message_invalid`, `siwe.domain_invalid`, `siwe.chain_invalid`, `siwe.message_expired`, `siwe.nonce_invalid` (400), `siwe.signature_invalid` (401), `siwe.address_invalid`, `siwe.email_required`, `siwe.email_not_accepted` (400), `siwe.sign_up_disabled` (403), `siwe.wallet_linked_elsewhere` (409), `siwe.wallet_not_found` (404).

## Tests

Unit tests in this module with real signatures from a fixed key, replayed nonces, a wrong domain, an expired message and a different checksum case; the flows in [examples/siwe-sign-in](../../examples/siwe-sign-in/).
