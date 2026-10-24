# Sign in with an Ethereum wallet

The page asks the server for a nonce, the wallet signs an ERC-4361 message that carries it, and the server checks the message and the signature. A wallet's first sign-in creates the account. The guide is [docs/plugins/siwe.md](../../docs/plugins/siwe.md).

## Run it

```sh
cd examples
go run ./siwe-sign-in
```

It creates `siwe-sign-in.db` (SQLite) and listens on `http://localhost:8081`. Open that address in a browser with a wallet extension such as MetaMask and press the button; the page runs the three steps below. Run the tests with `go test ./siwe-sign-in`, which sign with a fixed test key (`siwetest`) instead of a wallet.

## Walkthrough

1. `POST /auth/siwe/nonce {"walletAddress","chainId"}` answers `{"nonce"}`, single use and bound to that wallet and chain.
2. The wallet signs the message with `personal_sign`. The message names this site: its domain and URI must match the app's base URL, or the sign-in is refused with `siwe.domain_invalid`.
3. `POST /auth/siwe/verify {"message","signature"}` answers the user, the wallet and `created`, and sets the session cookie. The same message and signature a second time is `siwe.nonce_invalid`.

## What the tests prove

`main_test.go` signs with the Hardhat test key: the first sign-in creates, the second reuses the user and wallet; a replayed message and an invented nonce are refused; a message for another domain or an expired one is refused; the same address in a different checksum case is the same wallet; a bad signature or a request that disagrees with the message is refused; `RequireEmail` asks for an address at the first sign-in; and a second wallet links to the signed-in user while a wallet of another user is refused.
