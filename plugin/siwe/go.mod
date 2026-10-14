// Module siwe is the Sign-In with Ethereum (ERC-4361) plugin. A separate
// module so the secp256k1 and Keccak libraries reach only the apps that use
// it.
module github.com/ubgo/auth/plugin/siwe

go 1.25.0

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1
	github.com/ubgo/auth v0.1.0
	github.com/ubgo/sqlb v0.1.1
	golang.org/x/crypto v0.50.0
)

require golang.org/x/sys v0.43.0 // indirect
