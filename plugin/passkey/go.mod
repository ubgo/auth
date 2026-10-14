// Module passkey is the passkey (WebAuthn) plugin. A separate module so the
// WebAuthn library and its dependencies reach only the apps that use it.
module github.com/ubgo/auth/plugin/passkey

go 1.25.0

require (
	github.com/go-webauthn/webauthn v0.17.0
	github.com/ubgo/auth v0.0.0-20261014084637-dc7c057a66dd
	github.com/ubgo/sqlb v0.1.1
)

require (
	github.com/fxamacker/cbor/v2 v2.9.1 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/x v0.2.3 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/uuid v1.6.0
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.50.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
)

// Development inside this repository builds against the working tree. A
// consumer's build ignores replace directives in dependencies.
replace github.com/ubgo/auth => ../../
