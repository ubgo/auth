// Module integration holds the end-to-end tests that need a real database.
//
// It is a SEPARATE module on purpose: the three drivers it needs would
// otherwise appear in the root go.mod, and every consumer of the library would
// inherit dependencies they never build. The root module depends on sqlb
// only.
module github.com/ubgo/auth/integration

go 1.25.0

require (
	github.com/fxamacker/cbor/v2 v2.9.1
	github.com/go-sql-driver/mysql v1.10.1
	github.com/jackc/pgx/v5 v5.7.5
	github.com/ubgo/auth v0.1.0
	github.com/ubgo/auth/authui v0.1.0
	github.com/ubgo/auth/plugin/deviceauth v0.1.0
	github.com/ubgo/auth/plugin/deviceauth/oauthdevice v0.1.0
	github.com/ubgo/auth/plugin/oauthproxy v0.1.0
	github.com/ubgo/auth/plugin/organization v0.1.0
	github.com/ubgo/auth/plugin/passkey v0.1.0
	github.com/ubgo/auth/plugin/password v0.1.0
	github.com/ubgo/auth/plugin/scim v0.1.0
	github.com/ubgo/sqlb v0.1.1
	modernc.org/sqlite v1.58.0
)

require (
	github.com/Azure/go-ntlmssp v0.1.1 // indirect
	github.com/beevik/etree v1.7.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8 // indirect
	github.com/go-ldap/ldap/v3 v3.4.13 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/russellhaering/gosaml2 v0.12.0 // indirect
	github.com/russellhaering/goxmldsig v1.6.1 // indirect
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/webauthn v0.17.0 // indirect
	github.com/go-webauthn/x v0.2.3 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/ubgo/auth/plugin/access v0.1.0
	github.com/ubgo/auth/plugin/agentauth v0.1.0
	github.com/ubgo/auth/plugin/ldap v0.1.0
	github.com/ubgo/auth/plugin/oauthprovider v0.1.0
	github.com/ubgo/auth/plugin/referral v0.1.0
	github.com/ubgo/auth/plugin/samlidp v0.1.0
	github.com/ubgo/auth/plugin/siwe v0.1.0
	github.com/ubgo/auth/plugin/sso v0.1.0
	github.com/ubgo/auth/plugin/webhook v0.1.0
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.50.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.36.0 // indirect
	modernc.org/libc v1.75.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)
