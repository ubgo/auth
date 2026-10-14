// Module examples holds runnable programs — the cookbook recipes, the PoC and
// the negative type check — in a module of their own, so their database
// driver and frameworks never reach the core module's dependencies.
module github.com/ubgo/auth/examples

go 1.25.0

require (
	entgo.io/ent v0.14.5
	github.com/beevik/etree v1.7.0
	github.com/fxamacker/cbor/v2 v2.9.2
	github.com/gin-gonic/gin v1.12.0
	github.com/gofiber/fiber/v3 v3.5.0
	github.com/labstack/echo/v4 v4.15.4
	github.com/markbates/goth v1.82.0
	github.com/redis/go-redis/v9 v9.14.0
	github.com/russellhaering/gosaml2 v0.12.0
	github.com/russellhaering/goxmldsig v1.6.1
	github.com/ubgo/auth v0.0.0
	github.com/ubgo/auth/authui v0.0.0-20261014081355-f7af54573304
	github.com/ubgo/auth/contrib/echo v0.0.0-20261014081355-f7af54573304
	github.com/ubgo/auth/contrib/fiber v0.0.0-20261014081355-f7af54573304
	github.com/ubgo/auth/contrib/gin v0.0.0-20261014081355-f7af54573304
	github.com/ubgo/auth/contrib/goth v0.0.0-20261014081355-f7af54573304
	github.com/ubgo/auth/contrib/otel v0.0.0-20261014081355-f7af54573304
	github.com/ubgo/auth/contrib/redis v0.0.0-20261014081355-f7af54573304
	github.com/ubgo/auth/plugin/agentauth v0.0.0-20261014081355-f7af54573304
	github.com/ubgo/auth/plugin/deviceauth v0.0.0
	github.com/ubgo/auth/plugin/deviceauth/oauthdevice v0.0.0-20261014081355-f7af54573304
	github.com/ubgo/auth/plugin/ldap v0.0.0-20261014081355-f7af54573304
	github.com/ubgo/auth/plugin/oauthprovider v0.0.0
	github.com/ubgo/auth/plugin/oauthproxy v0.0.0-20261014081355-f7af54573304
	github.com/ubgo/auth/plugin/organization v0.0.0-20261014081355-f7af54573304
	github.com/ubgo/auth/plugin/passkey v0.0.0-20261014081355-f7af54573304
	github.com/ubgo/auth/plugin/password v0.0.0-20261014081355-f7af54573304
	github.com/ubgo/auth/plugin/referral v0.0.0-20261014081355-f7af54573304
	github.com/ubgo/auth/plugin/scim v0.0.0-20261014081355-f7af54573304
	github.com/ubgo/sqlb v0.1.1
	go.opentelemetry.io/otel v1.38.0
	go.opentelemetry.io/otel/sdk v1.38.0
	go.opentelemetry.io/otel/trace v1.38.0
	modernc.org/sqlite v1.58.0
)

require (
	ariga.io/atlas v0.32.1-0.20250325101103-175b25e1c1b9 // indirect
	github.com/Azure/go-ntlmssp v0.1.1 // indirect
	github.com/agext/levenshtein v1.2.3 // indirect
	github.com/andybalholm/brotli v1.2.2 // indirect
	github.com/apparentlymart/go-textseg/v15 v15.0.0 // indirect
	github.com/bmatcuk/doublestar v1.3.4 // indirect
	github.com/bytedance/gopkg v0.1.3 // indirect
	github.com/bytedance/sonic v1.15.0 // indirect
	github.com/bytedance/sonic/loader v0.5.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudwego/base64x v0.1.6 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/gabriel-vasile/mimetype v1.4.12 // indirect
	github.com/gin-contrib/sse v1.1.0 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8 // indirect
	github.com/go-ldap/ldap/v3 v3.4.13 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-openapi/inflect v0.19.0 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.30.1 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/x v0.2.3 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/goccy/go-yaml v1.19.2 // indirect
	github.com/gofiber/schema v1.8.3 // indirect
	github.com/gofiber/utils/v2 v2.4.1 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/hashicorp/hcl/v2 v2.18.1 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/compress v1.19.2 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/labstack/gommon v0.5.0 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/mattn/go-colorable v0.1.15 // indirect
	github.com/mitchellh/go-wordwrap v1.0.1 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/nyaruka/phonenumbers v1.8.1 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/quic-go/quic-go v0.59.0 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/ugorji/go/codec v1.3.1 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasthttp v1.73.0 // indirect
	github.com/valyala/fasttemplate v1.2.2 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/zclconf/go-cty v1.14.4 // indirect
	github.com/zclconf/go-cty-yaml v1.1.0 // indirect
	go.mongodb.org/mongo-driver/v2 v2.5.0 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/otel/metric v1.38.0 // indirect
	golang.org/x/arch v0.22.0 // indirect
	golang.org/x/mod v0.38.0 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/oauth2 v0.27.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-chi/chi/v5 v5.2.5
	github.com/go-webauthn/webauthn v0.17.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/ubgo/auth/contrib/phonenumbers v0.0.0-20261014081355-f7af54573304
	github.com/ubgo/auth/plugin/access v0.0.0
	github.com/ubgo/auth/plugin/samlidp v0.0.0-20261014081355-f7af54573304
	github.com/ubgo/auth/plugin/siwe v0.0.0-20261014081355-f7af54573304
	github.com/ubgo/auth/plugin/sso v0.0.0-20261014081355-f7af54573304
	github.com/ubgo/auth/plugin/webhook v0.0.0-20261014081355-f7af54573304
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	modernc.org/libc v1.75.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)

// Development inside this repository builds against the working tree.
replace (
	github.com/ubgo/auth => ../
	github.com/ubgo/auth/authui => ../authui
	github.com/ubgo/auth/contrib/echo => ../contrib/echo
	github.com/ubgo/auth/contrib/fiber => ../contrib/fiber
	github.com/ubgo/auth/contrib/gin => ../contrib/gin
	github.com/ubgo/auth/contrib/phonenumbers => ../contrib/phonenumbers
	github.com/ubgo/auth/contrib/redis => ../contrib/redis
	github.com/ubgo/auth/plugin/organization => ../plugin/organization
	github.com/ubgo/auth/plugin/passkey => ../plugin/passkey
	github.com/ubgo/auth/plugin/password => ../plugin/password
)

replace github.com/ubgo/auth/plugin/sso => ../plugin/sso

replace github.com/ubgo/auth/plugin/scim => ../plugin/scim

replace github.com/ubgo/auth/plugin/deviceauth => ../plugin/deviceauth

replace github.com/ubgo/auth/plugin/access => ../plugin/access

// Modules the documentation examples import; go adds their require lines
// on first use (task runs with -mod=mod).
replace (
	github.com/ubgo/auth/contrib/goth => ../contrib/goth
	github.com/ubgo/auth/contrib/otel => ../contrib/otel
	github.com/ubgo/auth/plugin/agentauth => ../plugin/agentauth
	github.com/ubgo/auth/plugin/deviceauth/oauthdevice => ../plugin/deviceauth/oauthdevice
	github.com/ubgo/auth/plugin/oauthprovider => ../plugin/oauthprovider
	github.com/ubgo/auth/plugin/oauthproxy => ../plugin/oauthproxy
	github.com/ubgo/auth/plugin/referral => ../plugin/referral
)

replace github.com/ubgo/auth/plugin/ldap => ../plugin/ldap

replace github.com/ubgo/auth/plugin/siwe => ../plugin/siwe

replace github.com/ubgo/auth/plugin/samlidp => ../plugin/samlidp

replace github.com/ubgo/auth/plugin/webhook => ../plugin/webhook
