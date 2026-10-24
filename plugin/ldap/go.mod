// Module ldap is the LDAP sign-in plugin. A separate module so the LDAP
// client and its dependencies reach only the apps that use it.
module github.com/ubgo/auth/plugin/ldap

go 1.25.0

require (
	github.com/go-ldap/ldap/v3 v3.4.13
	github.com/ubgo/auth v0.1.0
	github.com/ubgo/sqlb v0.1.1
)

require (
	github.com/Azure/go-ntlmssp v0.1.1 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	golang.org/x/crypto v0.50.0 // indirect
)
