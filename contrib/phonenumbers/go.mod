// Module phonenums normalizes phone numbers with country rules. A separate
// module so libphonenumber's metadata reaches only the apps that use it.
module github.com/ubgo/auth/contrib/phonenumbers

go 1.25.0

require (
	github.com/nyaruka/phonenumbers v1.8.1
	github.com/ubgo/auth v0.0.0
)

require (
	github.com/ubgo/sqlb v0.1.1 // indirect
	golang.org/x/text v0.23.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

// Development inside this repository builds against the working tree. A
// consumer's build ignores replace directives in dependencies.
replace github.com/ubgo/auth => ../../
