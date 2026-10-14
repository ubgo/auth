// Module redisrate is an auth.RateStore on Redis. A separate module so
// go-redis reaches only the apps that use it.
module github.com/ubgo/auth/contrib/redis

go 1.25.0

require (
	github.com/redis/go-redis/v9 v9.14.0
	github.com/ubgo/auth v0.0.0-20261014084637-dc7c057a66dd
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/ubgo/sqlb v0.1.1 // indirect
)

// Development inside this repository builds against the working tree. A
// consumer's build ignores replace directives in dependencies.
replace github.com/ubgo/auth => ../../
