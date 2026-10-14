// Module referral is user-to-user referrals: codes, who referred whom, and
// steps that complete a referral. A separate module because referrals are not
// authentication: an app without them never compiles it.
module github.com/ubgo/auth/plugin/referral

go 1.24.0

require (
	github.com/ubgo/auth v0.0.0
	github.com/ubgo/sqlb v0.1.1
)

replace github.com/ubgo/auth => ../..
