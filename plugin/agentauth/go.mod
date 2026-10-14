// Module agentauth lets AI agents authenticate to the app with their own
// keys and act under capabilities a user granted: the Agent Auth Protocol,
// better-auth's agent-auth plugin. A separate module because serving agents
// is opt-in and most apps never need it.
module github.com/ubgo/auth/plugin/agentauth

go 1.24.0

require (
	github.com/ubgo/auth v0.1.0
	github.com/ubgo/sqlb v0.1.1
)
