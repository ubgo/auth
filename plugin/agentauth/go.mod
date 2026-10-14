// Module agentauth lets AI agents authenticate to the app with their own
// keys and act under capabilities a user granted: the Agent Auth Protocol,
// better-auth's agent-auth plugin. A separate module because serving agents
// is opt-in and most apps never need it.
module github.com/ubgo/auth/plugin/agentauth

go 1.24.0

require (
	github.com/ubgo/auth v0.0.0-20261014084637-dc7c057a66dd
	github.com/ubgo/sqlb v0.1.1
)

// Development inside this repository builds against the working tree. A
// consumer's build ignores replace directives in dependencies.
replace github.com/ubgo/auth => ../../
