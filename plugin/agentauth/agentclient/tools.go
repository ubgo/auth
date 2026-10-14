package agentclient

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	"github.com/ubgo/auth/plugin/agentauth"
)

// Tool is one MCP-style tool: a name, a description and a JSON Schema for
// its arguments, and the function that runs it. Register each with any MCP
// server library (its tool name, description and input schema, and a
// handler that passes the raw arguments to Call); the package depends on
// none.
type Tool struct {
	Name        string
	Description string
	InputSchema json.RawMessage
	// Call runs the tool with its JSON arguments and returns a value for
	// the JSON encoder.
	Call func(ctx context.Context, args json.RawMessage) (any, error)
}

// Store keeps the agents the tools connect, by id: an agent's private key
// is a secret, so where it lives is the caller's decision.
type Store interface {
	SaveAgent(ctx context.Context, a Agent) error
	// LoadAgent returns ErrUnknownAgent for an id it does not hold.
	LoadAgent(ctx context.Context, id string) (Agent, error)
}

// ErrUnknownAgent is an agent id the Store does not hold.
var ErrUnknownAgent = errors.New("agentclient: unknown agent_id; call connect_agent first")

// MemoryStore is a Store in memory, for a process that never restarts its
// agents. The zero value is ready.
type MemoryStore struct {
	mu     sync.Mutex
	agents map[string]Agent
}

// SaveAgent keeps a.
func (m *MemoryStore) SaveAgent(_ context.Context, a Agent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.agents == nil {
		m.agents = map[string]Agent{}
	}
	m.agents[a.ID] = a
	return nil
}

// LoadAgent returns the agent with id.
func (m *MemoryStore) LoadAgent(_ context.Context, id string) (Agent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.agents[id]
	if !ok {
		return Agent{}, ErrUnknownAgent
	}
	return a, nil
}

// Tool names, better-auth's SDK tool names for what this client serves.
const (
	ToolDiscoverProvider   = "discover_provider"
	ToolListCapabilities   = "list_capabilities"
	ToolDescribeCapability = "describe_capability"
	ToolConnectAgent       = "connect_agent"
	ToolAgentStatus        = "agent_status"
	ToolRequestCapability  = "request_capability"
	ToolExecuteCapability  = "execute_capability"
	ToolDisconnectAgent    = "disconnect_agent"
)

// Tool argument schemas.
const (
	schemaProvider = `{"type":"object","properties":{"provider":{"type":"string","description":"Provider URL"}},"required":["provider"]}`
	schemaDescribe = `{"type":"object","properties":{"provider":{"type":"string","description":"Provider URL"},"name":{"type":"string","description":"Capability name"}},"required":["provider","name"]}`
	schemaConnect  = `{"type":"object","properties":{"provider":{"type":"string","description":"Provider URL"},"name":{"type":"string","description":"Agent name shown to the user"},"capabilities":{"type":"array","items":{"oneOf":[{"type":"string"},{"type":"object","properties":{"name":{"type":"string"},"constraints":{"type":"object"}},"required":["name"]}]},"description":"Capabilities to request, with constraints where the capability has constrainable fields"},"mode":{"type":"string","enum":["delegated","autonomous"]},"reason":{"type":"string"},"preferred_method":{"type":"string","enum":["device_authorization","ciba"]},"login_hint":{"type":"string"},"binding_message":{"type":"string"}},"required":["provider"]}`
	schemaAgent    = `{"type":"object","properties":{"agent_id":{"type":"string","description":"Agent ID returned by connect_agent"}},"required":["agent_id"]}`
	schemaRequest  = `{"type":"object","properties":{"agent_id":{"type":"string"},"capabilities":{"type":"array","items":{"oneOf":[{"type":"string"},{"type":"object","properties":{"name":{"type":"string"},"constraints":{"type":"object"}},"required":["name"]}]}},"reason":{"type":"string"},"preferred_method":{"type":"string"},"login_hint":{"type":"string"},"binding_message":{"type":"string"}},"required":["agent_id","capabilities"]}`
	schemaExecute  = `{"type":"object","properties":{"agent_id":{"type":"string","description":"Agent ID returned by connect_agent"},"capability":{"type":"string"},"arguments":{"type":"object"},"location":{"type":"string","description":"The capability's location, when it has one"}},"required":["agent_id","capability"]}`
)

// toolArgs is the union of every tool's arguments.
type toolArgs struct {
	Provider     string                        `json:"provider"`
	Name         string                        `json:"name"`
	AgentID      string                        `json:"agent_id"`
	Capabilities []agentauth.CapabilityRequest `json:"capabilities"`
	Mode         agentauth.Mode                `json:"mode"`
	Reason       string                        `json:"reason"`
	Capability   string                        `json:"capability"`
	Arguments    map[string]any                `json:"arguments"`
	Location     string                        `json:"location"`
	agentauth.ApprovalHints
}

// Tools returns the client's tools over store, better-auth's SDK tools for
// an MCP server: discover a provider, list and describe its capabilities,
// connect an agent, read its status, request more, execute, disconnect.
func (c *Client) Tools(store Store) []Tool {
	tool := func(name, desc, schema string, run func(ctx context.Context, in toolArgs) (any, error)) Tool {
		return Tool{Name: name, Description: desc, InputSchema: json.RawMessage(schema), Call: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var in toolArgs
			if len(raw) > 0 {
				if err := json.Unmarshal(raw, &in); err != nil {
					return nil, err
				}
			}
			return run(ctx, in)
		}}
	}
	agent := func(ctx context.Context, id string) (Agent, error) { return store.LoadAgent(ctx, id) }
	return []Tool{
		tool(ToolDiscoverProvider, "Read a provider's Agent Auth discovery document: its endpoints, modes and approval methods.", schemaProvider,
			func(ctx context.Context, in toolArgs) (any, error) { return c.Discover(ctx, in.Provider) }),
		tool(ToolListCapabilities, "List the capabilities a provider offers.", schemaProvider,
			func(ctx context.Context, in toolArgs) (any, error) {
				p, err := c.Discover(ctx, in.Provider)
				if err != nil {
					return nil, err
				}
				return c.ListCapabilities(ctx, p, nil)
			}),
		tool(ToolDescribeCapability, "Describe one capability with its input and output schemas.", schemaDescribe,
			func(ctx context.Context, in toolArgs) (any, error) {
				p, err := c.Discover(ctx, in.Provider)
				if err != nil {
					return nil, err
				}
				return c.DescribeCapability(ctx, p, in.Name)
			}),
		tool(ToolConnectAgent, "Connect to a provider and get an agent_id. Call once per provider, then use execute_capability. When the answer carries an approval, show the user its verification_uri_complete (or tell them to look for the request) and poll agent_status.", schemaConnect,
			func(ctx context.Context, in toolArgs) (any, error) {
				p, err := c.Discover(ctx, in.Provider)
				if err != nil {
					return nil, err
				}
				a, res, err := c.Connect(ctx, p, ConnectRequest{Name: in.Name, Capabilities: in.Capabilities, Mode: in.Mode, Reason: in.Reason, ApprovalHints: in.ApprovalHints})
				if err != nil {
					return nil, err
				}
				return res, store.SaveAgent(ctx, a)
			}),
		tool(ToolAgentStatus, "Read an agent's status and grants; poll it while the user approves.", schemaAgent,
			func(ctx context.Context, in toolArgs) (any, error) {
				a, err := agent(ctx, in.AgentID)
				if err != nil {
					return nil, err
				}
				return c.Status(ctx, a)
			}),
		tool(ToolRequestCapability, "Request more capabilities for a connected agent.", schemaRequest,
			func(ctx context.Context, in toolArgs) (any, error) {
				a, err := agent(ctx, in.AgentID)
				if err != nil {
					return nil, err
				}
				return c.RequestCapability(ctx, a, in.Capabilities, in.Reason, in.ApprovalHints)
			}),
		tool(ToolExecuteCapability, "Execute a capability with the agent_id from connect_agent.", schemaExecute,
			func(ctx context.Context, in toolArgs) (any, error) {
				a, err := agent(ctx, in.AgentID)
				if err != nil {
					return nil, err
				}
				return c.Execute(ctx, a, in.Capability, in.Location, in.Arguments)
			}),
		tool(ToolDisconnectAgent, "Revoke a connected agent.", schemaAgent,
			func(ctx context.Context, in toolArgs) (any, error) {
				a, err := agent(ctx, in.AgentID)
				if err != nil {
					return nil, err
				}
				return map[string]string{"agent_id": a.ID, "status": string(agentauth.AgentRevoked)}, c.Disconnect(ctx, a)
			}),
	}
}
