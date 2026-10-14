package agentauth

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/ubgo/auth"
)

// Event types, better-auth's AgentAuthEvent names for what this plugin
// does.
const (
	EventAgentCreated        = "agent.created"
	EventAgentRevoked        = "agent.revoked"
	EventHostCreated         = "host.created"
	EventHostKeyRotated      = "host.key_rotated"
	EventCapabilityRequested = "capability.requested"
	EventCapabilityApproved  = "capability.approved"
	EventCapabilityDenied    = "capability.denied"
	EventApprovalCreated     = "approval.created"
	EventApprovalApproved    = "approval.approved"
	EventApprovalDenied      = "approval.denied"
	EventCapabilityExecuted  = "capability.executed"
	EventHostRevoked         = "host.revoked"
	EventCapabilityRevoked   = "capability.revoked"
	EventAgentClaimed        = "agent.claimed"
	EventAgentUpdated        = "agent.updated"
	EventAgentReactivated    = "agent.reactivated"
	EventAgentKeyRotated     = "agent.key_rotated"
	EventHostUpdated         = "host.updated"
	EventHostEnrolled        = "host.enrolled"
	EventHostReactivated     = "host.reactivated"
	// Execution statuses of a capability.executed event.
	ExecutionSuccess = "success"
	ExecutionError   = "error"
	// Actor types.
	ActorUser  = "user"
	ActorAgent = "agent"
	// ActorHost is a host acting with its own JWT, as when it revokes
	// itself.
	ActorHost = "host"
)

// Event is one audit event, better-auth's AgentAuthEvent: who did what to
// which agent or host. The capability.executed fields are set only on that
// type.
type Event struct {
	Type      string
	ActorID   string
	ActorType string
	AgentID   string
	HostID    string
	// Capability, Arguments, Status, Duration and Error describe a
	// capability.executed event.
	Capability string
	Arguments  map[string]any
	Status     string
	Duration   time.Duration
	Error      string
	// Capabilities are the capabilities a request, approval or denial
	// named.
	Capabilities []string
	// ApprovalID, Method, UserID and BindingMessage describe an
	// approval.created event: the request, its approval method, the user
	// it waits for (nil when nobody owns the agent yet) and the message to
	// show. A CIBA request reaches its user only through the app, so this
	// event is where the app sends the notification.
	ApprovalID     string
	Method         string
	UserID         *string
	BindingMessage string
}

// EventFunc receives events. It runs after the commit, in the background
// (auth.WithBackground), and its panics and slowness never reach the
// request, better-auth's emit that never throws.
type EventFunc func(ctx context.Context, e Event)

// OnEvent installs an EventFunc, better-auth's onEvent.
func OnEvent(fn EventFunc) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("agentauth.OnEvent", fn) {
			return
		}
		p.onEvent = fn
	}
}

var _ auth.OperationHooker = (*Plugin)(nil)

// annotationStart is the Call annotation holding an execution's start, in
// Unix nanoseconds, from its Before hook to its Finally hook.
const annotationStart = "agentauth.execute_start"

// OperationHooks turns operation results into events: After for each
// success, Finally for an execution that failed. Nothing without OnEvent.
func (p *Plugin) OperationHooks() []auth.OperationHook {
	if p.onEvent == nil {
		return nil
	}
	return []auth.OperationHook{
		{Match: []auth.EndpointID{EndpointRegister}, After: func(ctx context.Context, c *auth.Call, out any) error {
			if r, ok := out.(RegisterResult); ok {
				p.emit(ctx, Event{Type: EventAgentCreated, ActorType: ActorAgent, ActorID: r.AgentID, AgentID: r.AgentID, HostID: r.HostID})
			}
			return nil
		}},
		{Match: []auth.EndpointID{EndpointCreateHost}, After: func(ctx context.Context, c *auth.Call, out any) error {
			if r, ok := out.(CreateHostResult); ok {
				typ := EventHostCreated
				if r.Reactivated {
					typ = EventHostReactivated
				}
				p.emit(ctx, Event{Type: typ, ActorType: ActorUser, ActorID: userOf(c), HostID: r.HostID})
			}
			return nil
		}},
		{Match: []auth.EndpointID{EndpointRevoke}, After: func(ctx context.Context, c *auth.Call, out any) error {
			if r, ok := out.(RevokeResult); ok {
				p.emit(ctx, Event{Type: EventAgentRevoked, ActorID: userOf(c), ActorType: actorType(c), AgentID: r.AgentID})
			}
			return nil
		}},
		{Match: []auth.EndpointID{EndpointRotateHostKey}, After: func(ctx context.Context, c *auth.Call, out any) error {
			if r, ok := out.(RotateHostKeyResult); ok {
				p.emit(ctx, Event{Type: EventHostKeyRotated, HostID: r.HostID})
			}
			return nil
		}},
		{Match: []auth.EndpointID{EndpointRequestCapability}, After: func(ctx context.Context, c *auth.Call, out any) error {
			if r, ok := out.(RequestCapabilityResult); ok {
				in, _ := c.Input.(RequestCapabilityRequest)
				p.emit(ctx, Event{Type: EventCapabilityRequested, ActorType: ActorAgent, ActorID: r.AgentID, AgentID: r.AgentID, Capabilities: requestedNames(in)})
			}
			return nil
		}},
		{Match: []auth.EndpointID{EndpointApproveCapability}, After: func(ctx context.Context, c *auth.Call, out any) error {
			r, _ := out.(ApproveResult) // After sees the operation's own result type
			e := Event{ActorType: ActorUser, ActorID: userOf(c), AgentID: r.AgentID, Capabilities: r.Added}
			switch {
			case r.Status == ApprovalApproved && r.Claimed:
				e.Type = EventAgentClaimed
				p.emit(ctx, e)
				e.Type = EventApprovalApproved
				p.emit(ctx, e)
			case r.Status == ApprovalApproved:
				e.Type = EventCapabilityApproved
				p.emit(ctx, e)
				e.Type = EventApprovalApproved
				p.emit(ctx, e)
			case r.Status == ApprovalDenied:
				e.Type = EventCapabilityDenied
				p.emit(ctx, e)
				e.Type = EventApprovalDenied
				p.emit(ctx, e)
			}
			return nil
		}},
		{Match: []auth.EndpointID{EndpointRevokeHost}, After: func(ctx context.Context, c *auth.Call, out any) error {
			if r, ok := out.(RevokeHostResult); ok {
				e := Event{Type: EventHostRevoked, ActorType: ActorUser, ActorID: userOf(c), HostID: r.HostID}
				if c.User == nil {
					e.ActorType, e.ActorID = ActorHost, r.HostID
				}
				p.emit(ctx, e)
			}
			return nil
		}},
		{Match: []auth.EndpointID{EndpointRevokeCapability}, After: func(ctx context.Context, c *auth.Call, out any) error {
			if r, ok := out.(RevokeCapabilityResult); ok && len(r.Revoked) > 0 {
				p.emit(ctx, Event{Type: EventCapabilityRevoked, ActorID: userOf(c), ActorType: actorType(c), AgentID: r.AgentID, Capabilities: r.Revoked})
			}
			return nil
		}},
		{Match: []auth.EndpointID{EndpointReactivate}, After: func(ctx context.Context, c *auth.Call, out any) error {
			if r, ok := out.(AgentStatusView); ok && c.Annotation(annotationReactivated) == annotationTrue {
				e := Event{Type: EventAgentReactivated, ActorType: ActorHost, ActorID: r.HostID, AgentID: r.AgentID, HostID: r.HostID}
				for _, g := range r.Grants {
					if g.Status == GrantActive {
						e.Capabilities = append(e.Capabilities, g.Capability)
					}
				}
				p.emit(ctx, e)
			}
			return nil
		}},
		{Match: []auth.EndpointID{EndpointRotateAgentKey}, After: func(ctx context.Context, _ *auth.Call, out any) error {
			if r, ok := out.(RotateAgentKeyResult); ok {
				p.emit(ctx, Event{Type: EventAgentKeyRotated, ActorType: ActorHost, ActorID: r.HostID, AgentID: r.AgentID, HostID: r.HostID})
			}
			return nil
		}},
		{Match: []auth.EndpointID{EndpointUpdateHost}, After: func(ctx context.Context, c *auth.Call, out any) error {
			if r, ok := out.(UpdateHostResult); ok {
				p.emit(ctx, Event{Type: EventHostUpdated, ActorType: ActorUser, ActorID: userOf(c), HostID: r.HostID})
			}
			return nil
		}},
		{Match: []auth.EndpointID{EndpointEnrollHost}, After: func(ctx context.Context, _ *auth.Call, out any) error {
			if r, ok := out.(EnrollHostResult); ok {
				p.emit(ctx, Event{Type: EventHostEnrolled, ActorType: ActorHost, ActorID: r.HostID, HostID: r.HostID})
			}
			return nil
		}},
		{Match: []auth.EndpointID{EndpointUpdateAgent}, After: func(ctx context.Context, c *auth.Call, out any) error {
			if r, ok := out.(UpdateAgentResult); ok {
				p.emit(ctx, Event{Type: EventAgentUpdated, ActorType: ActorUser, ActorID: userOf(c), AgentID: r.AgentID})
			}
			return nil
		}},
		{
			Match: []auth.EndpointID{EndpointExecute},
			Before: func(_ context.Context, c *auth.Call) error {
				c.Annotate(annotationStart, strconv.FormatInt(p.core.Now().UnixNano(), 10))
				return nil
			},
			Finally: func(ctx context.Context, c *auth.Call, err error) {
				in, ok := c.Input.(ExecuteRequest)
				if !ok {
					return // refused before the input was read: nothing executed
				}
				e := Event{Type: EventCapabilityExecuted, ActorType: ActorAgent, Capability: in.Capability, Arguments: in.Arguments, Status: ExecutionSuccess}
				if ns, perr := strconv.ParseInt(c.Annotation(annotationStart), 10, 64); perr == nil {
					e.Duration = p.core.Now().Sub(time.Unix(0, ns))
				}
				if err != nil {
					e.Status, e.Error = ExecutionError, auth.ErrorOf(err).Code
				}
				p.emit(ctx, e)
			},
		},
	}
}

// emitApproval reports a new approval request. A CIBA request whose login
// hint named nobody reports nothing: there is nobody to notify.
func (p *Plugin) emitApproval(ctx context.Context, id string, r approvalRow) {
	if p.onEvent == nil || (r.Method == MethodCIBA && r.UserID == nil) {
		return
	}
	e := Event{
		Type: EventApprovalCreated, ActorType: ActorAgent, ActorID: r.AgentID, AgentID: r.AgentID,
		Capabilities: strings.Fields(r.Capabilities), ApprovalID: id, Method: r.Method, UserID: r.UserID,
	}
	if r.HostID != nil {
		e.HostID = *r.HostID
	}
	if r.BindingMessage != nil {
		e.BindingMessage = *r.BindingMessage
	}
	p.emit(ctx, e)
}

// emit hands an event to OnEvent after the commit (at once outside a
// transaction, as in a Finally hook), in the background; a rolled-back call
// emits nothing, and a panic in OnEvent is recovered and logged.
func (p *Plugin) emit(ctx context.Context, e Event) {
	p.core.AfterCommit(ctx, func(ctx context.Context) {
		p.core.RunInBackground(ctx, func(ctx context.Context) {
			defer func() {
				if r := recover(); r != nil {
					p.core.Logger().Error("agentauth: onEvent panicked", "event", e.Type, "panic", r)
				}
			}()
			p.onEvent(ctx, e)
		})
	})
}

// requestedNames is the capability names of a request.
func requestedNames(in RequestCapabilityRequest) []string {
	out := make([]string, 0, len(in.Capabilities))
	for _, c := range in.Capabilities {
		out = append(out, c.Name)
	}
	return out
}

func userOf(c *auth.Call) string {
	if c.User == nil {
		return ""
	}
	return c.User.ID
}

func actorType(c *auth.Call) string {
	if c.User != nil {
		return ActorUser
	}
	return ActorAgent
}
