package auth

import (
	"context"
	"errors"
	"fmt"
	"reflect"
)

// OpKind says whether an operation reads or changes state. Transports map it:
// HTTP serves a Query as GET and a Mutation as POST; GraphQL exposes them as a
// query and a mutation. The origin check applies to mutations only.
type OpKind string

// Operation kinds.
const (
	Query    OpKind = "query"
	Mutation OpKind = "mutation"
)

// Requirement is what a call must have before the operation runs.
type Requirement string

// Requirements. The pipeline checks them, so an operation never needs its own
// "is anyone signed in" test and cannot forget one.
const (
	// Public operations run for anyone, signed in or not: sign-in, sign-up.
	//ds:def id=core-requirements-tksmmmjf owner=@khanakia stability=stable
	Public Requirement = "public"
	// SignedIn operations need a valid session.
	SignedIn Requirement = "signed_in"
	// FreshSignIn operations need a session created within the fresh window,
	// for actions a stolen laptop must not be able to take: changing a
	// password or an email address.
	FreshSignIn Requirement = "fresh_sign_in"
	// PendingSecondFactor operations need a session that is waiting for a
	// second factor, and are the only ones that see such a session: the
	// operation that checks the code and calls PromoteSession.
	PendingSecondFactor Requirement = "pending_second_factor"
	// SignedInOrPending operations need a session, pending or full, and see
	// either: one operation serving both the sign-in step and the signed-in
	// user, such as sending a second-factor code. c.User is set in both
	// cases; the operation checks c.Session.SecondFactorPending itself when
	// the two cases differ.
	SignedInOrPending Requirement = "signed_in_or_pending"
)

// RequirementValues is the canonical iteration order over requirements.
var RequirementValues = []Requirement{Public, SignedIn, FreshSignIn, PendingSecondFactor, SignedInOrPending}

// EndpointID names an operation, as "<plugin>.<name>". Plugins export theirs as
// constants so another plugin's hook can name them without a bare string.
type EndpointID string

// OpInfo describes an operation to the pipeline and to every transport.
//
//ds:def id=core-opinfo-6xnm8pzr owner=@khanakia stability=stable
type OpInfo struct {
	ID      EndpointID
	Kind    OpKind
	Require Requirement
	// Path is relative to the plugin, such as "/sign-in". The core serves it at
	// "/<plugin>/sign-in"; a core operation's path has no plugin segment.
	Path string
	// CrossSiteForm marks a Mutation that another site posts to as a plain
	// HTML form: an OAuth provider's response_mode=form_post answer, which
	// arrives without a trusted Origin and without the flow cookie (SameSite
	// Lax keeps it off a cross-site POST). Such an operation only relays its
	// fields into a redirect, so the pipeline skips the origin check for it
	// and resolves no session: its Credential is CredentialNone whatever the
	// request carried, and nothing a stray cookie held is visible to it. It
	// must be Public and a Mutation; auth.New refuses anything else
	// (ErrBadOperation), because a credential-bearing or session-reading
	// operation without the origin check would be the login CSRF the check
	// exists to refuse. authhttp decodes a form body for it without
	// AcceptForms, and documents the form media type. The relay's own
	// protection is the OAuth state it carries and the flow cookie the GET
	// callback it redirects to still checks; the flag removes nothing from
	// that step.
	//
	//ds:def id=core-opinfo-crosssiteform-7qn3kx8m owner=@khanakia stability=stable
	CrossSiteForm bool
	// SelfServed marks an operation whose HTTP wire format a standard fixes,
	// such as an OAuth 2.1 token endpoint (RFC 6749: form-encoded body,
	// HTTP Basic client authentication, {"error": "invalid_grant"} answers).
	// The plugin serves it over HTTP from its own handler, which calls the
	// typed Op.Call; Auth.Operations leaves it out, so no transport mounts a
	// second, JSON-shaped copy of it. It is still wired: Auth.Operation finds
	// it, hooks and WithDisabledOperations may name it, and every call runs
	// the whole pipeline (rate limits, origin check, requirement, hooks), so
	// the plugin's handler cannot skip a step. It also marks an operation
	// with no wire format at all, one only the plugin's own handler or Go
	// API calls (scim.request, which admits each SCIM request; handoff's
	// generate under ServerOnly): leaving it out of Auth.Operations is what
	// keeps authhttp.Handler, the adapters, the OpenAPI document and the
	// generated TypeScript client from offering a route that only answers
	// auth.ErrUnknownOperation.
	//
	//ds:def id=core-opinfo-selfserved-m4q8xk2w owner=@khanakia stability=stable
	SelfServed bool
	// SignIn marks an operation whose every successful call signs the
	// caller in: it authenticates someone who was not signed in and issues
	// their session (a password or code sign-in, a provider callback, a
	// second factor that promotes a pending session, a device-code token).
	// It is metadata for observers, so an audit log can type a third-party
	// sign-in method's operations as sign-ins without a list of ids; the
	// pipeline reads it for one thing only, WithGeoRules, which judges the
	// operations marked here and no others. An operation that signs in only sometimes
	// (a poll that is usually still pending) or that creates an account
	// (a sign-up, which observers record as its own event) leaves it false.
	//
	//ds:def id=core-opinfo-signin-5vt8kq2m owner=@khanakia stability=stable
	SignIn bool
}

// Operation is one feature, as every transport sees it.
//
// The interface is sealed by an unexported method, so the only way to make an
// Operation is Define. That is the point: an operation that could be built by
// hand could skip the pipeline, and the pipeline is where the rate limits, the
// origin check, the session requirement and the hooks live.
type Operation interface {
	Info() OpInfo
	// Plugin is the name of the plugin that registered the operation, or
	// CorePluginName for the core's own.
	Plugin() string
	// Route is the full path, "/<plugin><Path>", set when auth.New wires it.
	Route() string
	// Invoke runs the operation for a transport. decode fills the typed input
	// from the transport's request; ctx must come from Auth.WithRequest.
	//
	// The input and output are any because one transport serves every
	// operation through this one interface, and the concrete types differ per
	// operation. This is the boundary where typed Go meets an encoded request;
	// decode checks the input's shape, and the output goes straight to an
	// encoder. Go callers use the typed Op.Call instead and never see any.
	Invoke(ctx context.Context, decode func(dst any) error) (any, error)
	// InputType and OutputType are the Go types of In and Out, for a
	// documentation generator that writes schemas from their fields and
	// json tags; nothing else can see them through this interface.
	InputType() reflect.Type
	OutputType() reflect.Type

	bind(a *Auth, plugin string)
	// disable marks the operation as switched off by WithDisabledOperations,
	// so its typed Go method answers ErrUnknownOperation instead of
	// ErrOperationNotWired, which would blame the plugin list.
	disable()
}

// CorePluginName is the owner name of the core's own operations and
// migrations. No plugin may use it.
const CorePluginName = "core"

// Op is an operation with a typed input and output.
//
// A plugin keeps the value returned by Define and exposes it two ways: in its
// Operations list for the transports, and through a one-line typed method for
// Go callers. Both paths run the same pipeline.
type Op[In, Out any] struct {
	info     OpInfo
	run      func(ctx context.Context, c *Call, in In) (Out, error)
	a        *Auth
	plugin   string
	disabled bool
}

// Define declares an operation. The run function holds the feature's logic and
// is the only place that logic exists.
//
//ds:def id=core-define-jrndwtbj owner=@khanakia stability=stable
func Define[In, Out any](info OpInfo, run func(ctx context.Context, c *Call, in In) (Out, error)) *Op[In, Out] {
	return &Op[In, Out]{info: info, run: run}
}

// ErrOperationNotWired is returned when an operation is called before auth.New
// registered it. It is a programming error: the plugin was not in the list.
var ErrOperationNotWired = errors.New("auth: operation called before auth.New registered its plugin")

// Info returns the description the operation was defined with: its id, kind,
// requirement and path.
func (o *Op[In, Out]) Info() OpInfo { return o.info }

// InputType returns the type of In.
func (o *Op[In, Out]) InputType() reflect.Type { return reflect.TypeFor[In]() }

// OutputType returns the type of Out.
func (o *Op[In, Out]) OutputType() reflect.Type { return reflect.TypeFor[Out]() }

// Plugin returns the name of the plugin that registered the operation, set
// when auth.New wires it; empty before.
func (o *Op[In, Out]) Plugin() string { return o.plugin }

// Route returns the full path a transport serves the operation at:
// "/<plugin><Path>", or Path alone for a core operation.
func (o *Op[In, Out]) Route() string {
	if o.plugin == CorePluginName {
		return o.info.Path
	}
	return "/" + o.plugin + o.info.Path
}

func (o *Op[In, Out]) bind(a *Auth, plugin string) { o.a, o.plugin = a, plugin }

func (o *Op[In, Out]) disable() { o.disabled = true }

// unwired is the error for an operation no instance serves: switched off by
// WithDisabledOperations, or never registered because its plugin was not in
// the list.
func (o *Op[In, Out]) unwired() error {
	if o.disabled {
		return ErrUnknownOperation
	}
	return ErrOperationNotWired
}

// Call runs the operation from Go code: a service, a CLI, a GraphQL resolver.
// When ctx carries a request, the call uses that request's session and client
// and its effects reach that request's response.
func (o *Op[In, Out]) Call(ctx context.Context, in In) (Out, error) {
	var zero Out
	if o.a == nil {
		return zero, o.unwired()
	}
	return execute(ctx, o.a, o, func() (prepared[Out], error) { return o.prepare(in), nil })
}

// Invoke runs the operation for a transport. The input is decoded inside the
// pipeline, after the origin and requirement checks, so a cross-site request
// is refused before its body is even read.
func (o *Op[In, Out]) Invoke(ctx context.Context, decode func(dst any) error) (any, error) {
	if o.a == nil {
		return nil, o.unwired()
	}
	return execute(ctx, o.a, o, func() (prepared[any], error) {
		var in In
		if err := decode(&in); err != nil {
			return prepared[any]{}, ErrBadRequest
		}
		p := o.prepare(in)
		return prepared[any]{rateID: p.rateID, input: p.input, run: func(ctx context.Context, c *Call) (any, error) {
			out, err := p.run(ctx, c)
			if err != nil {
				return nil, err
			}
			return out, nil
		}}, nil
	})
}

// prepare binds the operation to its input and reads the account the input
// names. Both entry points use it, so a Go call is limited exactly like an
// HTTP call.
func (o *Op[In, Out]) prepare(in In) prepared[Out] {
	p := prepared[Out]{input: in, run: func(ctx context.Context, c *Call) (Out, error) {
		var zero Out
		if c.answered {
			out, ok := c.answer.(Out)
			if !ok {
				return zero, fmt.Errorf("%w: a hook answered %s with %T, the operation returns %T", ErrBadOperation, o.info.ID, c.answer, zero)
			}
			return out, nil
		}
		use := in
		if c.inputSet {
			v, ok := c.Input.(In)
			if !ok {
				return zero, fmt.Errorf("%w: a hook set the input of %s to %T, the operation takes %T", ErrBadOperation, o.info.ID, c.Input, in)
			}
			use = v
		}
		return o.run(ctx, c, use)
	}}
	// any(in) is how Go asks whether a type parameter implements an
	// interface; nothing is erased, the value keeps its type.
	if id, ok := any(in).(Identified); ok {
		p.rateID = id.RateIdentifier()
	}
	return p
}
