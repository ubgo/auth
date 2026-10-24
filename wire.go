package auth

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// wireOperations binds every operation to this instance, then refuses any
// combination that could not be served unambiguously. disabled names the
// operations WithDisabledOperations switched off: each must exist, and is
// then left out of the list every transport serves. appHooks are the
// WithOperationHooks hooks, checked like a plugin's and run after them.
func (a *Auth) wireOperations(disabled []EndpointID, appHooks []OperationHook) error {
	a.opsByID = make(map[EndpointID]Operation)
	a.disabled = make(map[EndpointID]struct{}, len(disabled))
	routes := make(map[string]EndpointID)
	off := make(map[EndpointID]bool, len(disabled))
	for _, id := range disabled {
		off[id] = true
	}

	add := func(owner string, op Operation) error {
		info := op.Info()
		if err := validateOpInfo(info); err != nil {
			return fmt.Errorf("%w: %s %q: %v", ErrBadOperation, owner, info.ID, err)
		}
		if err := checkOutputTokens(op.OutputType()); err != nil {
			return fmt.Errorf("%w: %s %q: %v", ErrBadOperation, owner, info.ID, err)
		}
		if off[info.ID] {
			// Bound to no instance and marked, so a Go call answers
			// ErrUnknownOperation like the missing route does, and a second
			// registration of the id is still caught below.
			op.disable()
			a.disabled[info.ID] = struct{}{}
			delete(off, info.ID)
			return nil
		}
		op.bind(a, owner)
		if prev, dup := a.opsByID[info.ID]; dup {
			return fmt.Errorf("%w: id %q is registered by %q and by %q", ErrDuplicateOperation, info.ID, prev.Plugin(), owner)
		}
		key := string(info.Kind) + " " + op.Route()
		if prev, dup := routes[key]; dup {
			return fmt.Errorf("%w: %s is served by %q and by %q", ErrDuplicateOperation, key, prev, info.ID)
		}
		a.opsByID[info.ID], routes[key] = op, info.ID
		if !info.SelfServed {
			// A self-served operation's plugin serves it over HTTP itself;
			// leaving it out of the list is what keeps every transport from
			// mounting it.
			a.ops = append(a.ops, op)
		}
		return nil
	}

	// The core's operations first, then each plugin's in list order, through
	// one loop: a plugin that reuses a core id or route is refused by the
	// same check as two plugins colliding.
	type owned struct {
		owner string
		op    Operation
	}
	a.core = newCoreOps(a)
	var all []owned
	for _, op := range a.core.list(a.cfg.MultiSession.Enabled, a.deferRefresh, a.accountDeletionOn) {
		all = append(all, owned{CorePluginName, op})
	}
	for _, p := range a.plugins {
		if prov, ok := p.(OperationProvider); ok {
			for _, op := range prov.Operations() {
				all = append(all, owned{p.Name(), op})
			}
		}
	}
	for _, o := range all {
		if err := add(o.owner, o.op); err != nil {
			return err
		}
	}
	for id := range off {
		// A disabled id nothing registered is a typo, and a typo here means
		// the operation the deployment meant to switch off is still served.
		return fmt.Errorf("%w: WithDisabledOperations names %q", ErrUnknownHookTarget, id)
	}

	for _, p := range a.plugins {
		hk, ok := p.(OperationHooker)
		if !ok {
			continue
		}
		if err := a.addOperationHooks(p.Name(), hk.OperationHooks()); err != nil {
			return err
		}
	}
	return a.addOperationHooks(HookSourceApp, appHooks)
}

// addOperationHooks registers hooks from one source (a plugin's name or
// HookSourceApp), refusing a Match that names no operation: a typo there
// means the hook silently never runs.
func (a *Auth) addOperationHooks(source string, hooks []OperationHook) error {
	// The error names what the app wrote (the option or the plugin), not
	// the span label.
	label := "plugin " + source
	if source == HookSourceApp {
		label = "WithOperationHooks"
	}
	for _, h := range hooks {
		for _, id := range h.Match {
			if !a.knowsOperation(id) {
				return fmt.Errorf("%w: %s hooks %q", ErrUnknownHookTarget, label, id)
			}
		}
		a.opHooks = append(a.opHooks, registeredHook{OperationHook: h, source: source})
	}
	return nil
}

// knowsOperation reports whether id is served or deliberately disabled. A
// hook or rule aimed at a disabled operation is kept, not refused: the plugin
// that declared it is still correct, the deployment merely switched the
// operation off.
func (a *Auth) knowsOperation(id EndpointID) bool {
	if _, ok := a.opsByID[id]; ok {
		return true
	}
	_, ok := a.disabled[id]
	return ok
}

// WithDisabledOperations switches operations off by id, such as
// password.EndpointSignUp for an app that creates its accounts itself. A
// disabled operation has no route on any transport (the request is answered
// like an unknown path) and its Go method returns ErrUnknownOperation, so no
// entry point serves it by accident. New refuses an id nothing registered.
//
// It disables whole operations only. A rate rule a plugin declared for an
// operation cannot be removed, because a limit that can be switched off by
// configuration is one a deployment switches off by mistake.
//
//ds:def id=opt-withdisabledoperations-4bkqa6ax owner=@khanakia stability=stable
func WithDisabledOperations(ids ...EndpointID) Option {
	return func(s *settings) { s.disabled = append(s.disabled, ids...) }
}

// DisabledOperations returns the ids WithDisabledOperations switched off, in
// no particular order, for operators and documentation tools.
func (a *Auth) DisabledOperations() []EndpointID {
	out := make([]EndpointID, 0, len(a.disabled))
	for id := range a.disabled {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

func validateOpInfo(info OpInfo) error {
	switch {
	case info.ID == "":
		return fmt.Errorf("empty id")
	case info.Kind != Query && info.Kind != Mutation:
		return fmt.Errorf("unknown kind %q", info.Kind)
	case !slices.Contains(RequirementValues, info.Require):
		return fmt.Errorf("unknown requirement %q", info.Require)
	case !strings.HasPrefix(info.Path, "/"):
		return fmt.Errorf("path %q must start with /", info.Path)
	case info.CrossSiteForm && (info.Kind != Mutation || info.Require != Public):
		return fmt.Errorf("a cross-site form must be a Public Mutation, not %s %s: it skips the origin check", info.Require, info.Kind)
	case info.CrossSiteForm && info.SelfServed:
		// CrossSiteForm tells a transport how to decode the form; a
		// self-served operation has no transport to tell, and the origin
		// check it skips would then be skipped for a handler nobody vetted.
		return fmt.Errorf("a self-served operation cannot be a cross-site form")
	}
	return nil
}

// resolveOrigins builds the allow-list for the origin check.
func (a *Auth) resolveOrigins() error {
	a.trustedOrigins = make(map[string]struct{})
	// Each candidate keeps the setting it came from, so a refusal names the
	// option to fix rather than only the value.
	type candidate struct{ raw, from string }
	var candidates []candidate
	if a.cfg.BaseURL != "" {
		candidates = append(candidates, candidate{a.cfg.BaseURL, "auth.WithBaseURL"})
	}
	for _, raw := range a.cfg.TrustedOrigins {
		candidates = append(candidates, candidate{raw, "auth.WithTrustedOrigins"})
	}
	for _, p := range a.plugins {
		if ot, ok := p.(OriginTruster); ok {
			for _, raw := range ot.TrustedOrigins() {
				candidates = append(candidates, candidate{raw, "plugin " + strconv.Quote(p.Name()) + " TrustedOrigins"})
			}
		}
	}
	a.trustedSchemes = make(map[string]struct{})
	for _, cand := range candidates {
		raw := cand.raw
		if scheme, ok := parseSchemeOnly(raw); ok {
			a.trustedSchemes[scheme] = struct{}{}
			continue
		}
		if p, ok, err := parseOriginPattern(raw); err != nil {
			return fmt.Errorf("%s: %w", cand.from, err)
		} else if ok {
			a.originPatterns = append(a.originPatterns, p)
			continue
		}
		o := originOf(raw)
		if o == "" {
			return fmt.Errorf("%w: %s: %q", ErrBadOrigin, cand.from, raw)
		}
		a.trustedOrigins[o] = struct{}{}
	}
	return nil
}

// capabilityNames maps each optional plugin interface to the name New logs.
// A method with a wrong signature silently stops implementing its interface in
// Go, so the log line is where a missing capability becomes visible.
func capabilities(p Plugin) []string {
	var out []string
	add := func(ok bool, name string) {
		if ok {
			out = append(out, name)
		}
	}
	_, ok := p.(Initializer)
	add(ok, "Initializer")
	_, ok = p.(Validator)
	add(ok, "Validator")
	_, ok = p.(Dependent)
	add(ok, "Dependent")
	_, ok = p.(TableOwner)
	add(ok, "TableOwner")
	_, ok = p.(SignInMethod)
	add(ok, "SignInMethod")
	_, ok = p.(SessionChecker)
	add(ok, "SessionChecker")
	_, ok = p.(OperationProvider)
	add(ok, "OperationProvider")
	_, ok = p.(OperationHooker)
	add(ok, "OperationHooker")
	_, ok = p.(DataHooker)
	add(ok, "DataHooker")
	_, ok = p.(ColumnExtender)
	add(ok, "ColumnExtender")
	_, ok = p.(Migrator)
	add(ok, "Migrator")
	_, ok = p.(TypedMigrator)
	add(ok, "TypedMigrator")
	_, ok = p.(IdentifierProvider)
	add(ok, "IdentifierProvider")
	_, ok = p.(Deliverer)
	add(ok, "Deliverer")
	_, ok = p.(VerificationSender)
	add(ok, "VerificationSender")
	_, ok = p.(RateLimiter)
	add(ok, "RateLimiter")
	_, ok = p.(OriginTruster)
	add(ok, "OriginTruster")
	_, ok = p.(CredentialCounter)
	add(ok, "CredentialCounter")
	_, ok = p.(Closer)
	add(ok, "Closer")
	return out
}

func (a *Auth) logCapabilities() {
	for _, p := range a.plugins {
		a.logger.Debug("auth: plugin wired", "plugin", p.Name(), "capabilities", strings.Join(capabilities(p), ","))
	}
}
