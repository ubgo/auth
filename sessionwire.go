package auth

import "fmt"

// wireSessionExtras settles the session options that depend on the mode
// wireSessions chose: the compact cache's key, the stateless read interval,
// the revocation list and the device-session extras. Each refuses the
// combination where it would do nothing, so a deployment never believes it
// has a protection it does not.
func (a *Auth) wireSessionExtras(s *settings) error {
	if cc, ok := a.cache.(*compactCache); ok {
		// Like the snapshot cache: no key means the derived one, and no key
		// with no secret is refused here, not at the first request.
		keys, err := a.cfg.derivedOrGiven("NewCompactSessionCache", KeyLabelCompactCache, cc.keys)
		if err != nil {
			return err
		}
		cc.keys = keys
	}
	if s.statelessReadSet {
		if a.stateless == nil {
			return fmt.Errorf("%w: WithStatelessRefreshWithoutRead needs WithStatelessSessions", ErrBadOperation)
		}
		a.stateless.readEvery = clampReadInterval(s.statelessRead)
	}
	if s.revocations != nil {
		if a.stateless == nil {
			return fmt.Errorf("%w: WithSessionRevocations needs WithStatelessSessions; a stored session is ended by deleting it", ErrBadOperation)
		}
		a.revocations = s.revocations
	}
	if s.deviceExtras {
		if !a.cfg.MultiSession.Enabled || a.sessionExtras == nil {
			return fmt.Errorf("%w: WithDeviceSessionExtras needs WithMultiSession and WithSessionExtras", ErrBadOperation)
		}
		a.deviceExtras = true
	}
	return nil
}
