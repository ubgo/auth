package auth

import (
	"context"
	"fmt"
)

// Scheduled maintenance beyond Sweep: jobs a plugin runs over its own rows or
// over users, such as mailing the owners of dormant accounts. Nothing here
// runs by itself, as with Sweep: the library has no background workers, so an
// app calls Maintain from a scheduled job, or runs "auth maintain" from the CLI.
// Kept apart from Sweep because Sweep only deletes what already stopped
// mattering and is safe to run on a whim, while maintenance can send mail and
// delete accounts and must be asked for by name.

// MaintainOptions are what one Maintain run is asked to do.
//
//ds:def id=core-maintainoptions-4qv7nx2k owner=@khanakia stability=stable
type MaintainOptions struct {
	// DryRun reports what the run would do, in the same counters, without
	// sending, writing or deleting anything.
	DryRun bool
}

// Maintainer is a plugin with a job for Maintain, such as plugin/stale. Maintain
// returns counters named by what they count ("warned", "deleted"); Auth.Maintain
// prefixes each with the plugin's name. It must be idempotent: a scheduler may
// run it twice, and a second run right after the first finds nothing left to
// do. A run that cannot finish returns the counters it has with an error.
//
//ds:def id=core-maintainer-8rm3wk5q owner=@khanakia stability=stable
type Maintainer interface {
	Maintain(ctx context.Context, o MaintainOptions) (map[string]int64, error)
}

// Maintain runs every Maintainer plugin in registration order and returns
// their counters as "<plugin>.<counter>", in the same shape as SweepResult. A
// failing plugin stops the run after recording what it had done, so a later
// plugin never works on a broken earlier one's half-finished state; the error
// names the plugin. With no Maintainer registered it returns an empty result.
//
//ds:def id=core-maintain-6wx9nq3v owner=@khanakia stability=stable
func (a *Auth) Maintain(ctx context.Context, o MaintainOptions) (SweepResult, error) {
	out := SweepResult{}
	for _, p := range a.plugins {
		m, ok := p.(Maintainer)
		if !ok {
			continue
		}
		counters, err := m.Maintain(ctx, o)
		for k, v := range counters {
			out[p.Name()+"."+k] = v
		}
		if err != nil {
			return out, fmt.Errorf("auth: maintain %s: %w", p.Name(), err)
		}
	}
	return out, nil
}
