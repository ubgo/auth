package password

import "github.com/ubgo/auth/plugin/username"

// The username plugin is the default UsernameClaimer: if its method drifts,
// sign-up with a username would answer ErrNoUsernames in every app, so the
// build fails here instead.
var _ UsernameClaimer = (*username.Plugin)(nil)
