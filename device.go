package auth

import "context"

// Remembered devices and credential changes: what a second-factor plugin
// needs from the core to trust a browser for a while, and to drop that trust
// when the credential it was granted behind changes.

// RequestDevice returns the device token the client sent with the request in
// ctx, from an earlier EffectRememberDevice (HTTP: a cookie of its own), or
// "" outside a request or when the client holds none. The core gives it no
// meaning: the plugin that issued it (two-factor "remember this browser")
// hashes and checks it.
//
//ds:def id=core-requestdevice-5wq8tn3k owner=@khanakia stability=stable
func RequestDevice(ctx context.Context) Token {
	st := stateFrom(ctx)
	if st == nil {
		return ""
	}
	return st.req.Device
}

// CredentialListener is a plugin that must hear when a user's credential
// changed: a password reset or change, a recovery. The two-factor plugin
// forgets the user's remembered devices on it, because a reset is often the
// answer to a stolen account and a device trusted before it must not
// outlive it.
//
//ds:def id=core-credentiallistener-8pm2xv6r owner=@khanakia stability=stable
type CredentialListener interface {
	CredentialChanged(ctx context.Context, userID string) error
}

// CredentialChanged tells every CredentialListener plugin, in plugin order,
// that userID's credential changed, inside the transaction of ctx when there
// is one. The plugin that changed the credential calls it after its own
// write and after ending the sessions it ends; the first error stops the
// call and rolls everything back with it.
//
//ds:def id=core-credentialchanged-3tk7qw9m owner=@khanakia stability=stable
func (a *Auth) CredentialChanged(ctx context.Context, userID string) error {
	for _, p := range a.plugins {
		if l, ok := p.(CredentialListener); ok {
			if err := l.CredentialChanged(ctx, userID); err != nil {
				return err
			}
		}
	}
	return nil
}
