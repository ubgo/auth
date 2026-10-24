package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Unknown-device sign-in notification: when a user signs in from a device the
// library has not seen them use, a message goes to their recovery channel.
// Off by default, on with WithUnknownDeviceNotification. What counts as
// "seen" is a DeviceRecognizer; the default compares the sign-in's user agent
// with the user's other sessions. The check and the send run after the
// sign-in commits, in the background, so neither can slow or fail a sign-in.

// PurposeUnknownDevice is the purpose of the message sent when a user signs
// in from a device not seen before. Its Data is UnknownDeviceData, and it
// carries English DefaultSubject and DefaultText, so every delivering plugin
// (an SMS one too) has wording; an app's own templates, per locale through
// the delivering plugin (email.TemplatesByLocale), win over them.
//
//ds:def id=core-purposeunknowndevice-6vq2mk8t owner=@khanakia stability=stable
const PurposeUnknownDevice Purpose = "unknown_device"

// UnknownDeviceData is Message.Data for PurposeUnknownDevice: what an app
// template shows about the sign-in. IP is "" under WithoutIPTracking.
//
//ds:def id=core-unknowndevicedata-3hn7wq4x owner=@khanakia stability=stable
type UnknownDeviceData struct {
	UserAgent string    `json:"userAgent"`
	IP        string    `json:"ip,omitempty"`
	At        time.Time `json:"at"`
	SessionID string    `json:"sessionId"`
	// Method is the sign-in method, the plugin of the operation that signed
	// the user in ("password", "oauth"), or "" for a Go call outside one.
	Method string `json:"method,omitempty"`
}

// DeviceSignIn is the sign-in a DeviceRecognizer judges. It is a struct so
// fields can be added without breaking implementers.
type DeviceSignIn struct {
	// Auth is the instance, for a recognizer that reads sessions or tables.
	Auth   *Auth
	UserID string
	// Session is the new session; it is already committed, so a recognizer
	// listing sessions must leave it out by id.
	Session Session
	Client  Client
	// Operation and Method are as in SignInAttempt: the operation that
	// signed the user in and its plugin, "" for a Go call outside one.
	Operation EndpointID
	Method    string
}

// DeviceRecognizer decides whether a sign-in comes from a device the user
// has used before. It runs after the sign-in, off the request, so it may
// read the database; an error is logged and nothing is sent, since an
// alarm on every sign-in while a store is down would teach users to ignore
// it. The default is SessionDevices; an app with a device cookie, a
// fingerprinting service or a table of its own passes its rule through
// WithDeviceRecognizer.
//
//ds:def id=core-devicerecognizer-8pt3vn6k owner=@khanakia stability=stable
type DeviceRecognizer interface {
	KnownDevice(ctx context.Context, in DeviceSignIn) (bool, error)
}

// DeviceRecognizerFunc adapts a function to DeviceRecognizer.
type DeviceRecognizerFunc func(ctx context.Context, in DeviceSignIn) (bool, error)

// KnownDevice calls f.
func (f DeviceRecognizerFunc) KnownDevice(ctx context.Context, in DeviceSignIn) (bool, error) {
	return f(ctx, in)
}

// SessionDevices returns the default DeviceRecognizer: a sign-in is from a
// known device when another of the user's sessions has the same DeviceKey
// (the user agent without its version numbers, so a browser update is not
// a new device). It reads the live sessions and, under WithSessionArchive,
// the revoked ones, so a device the user signed out of stays known. Pending
// sessions (a second factor not yet passed) and impersonation sessions are
// not the user's devices and do not count. A user with no other session at
// all (the first sign-in, or every session expired and swept) is treated as
// known: there is nothing to compare with, and a mail on every first
// sign-in would be noise. The IP address is not compared: it changes with
// every network a phone joins.
//
// It needs a session list, so New refuses it with WithStatelessSessions,
// where only the request's own session is known.
//
//ds:def id=core-sessiondevices-4kw9xm2q owner=@khanakia stability=stable
func SessionDevices() DeviceRecognizer { return sessionDevices{} }

// sessionDevices is SessionDevices.
type sessionDevices struct{}

// KnownDevice compares the sign-in's device key with the user's other
// sessions'.
func (sessionDevices) KnownDevice(ctx context.Context, in DeviceSignIn) (bool, error) {
	live, err := in.Auth.Sessions(ctx, in.UserID)
	if err != nil {
		return false, err
	}
	revoked, err := in.Auth.RevokedSessions(ctx, in.UserID)
	if err != nil && !errors.Is(err, ErrNoDatabase) {
		return false, err
	}
	key := DeviceKey(in.Client.UserAgent)
	others := false
	for _, s := range append(live, revoked...) {
		if s.ID == in.Session.ID || s.SecondFactorPending || s.ImpersonatedBy != nil {
			continue
		}
		if DeviceKey(s.UserAgent) == key {
			return true, nil
		}
		others = true
	}
	return !others, nil
}

// deviceVersion matches the version numbers in a user agent ("129.0.6668",
// "10_15_7"): the parts that change with every update of the same browser
// on the same machine.
var deviceVersion = regexp.MustCompile(`[0-9]+([._][0-9]+)*`)

// DeviceKey reduces a user agent to what stays the same across updates of
// one browser on one machine: the string with its version numbers removed
// and its spaces folded, so "Chrome/129.0.0.0" and "Chrome/130.0.0.0" on the
// same system are one device. It is a heuristic, as anything read from a
// user agent is: two machines of the same make and browser share a key.
//
//ds:def id=core-devicekey-7mz4tq8n owner=@khanakia stability=stable
func DeviceKey(userAgent string) string {
	return strings.Join(strings.Fields(deviceVersion.ReplaceAllString(userAgent, "")), " ")
}

// WithUnknownDeviceNotification sends the user a message (PurposeUnknownDevice,
// to their best recovery channel, as a password reset goes) when they sign in
// from a device not seen before, judged by SessionDevices unless
// WithDeviceRecognizer replaces it. Every full session counts as a sign-in,
// including the one a second factor promotes; a pending session waits for
// its promotion, and an impersonation is not the user's sign-in.
//
// It never blocks a sign-in: the check and the send run after the sign-in
// commits, in the background (WithBackground, waited for by
// WaitDeliveries), and a failure of either is logged. A user without a
// verified recovery identity gets nothing. Under WithDeliveryOutbox the
// message is queued and retried like any other.
//
//ds:def id=opt-withunknowndevicenotification-2xq8vk5m owner=@khanakia stability=stable
func WithUnknownDeviceNotification() Option {
	return func(s *settings) { s.unknownDevice = true }
}

// WithDeviceRecognizer replaces the rule WithUnknownDeviceNotification
// judges a device by. It does not turn the notification on: New refuses it
// without WithUnknownDeviceNotification, since it would change nothing.
//
//ds:def id=opt-withdevicerecognizer-5nh2wq7v owner=@khanakia stability=stable
func WithDeviceRecognizer(r DeviceRecognizer) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithDeviceRecognizer", r) {
			return
		}
		s.deviceRecognizer = r
	}
}

// wireUnknownDevice settles the notification at New, after the session
// store: SessionDevices needs a session list, which stateless mode lacks.
func (a *Auth) wireUnknownDevice(s *settings) error {
	if !s.unknownDevice {
		if s.deviceRecognizer != nil {
			return fmt.Errorf("%w: auth.WithDeviceRecognizer needs auth.WithUnknownDeviceNotification", ErrBadOperation)
		}
		return nil
	}
	a.deviceRecognizer = s.deviceRecognizer
	if a.deviceRecognizer == nil {
		if a.stateless != nil {
			return fmt.Errorf("%w: auth.WithUnknownDeviceNotification: the default device rule reads the user's sessions, which WithStatelessSessions does not keep; pass auth.WithDeviceRecognizer", ErrBadOperation)
		}
		a.deviceRecognizer = SessionDevices()
	}
	return nil
}

// afterSignIn schedules the unknown-device check for a new session, once
// the transaction in ctx commits. Pending and impersonation sessions are
// not sign-ins of the user's own device, and an import (Quiet) sends
// nothing.
func (a *Auth) afterSignIn(ctx context.Context, s Session, client Client, seed sessionSeed) {
	if a.deviceRecognizer == nil || seed.pending || seed.continued || seed.impersonator != nil || isQuiet(ctx) {
		return
	}
	attempt := a.signInAttempt(ctx, s.UserID, client, false)
	in := DeviceSignIn{Auth: a, UserID: s.UserID, Session: s, Client: client, Operation: attempt.Operation, Method: attempt.Method}
	a.AfterCommit(ctx, func(ctx context.Context) {
		a.RunInBackground(ctx, func(ctx context.Context) { a.notifyUnknownDevice(ctx, in) })
	})
}

// unknownDeviceSubject is the English subject of the message.
const unknownDeviceSubject = "New sign-in to your account"

// notifyUnknownDevice asks the recognizer and, for an unknown device, sends
// the message. Every failure is logged, never returned: the sign-in is done.
func (a *Auth) notifyUnknownDevice(ctx context.Context, in DeviceSignIn) {
	known, err := a.deviceRecognizer.KnownDevice(ctx, in)
	if err != nil {
		a.logger.Error("auth: unknown-device check failed", "user", in.UserID, "error", err)
		return
	}
	if known {
		return
	}
	data := UnknownDeviceData{UserAgent: in.Client.UserAgent, IP: in.Session.IP, At: in.Session.CreatedAt, SessionID: in.Session.ID, Method: in.Method}
	m := Message{Purpose: PurposeUnknownDevice, Data: data, DefaultSubject: unknownDeviceSubject, DefaultText: unknownDeviceText(data)}
	if err := a.DeliverRecovery(ctx, in.UserID, m); err != nil {
		if errors.Is(err, ErrNoRecoveryChannel) {
			a.logger.Debug("auth: unknown-device sign-in, no recovery channel to tell", "user", in.UserID)
			return
		}
		a.logger.Error("auth: unknown-device notification failed", "user", in.UserID, "error", err)
	}
}

// unknownDeviceText is the English body: what signed in, when, from where,
// and what to do if it was not the user.
func unknownDeviceText(d UnknownDeviceData) string {
	device := d.UserAgent
	if device == "" {
		device = "an unnamed client"
	}
	var b strings.Builder
	b.WriteString("Your account was just signed in to from a device we have not seen you use before.\n\n")
	b.WriteString("Device: " + device + "\n")
	if d.IP != "" {
		b.WriteString("IP address: " + d.IP + "\n")
	}
	b.WriteString("Time: " + d.At.UTC().Format(time.RFC1123) + "\n\n")
	b.WriteString("If this was you, you can ignore this message. If it was not, change your password now and sign out every other session.")
	return b.String()
}

// decodeCoreMessageData restores Message.Data for the core's own purposes
// from the delivery outbox; (nil, nil) for any other purpose.
// The any result is the boundary type of Message.Data and of
// MessageDataDecoder, which carries an app-defined payload per purpose; here it
// is always UnknownDeviceData.
func decodeCoreMessageData(p Purpose, raw json.RawMessage) (any, error) {
	if p != PurposeUnknownDevice {
		return nil, nil
	}
	var d UnknownDeviceData
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	return d, nil
}
