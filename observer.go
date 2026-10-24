package auth

import (
	"context"
	"fmt"
	"time"
)

// OperationEvent describes one finished call, successful or not, to an
// Observer. Err is nil for success and otherwise the error the caller got,
// so an observer can count refusals by code (errors.As to *Error) without
// seeing any input or output: those stay with the operation, because a
// metrics sink is the last place a password or a token should travel to.
//
//ds:def id=core-operationevent-9qmvrxbe owner=@khanakia stability=stable
type OperationEvent struct {
	Op        OpInfo
	Plugin    string
	Transport Transport
	// Duration is from the pipeline's first check to the result, measured on
	// the configured clock.
	Duration time.Duration
	Err      error
}

// Observer sees every operation end. It is the hook for metrics, tracing and
// error reporting: one Observer, not an error callback plus a timing callback
// plus a log hook, so a trace span and an error counter are built from the
// same event and cannot disagree about what happened.
//
// Operation runs on the request's goroutine after the result is known and
// before it is returned, so it must be quick and must not fail: it returns
// nothing, and a panic in it is the app's.
//
//ds:def id=core-observer-4c7sgyun owner=@khanakia stability=stable
type Observer interface {
	Operation(ctx context.Context, e OperationEvent)
}

// ObserverFunc adapts a function to Observer.
type ObserverFunc func(ctx context.Context, e OperationEvent)

// Operation calls f.
func (f ObserverFunc) Operation(ctx context.Context, e OperationEvent) { f(ctx, e) }

// WithObserver sets the observer every call reports to. Without one nothing
// is measured, and the pipeline reads no clock for it.
//
//ds:def id=opt-withobserver-8mvzpdru owner=@khanakia stability=stable
func WithObserver(o Observer) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithObserver", o) {
			return
		}
		s.observer = o
	}
}

// BackgroundFunc runs task after the response, detached from the request.
// ctx is the request's context without its cancellation, so the task is not
// cut short by the client hanging up, but with its values, so a tenant scope
// or a trace survives into it. The function must return at once: the request
// is waiting on it.
//
//ds:def id=core-backgroundfunc-6dfpk3re owner=@khanakia stability=stable
type BackgroundFunc func(ctx context.Context, task func(context.Context))

// WithBackground replaces how post-commit work such as message delivery
// leaves the request. The default starts a goroutine. A platform that ends
// the process with the response (a serverless runtime with a waitUntil, a
// worker pool with a queue) passes its own runner. The core still bounds each
// task (DeliveryTimeout) and WaitDeliveries still waits for them, because the
// runner is told when a task ends through the function it is handed.
//
//ds:def id=opt-withbackground-7zhq8n2w owner=@khanakia stability=stable
func WithBackground(run BackgroundFunc) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithBackground", run) {
			return
		}
		s.background = run
	}
}

// RunInBackground hands task to the WithBackground runner now, for a plugin
// whose bookkeeping must not hold up the response (an API key's last-use
// stamp): ctx loses its cancellation and keeps its values, the task is
// bounded by DeliveryTimeout like a delivery, and WaitDeliveries waits for
// it, so a test or a shutdown sees it finish. It does not wait for the call's
// transaction: a task that must see committed data goes through AfterCommit
// first. A failure is the task's to log.
func (a *Auth) RunInBackground(ctx context.Context, task func(context.Context)) {
	a.deliveries.Add(1)
	a.background(context.WithoutCancel(ctx), func(ctx context.Context) {
		defer a.deliveries.Done()
		ctx, cancel := context.WithTimeout(ctx, DeliveryTimeout)
		defer cancel()
		task(ctx)
	})
}

// goBackground is the default BackgroundFunc: one goroutine per task.
func goBackground(ctx context.Context, task func(context.Context)) { go task(ctx) }

// WithoutIPTracking stops sessions from recording the client's address.
// Sessions and the session list then show no IP. Rate limits by IP still
// count: they hold the address for a window, not for the life of a session,
// and a limiter that forgot addresses would not limit anything.
//
//ds:def id=opt-withoutiptracking-3f2vnmkt owner=@khanakia stability=stable
func WithoutIPTracking() Option { return func(s *settings) { s.noIPTracking = true } }

// TracksIP reports whether sessions record the client's address: false under
// WithoutIPTracking. A plugin that records addresses of its own (an audit
// log) follows it, so one option covers every place an address is kept.
func (a *Auth) TracksIP() bool { return a.trackIP }

// WithDefaultLocale sets the locale of a message whose request carried no
// language (no Accept-Language, or a Go call), as a BCP 47 tag such as "de".
// A plugin's templates by locale (email.TemplatesByLocale and the like) are
// looked up with it through PickLocale. Without it such a message has no
// locale and gets the plugin's default template.
//
//ds:def id=opt-withdefaultlocale-5wc4ae9h owner=@khanakia stability=stable
func WithDefaultLocale(tag string) Option { return func(s *settings) { s.defaultLocale = tag } }

// maxLocaleTagLen is the longest BCP 47 tag accepted for a default locale,
// the same bound transports apply to a client's.
const maxLocaleTagLen = 35

// checkLocaleTag refuses a default locale that is not a plausible tag: letters,
// digits and "-" only. Empty is fine and means none.
func checkLocaleTag(tag string) error {
	if tag == "" {
		return nil
	}
	if len(tag) > maxLocaleTagLen {
		return fmt.Errorf("%w: default locale %q is longer than %d characters", ErrBadOperation, tag, maxLocaleTagLen)
	}
	for _, r := range tag {
		if !(r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return fmt.Errorf("%w: default locale %q is not a language tag such as \"de-CH\"", ErrBadOperation, tag)
		}
	}
	return nil
}

// SessionExtras computes SessionResult.Extras for the signed-in call: the
// roles, the plan, whatever the front end needs with the session so it does
// not make a second request for it. It runs inside core.session with the
// call's user and session, after the requirement check, so c.User is set.
//
//ds:def id=core-sessionextras-8ph6yn7v owner=@khanakia stability=stable
type SessionExtras func(ctx context.Context, c *Call) (any, error)

// WithSessionExtras adds app data to the session response (GET /session and
// Auth.Session). The value is encoded as the "extras" field; a nil value or no
// function leaves the field out, so the response is unchanged for every app
// that does not use it.
//
//ds:def id=opt-withsessionextras-9zxg2w8t owner=@khanakia stability=stable
func WithSessionExtras(fn SessionExtras) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithSessionExtras", fn) {
			return
		}
		s.sessionExtras = fn
	}
}

// WithStatelessVersion numbers the stateless session tokens. A token carries
// the version it was sealed with and opens only while it matches: raising the
// number signs every user out at once without rotating the key, and lowering
// it back does not revive them, because the tokens have been cleared by their
// browsers by then. The default is 0; a negative number is refused, and the
// option without WithStatelessSessions is refused too, since no token would
// carry it.
//
//ds:def id=opt-withstatelessversion-2b8jt6kq owner=@khanakia stability=stable
func WithStatelessVersion(n int) Option { return func(s *settings) { s.statelessVersion = n } }
