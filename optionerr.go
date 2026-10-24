package auth

import (
	"errors"
	"fmt"
	"reflect"
)

// OptionErrors collects the mistakes options can only find while they run,
// above all a nil func or interface, so the component they configure fails
// start-up with an error naming the option instead of panicking at the first
// request that calls the nil value.
//
// Why it exists: a functional option returns nothing, so it cannot fail by
// itself. Every option in this module and its plugin and contrib modules that
// takes a func or an interface records a nil here, and the error surfaces
// where the component is checked: New calls OptionErr on every plugin and on
// every component given to it through an option (see OptionChecker), and a
// constructor that returns an error returns it. One helper rather than a
// hand-written check per option, so the rule and its message are the same
// everywhere; the guard test TestGuard_OptionsRefuseNil finds every option
// that takes a func or an interface and fails if one does not call it.
//
// The zero value is ready to use. Keep it in an unexported field and expose
// OptionErr through a one-line method, so the type's public surface gains
// only OptionErr.
type OptionErrors struct{ err error }

// RefuseNil records ErrNilOption naming the option name ("email.WithMailer")
// when v is nil, and reports whether it did, so an option reads
//
//	if p.optErrs.RefuseNil("email.WithMailer", m) {
//		return
//	}
//
// and keeps its default. Nil means a nil interface, a nil func or a nil
// pointer (a typed nil inside an interface included): each would panic at
// its first call or dereference.
func (o *OptionErrors) RefuseNil(name string, v any) bool {
	if !isNilOption(v) {
		return false
	}
	o.err = errors.Join(o.err, nilOptionError(name))
	return true
}

// JoinOptionErr adds err, which may be nil, to the collected errors. A
// composite option (one applying a nested list of options to a config of its
// own) passes the nested collector's OptionErr up with it.
func (o *OptionErrors) JoinOptionErr(err error) { o.err = errors.Join(o.err, err) }

// OptionErr is every error the options recorded, joined; nil when none.
func (o *OptionErrors) OptionErr() error { return o.err }

// RefuseNilEach is RefuseNil for a variadic option: it records ErrNilOption
// naming name when any element of vs is nil, and reports whether it did. A
// generic function rather than a method because Go methods cannot have type
// parameters.
func RefuseNilEach[T any](o *OptionErrors, name string, vs []T) bool {
	for _, v := range vs {
		if o.RefuseNil(name, v) {
			return true
		}
	}
	return false
}

// OptionChecker is implemented by a plugin or a component that collects
// option errors (usually through an OptionErrors field). New calls OptionErr
// on every plugin and on every component given to it through an option
// (rate store, session store, session cache, revocations, secondary storage,
// verification store, sealer, observer, tracer, message catalogue) before
// anything else, so a nil option inside a plugin or a contrib store fails
// start-up the same way a nil core option does.
type OptionChecker interface {
	OptionErr() error
}

// optionErrOf is v's OptionErr when v is an OptionChecker, else nil.
func optionErrOf(v any) error {
	if oc, ok := v.(OptionChecker); ok {
		return oc.OptionErr()
	}
	return nil
}

// optionErr is every option error New must refuse: the core options' own,
// then each plugin's and each component's OptionErr, in that order, joined.
// The core's storage wrappers (NewStorageSessionStore and the others) pass
// on the wrapped storage's OptionErr, so WithSecondaryStorage is covered.
func (s *settings) optionErr() error {
	errs := []error{s.optErrs.OptionErr()}
	for _, p := range s.plugins {
		errs = append(errs, optionErrOf(p))
	}
	for _, c := range []any{s.rateStore, s.sessions, s.cache, s.revocations, s.verifications, s.cfg.sealer, s.observer, s.tracer, s.messages} {
		errs = append(errs, optionErrOf(c))
	}
	return errors.Join(errs...)
}

// isNilOption reports whether v is nil or holds a nil func or pointer.
func isNilOption(v any) bool {
	if v == nil {
		return true
	}
	switch rv := reflect.ValueOf(v); rv.Kind() {
	case reflect.Func, reflect.Pointer:
		return rv.IsNil()
	default:
		return false
	}
}

// nilOptionError is the one ErrNilOption message: the option's name and
// "(nil)", such as "email.WithMailer(nil)".
func nilOptionError(name string) error { return fmt.Errorf("%w: %s(nil)", ErrNilOption, name) }
