package auth

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
)

// Error is an error that a caller outside the process may see.
//
// Why it exists: an HTTP client needs a stable code to pick a message, a Go
// caller needs a value for errors.Is, and neither may ever see an internal
// detail such as a SQL error, because that detail tells an attacker how the
// system is built. An Error carries exactly the three things that are safe to
// send — a code, a status and a message — and every transport renders it the
// same way. Anything that is not an Error is reported as "auth.internal" and its
// text goes to the log only.
//
// Invariant: Code is "<plugin>.<name>" or "auth.<name>" for the core, so two
// plugins can never declare the same code. Message is written for an end user
// and must not depend on whether an account exists.
//
//ds:def id=core-error-u6547ehr owner=@khanakia stability=stable
type Error struct {
	Code    string
	Status  int
	Message string
}

// NewError declares an error once, at package level, in the plugin that owns
// it. The value is then both the sentinel for errors.Is and the source of the
// wire response.
//
//ds:def id=core-newerror-5gqrhbw2 owner=@khanakia stability=stable
func NewError(code string, status int, message string) *Error {
	e := &Error{Code: code, Status: status, Message: message}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if prev, dup := registry.byCode[code]; dup {
		if prev.Status != status || prev.Message != message {
			registry.conflicts[code] = append(registry.conflicts[code], e)
		}
		return e
	}
	registry.byCode[code] = e
	return e
}

// registry holds every declared Error by code, and the later declarations
// that disagreed with the first; see Errors and ErrorCodeConflicts.
var registry = struct {
	mu        sync.Mutex
	byCode    map[string]*Error
	conflicts map[string][]*Error
}{byCode: map[string]*Error{}, conflicts: map[string][]*Error{}}

// ErrorCodeConflicts returns the codes declared more than once with a
// different status or message, sorted: two plugins sharing a code would
// answer clients ambiguously. A documentation generator or a wiring test
// fails on a non-empty list; NewError itself does not panic, because a test
// may build an Error with a known code on purpose.
//
//ds:def id=core-errorcodeconflicts-2vq7xn8k owner=@khanakia stability=stable
func ErrorCodeConflicts() []string {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	out := make([]string, 0, len(registry.conflicts))
	for code := range registry.conflicts {
		out = append(out, code)
	}
	slices.Sort(out)
	return out
}

// Errors returns every error declared with NewError so far, one per code,
// the first declaration, sorted by code: the complete list a client can
// meet, for a generated reference or typed client. It is complete once every
// plugin package is imported, which is the case for any program that wires
// them.
//
//ds:def id=core-errors-4kq9wn2x owner=@khanakia stability=stable
func Errors() []*Error {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	out := make([]*Error, 0, len(registry.byCode))
	for _, e := range registry.byCode {
		out = append(out, e)
	}
	slices.SortFunc(out, func(x, y *Error) int { return strings.Compare(x.Code, y.Code) })
	return out
}

// Error returns the code, which is what a log line should show. The message is
// for end users and is not needed to identify the failure.
func (e *Error) Error() string { return e.Code }

// Is reports equality by code, so an Error that a plugin copied or wrapped
// still matches its declared sentinel under errors.Is.
//
//ds:def id=core-error-is-czm58ubw owner=@khanakia stability=stable
func (e *Error) Is(target error) bool {
	var t *Error
	if !errors.As(target, &t) {
		return false
	}
	return t.Code == e.Code
}

// ErrorInfo is the safe, transport-neutral description of any error.
//
//ds:def id=core-errorinfo-wjvs3c6f owner=@khanakia stability=stable
type ErrorInfo struct {
	Code    string `json:"code"`
	Status  int    `json:"-"`
	Message string `json:"message"`
	// OriginalMessage is the declared English message when Message was
	// translated by the WithMessages catalogue, as better-auth's i18n plugin
	// answers it, so a log or a support screen can show the text the
	// reference documents; empty (and left out of the JSON) when Message is
	// the declared one.
	OriginalMessage string `json:"originalMessage,omitempty"`
}

// ErrorOf describes err for a response. Every transport calls it, so REST,
// GraphQL and any custom transport answer the same failure with the same code.
//
// An error that is not an *Error — a database error, a bug — becomes
// ErrInternal. That is deliberate: its text may contain SQL, a table name or a
// value, and none of that may reach a client. The caller is expected to log the
// original error before it discards it.
//
//ds:def id=core-errorof-pdarrq6t owner=@khanakia stability=stable
func ErrorOf(err error) ErrorInfo {
	var e *Error
	if errors.As(err, &e) {
		return ErrorInfo{Code: e.Code, Status: e.Status, Message: e.Message}
	}
	return ErrorInfo{Code: ErrInternal.Code, Status: ErrInternal.Status, Message: ErrInternal.Message}
}

// Errors the core itself returns to callers. Plugins declare their own the same
// way, with their own prefix.
var (
	// ErrInternal stands for every error that is not safe to describe.
	ErrInternal = NewError("auth.internal", http.StatusInternalServerError, "Something went wrong. Try again.")

	// ErrSignedOut is returned when an operation needs a session and the call
	// has none. It says nothing about why: an expired, revoked and missing
	// session look the same to the caller.
	ErrSignedOut = NewError("auth.signed_out", http.StatusUnauthorized, "Sign in to continue.")

	// ErrImpersonationRefused is returned for a FreshSignIn operation on an
	// impersonation session.
	ErrImpersonationRefused = NewError("auth.impersonation_refused", http.StatusForbidden, "This cannot be done while acting as another user.")

	// ErrFreshSessionRequired is returned when an operation needs a fresh
	// session, such as changing a password, and the current one was neither
	// created nor re-authenticated (Reauthenticate) within the fresh window.
	ErrFreshSessionRequired = NewError("auth.fresh_session_required", http.StatusForbidden, "Sign in again to continue.")

	// ErrOriginNotTrusted is returned when a call that carries a session
	// cookie comes from an origin that is not trusted. It is the CSRF defence.
	ErrOriginNotTrusted = NewError("auth.origin_not_trusted", http.StatusForbidden, "This request came from a site that is not trusted.")

	// ErrBadRequest is returned when the input of an operation cannot be
	// decoded. It never echoes the input back.
	ErrBadRequest = NewError("auth.bad_request", http.StatusBadRequest, "The request is not valid.")

	// ErrUnknownOperation is returned by a transport that is asked for an
	// operation that no plugin registered.
	ErrUnknownOperation = NewError("auth.unknown_operation", http.StatusNotFound, "Not found.")
)
