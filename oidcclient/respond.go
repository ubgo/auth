package oidcclient

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// RefusalKind is what the person must be told: the answer a Responder
// writes. It is the coarse half of a Refusal; Reason is the fine half.
type RefusalKind string

const (
	// RefusalLoginRequired: no usable session. A page is redirected to
	// LoginURL; an API call gets 401.
	RefusalLoginRequired RefusalKind = "login_required"
	// RefusalNoAccess: signed in, but the app (Authorizer, UserMapper) or the
	// login server (access_denied at the callback) says no. 403.
	RefusalNoAccess RefusalKind = "no_access"
	// RefusalUnavailable: the login server has been unreachable for longer
	// than the outage grace. The session is kept. 503.
	RefusalUnavailable RefusalKind = "unavailable"
	// RefusalFailed: something broke (a store, a hook's own failure, a
	// callback that does not verify). 500 for a failure of the app, 400 for
	// a callback that is not acceptable; the cause is logged, never shown.
	RefusalFailed RefusalKind = "failed"
)

// RefusalKindValues is every RefusalKind.
var RefusalKindValues = []RefusalKind{RefusalLoginRequired, RefusalNoAccess, RefusalUnavailable, RefusalFailed}

// Reason is why a request was refused, for observers and logs. It is
// finer than RefusalKind and may grow; a Responder decides on Kind.
type Reason string

const (
	ReasonNoSession       Reason = "no_session"         // no cookie, or one that does not open
	ReasonIdleExpired     Reason = "idle_expired"       // past LastSeenAt + Idle
	ReasonAbsoluteExpired Reason = "absolute_expired"   // past CreatedAt + Absolute
	ReasonServerRefused   Reason = "server_refused"     // the Rechecker said Deny
	ReasonServerDown      Reason = "server_down"        // unreachable past the outage grace
	ReasonNotAuthorized   Reason = "not_authorized"     // the Authorizer or UserMapper said no
	ReasonProviderDenied  Reason = "provider_denied"    // the callback carried error=access_denied
	ReasonBadCallback     Reason = "bad_callback"       // state, PKCE, ID token or iss check failed
	ReasonHookFailed      Reason = "hook_failed"        // a UserMapper or Authorizer returned another error
	ReasonStoreFailed     Reason = "store_failed"       // the SessionStore or Sealer failed
	ReasonBackchannel     Reason = "backchannel_logout" // a logout token ended the session
	ReasonProviderInvalid Reason = "provider_invalid"   // the discovery document or a server answer broke a floor
)

// ReasonValues is every Reason.
var ReasonValues = []Reason{ReasonNoSession, ReasonIdleExpired, ReasonAbsoluteExpired, ReasonServerRefused, ReasonServerDown,
	ReasonNotAuthorized, ReasonProviderDenied, ReasonBadCallback, ReasonHookFailed, ReasonStoreFailed, ReasonBackchannel, ReasonProviderInvalid}

// Refusal is one refused request, for a Responder to answer.
type Refusal struct {
	Kind   RefusalKind
	Reason Reason
	// LoginURL is the login route with this request's same-site path as
	// return_to, set for RefusalLoginRequired.
	LoginURL string
	// Err is the cause, for the log. A Responder must not show it: it may
	// name internals.
	Err error
}

// Responder writes the answer to a refused request: the seam for the
// app's own templates, a JSON shape its SPA expects, or translated pages.
// The default is DefaultResponder. It cannot change the decision: the
// request is refused whatever it writes.
type Responder interface {
	Respond(w http.ResponseWriter, r *http.Request, ref Refusal)
}

// ResponderFunc adapts a function to Responder.
type ResponderFunc func(w http.ResponseWriter, r *http.Request, ref Refusal)

// Respond calls f.
func (f ResponderFunc) Respond(w http.ResponseWriter, r *http.Request, ref Refusal) { f(w, r, ref) }

// DefaultResponder answers a page request (IsPageRequest) with a redirect
// to the login route for RefusalLoginRequired and a plain HTML page for the
// rest, and an API call with a JSON body {"error": kind, "login_url": …}
// and the status of the kind. A custom Responder can delegate the kinds it
// does not handle to it.
func DefaultResponder() Responder {
	return ResponderFunc(func(w http.ResponseWriter, r *http.Request, ref Refusal) {
		noStore(w)
		status := refusalStatus(ref)
		if IsPageRequest(r) {
			if ref.Kind == RefusalLoginRequired && ref.LoginURL != "" {
				w.Header().Set(headerLocation, ref.LoginURL)
				w.WriteHeader(http.StatusFound)
				return
			}
			page, ok := refusalPages[ref.Kind]
			if !ok {
				page = refusalPages[RefusalFailed]
			}
			w.Header().Set(headerContentType, mediaTypeHTMLUTF8)
			w.WriteHeader(status)
			_, _ = fmt.Fprintf(w, refusalPage, page.title, page.message) // a browser that hung up cannot be told
			return
		}
		w.Header().Set(headerContentType, mediaTypeJSON)
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(refusalBody{Error: ref.Kind, LoginURL: ref.LoginURL}) // a client that hung up cannot be told
	})
}

// refusalBody is the JSON DefaultResponder answers an API call with.
type refusalBody struct {
	Error    RefusalKind `json:"error"`
	LoginURL string      `json:"login_url,omitempty"`
}

// refusalStatus is the HTTP status of a refusal: 401 login required, 403
// no access, 503 unavailable, and for a failure 400 when the callback was
// not acceptable, else 500.
func refusalStatus(ref Refusal) int {
	switch ref.Kind {
	case RefusalLoginRequired:
		return http.StatusUnauthorized
	case RefusalNoAccess:
		return http.StatusForbidden
	case RefusalUnavailable:
		return http.StatusServiceUnavailable
	}
	if ref.Reason == ReasonBadCallback {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

// refusalPage is DefaultResponder's plain page. Its two values are the
// constants of refusalPages: nothing from the request is ever written
// into it.
const refusalPage = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>%[1]s</title><h1>%[1]s</h1><p>%[2]s</p>`

// pageText is one refusal page's wording.
type pageText struct{ title, message string }

// refusalPages is DefaultResponder's wording per kind. A login-required
// page shows only when there is no login URL to redirect to.
var refusalPages = map[RefusalKind]pageText{
	RefusalLoginRequired: {"Sign-in required", "Please sign in to continue."},
	RefusalNoAccess:      {"No access", "You are signed in, but this account may not use this app."},
	RefusalUnavailable:   {"Temporarily unavailable", "The sign-in service cannot be reached. Please try again in a moment."},
	RefusalFailed:        {"Something went wrong", "Signing in did not work. Please try again."},
}

// IsPageRequest reports whether r is a browser navigation that should get
// a redirect or a page rather than a status and JSON: a GET or HEAD whose
// Accept header lists text/html. It is the rule DefaultResponder uses,
// exported for a custom Responder that keeps it.
func IsPageRequest(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	return strings.Contains(r.Header.Get(headerAccept), mediaTypeHTML)
}

// HTTP names the responder and handlers use.
const (
	headerAccept      = "Accept"
	mediaTypeHTML     = "text/html"
	mediaTypeHTMLUTF8 = "text/html; charset=utf-8"
)
