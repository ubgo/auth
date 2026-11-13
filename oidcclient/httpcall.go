package oidcclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// HTTP names the package sends and reads. They are wire constants of RFC
// 6749, RFC 6750 and the Fetch standard, kept in one place so no handler
// spells one twice.
const (
	headerContentType   = "Content-Type"
	headerAuthorization = "Authorization"
	headerCacheControl  = "Cache-Control"
	headerPragma        = "Pragma"
	headerLocation      = "Location"
	headerAllow         = "Allow"
	headerOrigin        = "Origin"
	headerSecFetchSite  = "Sec-Fetch-Site"
	mediaTypeJSON       = "application/json"
	mediaTypeForm       = "application/x-www-form-urlencoded"
	cacheNoStore        = "no-store"
	pragmaNoCache       = "no-cache"
	schemeBasic         = "Basic "
	schemeBearer        = "Bearer "
	tokenTypeBearer     = "Bearer"
	fetchSameOrigin     = "same-origin"
)

// maxResponseBytes bounds any body read from the login server: a discovery
// document, a key set or a token answer is a few kilobytes, and a server
// that streams more is not answering the protocol.
const maxResponseBytes = 1 << 20

// oauthError is RFC 6749 section 5.2's error body, read from a refusing
// token, introspection or userinfo endpoint for the log.
type oauthError struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// OAuth error codes the package names (RFC 6749 section 4.1.2.1).
const (
	oauthAccessDenied = "access_denied"
)

// send performs req with the client's HTTP client and returns the body of
// a 200 answer. Every other outcome is classified, because the middleware
// decides on the class, not the detail:
//
//   - no answer (a transport error, a timeout), a 5xx, a 429, an unexpected
//     status (a 3xx the client did not follow, a 204), or a body that cannot
//     be read in full: ErrProviderUnavailable, which starts the outage grace;
//   - any other 4xx: ErrProviderRefused, the server's "no", with its RFC
//     6749 error code when the body carries one.
//
// The endpoint named in the error is the request URL without its query, so
// a token in a query string never reaches a log.
func (p *Provider) send(req *http.Request) ([]byte, error) {
	endpoint := redactURL(req.URL)
	res, err := p.c.set.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrProviderUnavailable, endpoint, err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: read: %w", ErrProviderUnavailable, endpoint, err)
	}
	if len(body) > maxResponseBytes {
		return nil, fmt.Errorf("%w: %s: answer larger than %d bytes", ErrProviderUnavailable, endpoint, maxResponseBytes)
	}
	switch {
	case res.StatusCode == http.StatusOK:
		return body, nil
	case res.StatusCode == http.StatusTooManyRequests || res.StatusCode >= http.StatusInternalServerError:
		return nil, fmt.Errorf("%w: %s answered %d", ErrProviderUnavailable, endpoint, res.StatusCode)
	case res.StatusCode >= http.StatusBadRequest:
		var oe oauthError
		_ = json.Unmarshal(body, &oe) // an unreadable error body still is a "no"; the status says so
		return nil, &refusedError{endpoint: endpoint, status: res.StatusCode, code: oe.Code}
	}
	return nil, fmt.Errorf("%w: %s answered %d", ErrProviderUnavailable, endpoint, res.StatusCode)
}

// refusedError is a 4xx from the login server: ErrProviderRefused with the
// status and the RFC 6749 error code, for the log and for the callback,
// which answers access_denied differently.
type refusedError struct {
	endpoint string
	status   int
	code     string
}

func (e *refusedError) Error() string {
	return fmt.Sprintf("%v: %s answered %d %s", ErrProviderRefused, e.endpoint, e.status, e.code)
}

// Unwrap makes errors.Is(err, ErrProviderRefused) true.
func (e *refusedError) Unwrap() error { return ErrProviderRefused }

// oauthErrorOf returns the RFC 6749 error code of a refusedError in err's
// chain, or "".
func oauthErrorOf(err error) string {
	var re *refusedError
	if errors.As(err, &re) {
		return re.code
	}
	return ""
}

// decodeJSON reads a 200 answer into v. A body that is not the JSON the
// protocol promises is ErrProviderUnavailable: the server answered, but
// not with anything the package can act on, which is an outage of the
// protocol rather than a "no".
func decodeJSON(endpoint string, body []byte, v any) error {
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("%w: %s: unreadable answer: %w", ErrProviderUnavailable, endpoint, err)
	}
	return nil
}

// redactURL is u without its query and fragment, for errors and logs.
func redactURL(u *url.URL) string {
	c := *u
	c.RawQuery, c.Fragment, c.User = "", "", nil
	return c.String()
}

// noStore marks an answer as never cacheable: every answer that sets or
// clears a session cookie, or carries a token, is one person's.
func noStore(w http.ResponseWriter) {
	w.Header().Set(headerCacheControl, cacheNoStore)
	w.Header().Set(headerPragma, pragmaNoCache)
}
