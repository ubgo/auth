package deviceauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

// RFC 6749 / RFC 8628 error codes, the "error" member CodeHandler and
// TokenHandler answer. A device client library (golang.org/x/oauth2's
// DeviceAccessToken, for one) switches on these exact strings.
const (
	RFCInvalidRequest       = "invalid_request"
	RFCInvalidClient        = "invalid_client"
	RFCInvalidGrant         = "invalid_grant"
	RFCUnsupportedGrantType = "unsupported_grant_type"
	RFCAuthorizationPending = "authorization_pending"
	RFCSlowDown             = "slow_down"
	RFCAccessDenied         = "access_denied"
	RFCExpiredToken         = "expired_token"
	RFCServerError          = "server_error"
	// RFCInvalidTarget is RFC 8707's answer for a resource the server does
	// not serve, which a Grant's error reports through RFCCoder.
	RFCInvalidTarget = "invalid_target"
	// RFCTemporarilyUnavailable answers a rate-limited request, RFC 6749
	// §4.1.2.1's code for "try again later".
	RFCTemporarilyUnavailable = "temporarily_unavailable"
)

// maxBody bounds a code or token request body: three short parameters.
const maxBody = 16 << 10

// rfcCodes maps each request error to its RFC code. An error not listed is
// server_error, so nothing internal reaches the client.
var rfcCodes = []struct {
	err  error
	code string
}{
	{ErrInvalidRequest, RFCInvalidRequest},
	{auth.ErrBadRequest, RFCInvalidRequest},
	{ErrUnsupportedGrantType, RFCUnsupportedGrantType},
	{ErrInvalidClient, RFCInvalidClient},
	{ErrInvalidDeviceCode, RFCInvalidGrant},
	{ErrExpiredDeviceCode, RFCExpiredToken},
	{ErrAuthorizationPending, RFCAuthorizationPending},
	{ErrPollingTooFrequently, RFCSlowDown},
	{ErrAccessDenied, RFCAccessDenied},
	{ErrNotOwner, RFCAccessDenied},
	{ErrInvalidUserCode, RFCInvalidRequest},
	{ErrExpiredUserCode, RFCExpiredToken},
	{ErrAlreadyProcessed, RFCInvalidRequest},
	{ErrNotClaimed, RFCInvalidRequest},
	{auth.ErrRateLimited, RFCTemporarilyUnavailable},
}

// RFCCoder is an error that names its own RFC error code, for a Grant
// whose refusals (invalid_scope, invalid_target) this plugin does not know.
type RFCCoder interface {
	RFCCode() string
}

// RFCErrorCode returns the RFC 8628 error code for an error of this plugin,
// the code of an RFCCoder, and server_error for anything else.
//
//ds:def id=deviceauth-rfcerrorcode-5k9wq2mv owner=@khanakia stability=stable
func RFCErrorCode(err error) string {
	for _, m := range rfcCodes {
		if errors.Is(err, m.err) {
			return m.code
		}
	}
	var rc RFCCoder
	if errors.As(err, &rc) && rc.RFCCode() != "" {
		return rc.RFCCode()
	}
	return RFCServerError
}

// rfcError is the RFC 6749 §5.2 error body.
type rfcError struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
	// Auth is the same failure as the library's own error (code, message),
	// under an extension member an RFC client ignores (RFC 6749 §5.2 lets a
	// response carry members it does not define). It is what lets the
	// library's TypeScript client, whose device.code and device.token calls
	// reach these handlers when they are mounted on the operation's route,
	// tell authorization_pending from slow_down, access_denied and
	// expired_token by the plugin's declared codes instead of answering
	// client.invalid_response for all four.
	Auth auth.ErrorInfo `json:"auth_error"`
}

// newRFCError pairs the RFC code with the library's error for err. The
// library's message is in the request's locale when the app configured a
// catalogue; error_description stays the declared English one, because RFC
// 6749 §5.2 limits it to printable ASCII.
func newRFCError(ctx context.Context, code string, err error) rfcError {
	return rfcError{Error: code, Description: auth.ErrorOf(err).Message, Auth: auth.ErrorInfoFor(ctx, err)}
}

// CodeHandler serves /device/code in RFC 8628's own shape: a form or JSON
// body, the RFC error body ({"error":"invalid_client"}, with the library's
// own error beside it under "auth_error"), Cache-Control: no-store. Mount it
// where authhttp.Handler would serve the route, so a stock device client
// and the library's TypeScript client both work unchanged; both run the
// same operation.
//
//ds:def id=deviceauth-codehandler-8w2nq6kt owner=@khanakia stability=stable
func (p *Plugin) CodeHandler(opts ...authhttp.Option) http.Handler { return p.rfcHandler(p.code, opts) }

// TokenHandler serves /device/token in RFC 8628's own shape, as CodeHandler
// does for /device/code: authorization_pending, slow_down, expired_token and
// access_denied come back as {"error": ...} with status 400.
//
//ds:def id=deviceauth-tokenhandler-3m7xv9qw owner=@khanakia stability=stable
func (p *Plugin) TokenHandler(opts ...authhttp.Option) http.Handler {
	return p.rfcHandler(p.token, opts)
}

// rfcHandler runs op through the pipeline with the RFC's decoding and error
// shape; the operation, its rate limits and its hooks are the ones the
// default handler runs.
func (p *Plugin) rfcHandler(op auth.Operation, opts []authhttp.Option) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			e := newRFCError(r.Context(), RFCInvalidRequest, authhttp.ErrMethodNotAllowed)
			e.Description = "use POST"
			writeRFC(w, http.StatusMethodNotAllowed, e)
			return
		}
		ctx := p.core.WithRequest(r.Context(), authhttp.RequestOf(r, opts...))
		r = r.WithContext(ctx)
		out, err := op.Invoke(ctx, func(dst any) error { return decodeRFC(r, dst) })
		if err != nil {
			authhttp.SetRetryAfter(w, err)
			e := newRFCError(ctx, RFCErrorCode(err), err)
			// RFC 6749 §5.2 answers 400; a rate limit and a server failure
			// keep their status, because a client backs off on those.
			status := e.Auth.Status
			if status != http.StatusTooManyRequests && status < http.StatusInternalServerError {
				status = http.StatusBadRequest
			}
			if errors.Is(err, auth.ErrBadRequest) {
				e.Description = "The request body is malformed or repeats a parameter."
			}
			writeRFC(w, status, e)
			return
		}
		authhttp.ApplyEffects(w, r, auth.RequestEffects(ctx), opts...)
		writeRFC(w, http.StatusOK, out)
	})
}

// decodeRFC fills dst from a form body (RFC 8628 §3.1) or a JSON one. A form
// parameter given twice is refused, as RFC 6749 §3.1 requires, by answering
// an error the pipeline reports as auth.ErrBadRequest (invalid_request).
func decodeRFC(r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, maxBody)
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mt == "application/json" {
		return json.NewDecoder(r.Body).Decode(dst)
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	vals, err := url.ParseQuery(string(body))
	if err != nil {
		return err
	}
	flat := make(map[string]string, len(vals))
	for k, v := range vals {
		for _, one := range v {
			if one == "" {
				continue // an empty duplicate is treated as omitted, as better-auth does
			}
			if flat[k] != "" {
				return errRepeated
			}
			flat[k] = one
		}
	}
	// A map of strings always marshals.
	b, _ := json.Marshal(flat)
	return json.Unmarshal(b, dst)
}

// errRepeated is a form parameter sent twice.
var errRepeated = errors.New("deviceauth: repeated parameter")

// writeRFC writes v as JSON. v is any because it is the output of whichever
// operation ran; the encoder is the boundary where it leaves Go.
func writeRFC(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v) // a client that hung up cannot be told
}
