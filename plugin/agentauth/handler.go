package agentauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

// HTTP constants.
const (
	headerAuthorization = "Authorization"
	headerCookie        = "Cookie"
	headerContentType   = "Content-Type"
	headerCacheControl  = "Cache-Control"
	headerAllow         = "Allow"
	headerWWWAuth       = "WWW-Authenticate"
	// headerXForwardedProto and headerXForwardedHost are read only under
	// TrustProxy.
	headerXForwardedProto = "X-Forwarded-Proto"
	headerXForwardedHost  = "X-Forwarded-Host"
	contentTypeJSON       = "application/json"
	schemeBearer          = "Bearer"
	noStore               = "no-store"
	// configurationCacheControl is better-auth's caching of the discovery
	// document: an hour, RFC 9111.
	configurationCacheControl = "public, max-age=3600"
	// maxBodyBytes bounds a request body.
	maxBodyBytes = 1 << 20
	// queryAgentID, queryName, queryCursor and queryLimit are the query
	// parameters of the GET endpoints.
	queryAgentID = "agent_id"
	queryName    = "name"
	queryCursor  = "cursor"
	queryLimit   = "limit"
)

// errorBody is the protocol's error answer, section 5.13.
type errorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// protocolCode is the protocol error code for err: the part after
// "agentauth." of the plugin's own errors, a generic code otherwise.
func protocolCode(err error) string {
	info := auth.ErrorOf(err)
	switch {
	case strings.HasPrefix(info.Code, PluginName+"."):
		return strings.TrimPrefix(info.Code, PluginName+".")
	case info.Status == http.StatusTooManyRequests:
		return "rate_limited"
	case info.Status == http.StatusUnauthorized:
		return "unauthorized"
	case info.Status >= http.StatusInternalServerError:
		return "internal_error"
	}
	return "invalid_request"
}

// issuerPath is the issuer's path, "" for a bare host.
func (p *Plugin) issuerPath() string {
	u, err := url.Parse(p.issuer)
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(u.Path, "/")
}

// Handler serves the protocol endpoints at their paths under the issuer,
// and the discovery document at /.well-known/agent-configuration: mount it
// at the root of the issuer's host. opts are the authhttp options the
// app's auth handler uses, so revoking by a signed-in user reads the same
// session. Every endpoint calls its operation through the pipeline; an
// unknown path answers 404.
func (p *Plugin) Handler(opts ...authhttp.Option) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := p.issuerPath()
		path := r.URL.Path
		switch path {
		case WellKnownConfiguration, base + WellKnownConfiguration, base + PathConfiguration:
			if p.allow(w, http.MethodGet, r) {
				p.serve(w, r, opts, false, func(r *http.Request, _ Bearer, _ []byte) (any, error) {
					w.Header().Set(headerCacheControl, configurationCacheControl)
					return p.configuration.Call(r.Context(), struct{}{})
				})
			}
		case base + PathRegister:
			p.post(w, r, opts, func(r *http.Request, b Bearer, body []byte) (any, error) {
				var in RegisterRequest
				if err := decode(body, &in); err != nil {
					return nil, err
				}
				in.Bearer = b
				return p.register.Call(r.Context(), in)
			})
		case base + PathSession:
			if p.allow(w, http.MethodGet, r) {
				p.serve(w, r, opts, false, func(r *http.Request, b Bearer, _ []byte) (any, error) {
					return p.session.Call(r.Context(), b)
				})
			}
		case base + PathStatus:
			if p.allow(w, http.MethodGet, r) {
				p.serve(w, r, opts, false, func(r *http.Request, b Bearer, _ []byte) (any, error) {
					return p.status.Call(r.Context(), StatusRequest{Bearer: b, AgentID: r.URL.Query().Get(queryAgentID)})
				})
			}
		case base + PathListCapabilities:
			if p.allow(w, http.MethodGet, r) {
				p.serve(w, r, opts, false, func(r *http.Request, b Bearer, _ []byte) (any, error) {
					q := r.URL.Query()
					limit, _ := strconv.Atoi(q.Get(queryLimit))
					return p.listCaps.Call(r.Context(), ListCapabilitiesRequest{Bearer: b, Cursor: q.Get(queryCursor), Limit: limit})
				})
			}
		case base + PathDescribeCapability:
			if p.allow(w, http.MethodGet, r) {
				p.serve(w, r, opts, false, func(r *http.Request, b Bearer, _ []byte) (any, error) {
					return p.describeCap.Call(r.Context(), DescribeCapabilityRequest{Bearer: b, Name: r.URL.Query().Get(queryName)})
				})
			}
		case base + PathRevoke:
			p.post(w, r, opts, func(r *http.Request, b Bearer, body []byte) (any, error) {
				var in RevokeRequest
				if err := decode(body, &in); err != nil {
					return nil, err
				}
				in.Bearer = b
				return p.revoke.Call(r.Context(), in)
			})
		case base + PathIntrospect:
			p.post(w, r, opts, func(r *http.Request, _ Bearer, body []byte) (any, error) {
				var in IntrospectRequest
				if err := decode(body, &in); err != nil {
					return nil, err
				}
				return p.introspect.Call(r.Context(), in)
			})
		case base + PathRequestCapability:
			p.post(w, r, opts, func(r *http.Request, b Bearer, body []byte) (any, error) {
				var in RequestCapabilityRequest
				if err := decode(body, &in); err != nil {
					return nil, err
				}
				in.Bearer = b
				return p.requestCap.Call(r.Context(), in)
			})
		case base + PathExecute:
			p.post(w, r, opts, func(r *http.Request, b Bearer, body []byte) (any, error) {
				var in ExecuteRequest
				if err := decode(body, &in); err != nil {
					return nil, err
				}
				in.Bearer = b
				return p.execute.Call(r.Context(), in)
			})
		case base + PathRotateHostKey:
			p.post(w, r, opts, func(r *http.Request, b Bearer, body []byte) (any, error) {
				var in RotateHostKeyRequest
				if err := decode(body, &in); err != nil {
					return nil, err
				}
				in.Bearer = b
				return p.rotateHostKey.Call(r.Context(), in)
			})
		case base + PathCIBAAuthorize:
			p.post(w, r, opts, func(r *http.Request, b Bearer, body []byte) (any, error) {
				var in CIBAAuthorizeRequest
				if err := decode(body, &in); err != nil {
					return nil, err
				}
				in.Bearer = b
				return p.cibaAuthorize.Call(r.Context(), in)
			})
		case base + PathRevokeHost:
			p.post(w, r, opts, func(r *http.Request, b Bearer, body []byte) (any, error) {
				var in RevokeHostRequest
				if err := decode(body, &in); err != nil {
					return nil, err
				}
				in.Bearer = b
				return p.revokeHost.Call(r.Context(), in)
			})
		case base + PathRevokeCapability:
			p.post(w, r, opts, func(r *http.Request, b Bearer, body []byte) (any, error) {
				var in RevokeCapabilityRequest
				if err := decode(body, &in); err != nil {
					return nil, err
				}
				in.Bearer = b
				return p.revokeCap.Call(r.Context(), in)
			})
		case base + PathClaim:
			p.post(w, r, opts, func(r *http.Request, b Bearer, body []byte) (any, error) {
				var in ClaimRequest
				if err := decode(body, &in); err != nil {
					return nil, err
				}
				in.Bearer = b
				return p.claim.Call(r.Context(), in)
			})
		case base + PathReactivate:
			p.post(w, r, opts, func(r *http.Request, b Bearer, body []byte) (any, error) {
				var in ReactivateRequest
				if err := decode(body, &in); err != nil {
					return nil, err
				}
				in.Bearer = b
				return p.reactivate.Call(r.Context(), in)
			})
		case base + PathRotateAgentKey:
			p.post(w, r, opts, func(r *http.Request, b Bearer, body []byte) (any, error) {
				var in RotateAgentKeyRequest
				if err := decode(body, &in); err != nil {
					return nil, err
				}
				in.Bearer = b
				return p.rotateAgent.Call(r.Context(), in)
			})
		case base + PathEnrollHost:
			p.post(w, r, opts, func(r *http.Request, _ Bearer, body []byte) (any, error) {
				var in EnrollHostRequest
				if err := decode(body, &in); err != nil {
					return nil, err
				}
				return p.enrollHost.Call(r.Context(), in)
			})
		default:
			http.NotFound(w, r)
		}
	})
}

// endpointFunc runs one endpoint's operation.
type endpointFunc func(r *http.Request, b Bearer, body []byte) (any, error)

// allow answers a wrong method; it reports whether to serve.
func (p *Plugin) allow(w http.ResponseWriter, method string, r *http.Request) bool {
	if r.Method != method {
		w.Header().Set(headerAllow, method)
		p.writeError(w, ErrInvalidRequest, http.StatusMethodNotAllowed)
		return false
	}
	return true
}

// post serves a POST endpoint with a JSON body.
func (p *Plugin) post(w http.ResponseWriter, r *http.Request, opts []authhttp.Option, fn endpointFunc) {
	if p.allow(w, http.MethodPost, r) {
		p.serve(w, r, opts, true, fn)
	}
}

// serve reads the bearer and the body, attaches the request to the
// pipeline, and answers fn's result. A request carrying an agent or host
// JWT has its Authorization header and cookies removed before the
// pipeline sees it: the JWT is the credential, and a session riding along
// must neither be resolved nor trip the cookie CSRF check. A request
// without one keeps its cookies, so a signed-in user can revoke.
func (p *Plugin) serve(w http.ResponseWriter, r *http.Request, opts []authhttp.Option, hasBody bool, fn endpointFunc) {
	var body []byte
	if hasBody {
		var err error
		body, err = io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
		if err != nil {
			p.writeError(w, ErrInvalidRequest, 0)
			return
		}
	}
	b, err := bearerOf(r, body, p.trustProxy)
	if err != nil {
		p.writeError(w, err, 0)
		return
	}
	if b.Token != "" {
		r = r.Clone(r.Context())
		r.Header.Del(headerAuthorization)
		r.Header.Del(headerCookie)
	}
	r, err = authhttp.Begin(p.core, r, opts...)
	if err != nil {
		p.writeError(w, err, 0)
		return
	}
	w.Header().Set(headerCacheControl, noStore)
	out, err := fn(r, b, body)
	if err != nil {
		if auth.ErrorOf(err).Status >= http.StatusInternalServerError {
			p.core.Logger().Error("agentauth: request failed", "error", err)
		}
		p.writeError(w, err, 0)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// bearerOf reads a "Bearer <jwt>" Authorization header and the request it
// binds; no header is an empty Bearer, any other scheme or a token that is
// not a three-part JWT is ErrInvalidJWT. trustProxy takes the request URL's
// scheme and host from X-Forwarded-Proto and X-Forwarded-Host (TrustProxy).
func bearerOf(r *http.Request, body []byte, trustProxy bool) (Bearer, error) {
	h := r.Header.Get(headerAuthorization)
	if h == "" {
		return Bearer{}, nil
	}
	authScheme, tok, _ := strings.Cut(h, " ")
	tok = strings.TrimSpace(tok)
	if !strings.EqualFold(authScheme, schemeBearer) || strings.Count(tok, ".") != jwtSegments-1 {
		return Bearer{}, ErrInvalidJWT
	}
	scheme, host := "https", r.Host
	if r.TLS == nil {
		scheme = "http"
	}
	if trustProxy {
		if v := forwarded(r, headerXForwardedProto); v == "http" || v == "https" {
			scheme = v
		}
		if v := forwarded(r, headerXForwardedHost); v != "" {
			host = v
		}
	}
	sum := sha256.Sum256(body)
	return Bearer{
		Token: tok, Method: r.Method, URL: scheme + "://" + host + r.URL.Path,
		BodySHA256: base64.RawURLEncoding.EncodeToString(sum[:]),
	}, nil
}

// forwarded is the first value of a proxy header, the one the client-facing
// proxy wrote.
func forwarded(r *http.Request, name string) string {
	v, _, _ := strings.Cut(r.Header.Get(name), ",")
	return strings.ToLower(strings.TrimSpace(v))
}

// decode reads a JSON body; an empty one decodes to the zero value.
func decode(body []byte, dst any) error {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(dst); err != nil {
		return ErrInvalidRequest
	}
	return nil
}

// writeError answers err in the protocol's shape, with status (0 takes the
// error's own), Retry-After for a rate limit, and the AgentAuth challenge
// on a 401, pointing the agent at the discovery document (section 6.14).
func (p *Plugin) writeError(w http.ResponseWriter, err error, status int) {
	info := auth.ErrorOf(err)
	if status == 0 {
		status = info.Status
	}
	if status == http.StatusUnauthorized {
		w.Header().Set(headerWWWAuth, p.challenge())
	}
	authhttp.SetRetryAfter(w, err)
	writeJSON(w, status, errorBody{Error: protocolCode(err), Message: info.Message})
}

// challenge is the WWW-Authenticate value of a 401.
func (p *Plugin) challenge() string {
	origin := p.issuer
	if u, err := url.Parse(p.issuer); err == nil {
		origin = u.Scheme + "://" + u.Host
	}
	return `AgentAuth discovery="` + origin + WellKnownConfiguration + `"`
}

// writeJSON takes any because it encodes whichever answer the endpoint
// produced; the encoder is where the typed value leaves Go.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set(headerContentType, contentTypeJSON)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v) // a client that hung up cannot be told
}

// VerifyAgentRequest authenticates the agent JWT of a request to one of
// the app's own routes, such as a capability with a Location: better-auth's
// verifyAgentRequest. It spends the token's jti. The route checks
// AgentSession.HasGrant, and enforces the grant's constraints itself.
func (p *Plugin) VerifyAgentRequest(r *http.Request, opts ...authhttp.Option) (AgentSession, error) {
	var body []byte
	if r.Body != nil && r.Body != http.NoBody {
		var err error
		if body, err = io.ReadAll(io.LimitReader(r.Body, maxBodyBytes)); err != nil {
			return AgentSession{}, ErrInvalidRequest
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	b, err := bearerOf(r, body, p.trustProxy)
	if err != nil {
		return AgentSession{}, err
	}
	if b.Token == "" {
		return AgentSession{}, ErrAuthenticationRequired
	}
	clean := r.Clone(r.Context())
	clean.Header.Del(headerAuthorization)
	clean.Header.Del(headerCookie)
	clean, err = authhttp.Begin(p.core, clean, opts...)
	if err != nil {
		return AgentSession{}, err
	}
	return p.session.Call(clean.Context(), b)
}
