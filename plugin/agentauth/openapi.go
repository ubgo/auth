package agentauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// openAPIMethods are the operation keys of an OpenAPI path item, in the
// order the specification lists them. Every other key of a path item
// (parameters, servers, summary, $ref, x-*) is not an operation.
var openAPIMethods = []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"}

// maxUpstreamBytes bounds an upstream answer the OpenAPI proxy reads.
const maxUpstreamBytes = 10 << 20

// contentTypeJSONPrefix matches an upstream JSON answer, with or without
// parameters.
const contentTypeJSONPrefix = "application/json"

// Parameter locations the proxy fills from the arguments.
const (
	paramInPath   = "path"
	paramInQuery  = "query"
	paramInHeader = "header"
)

// ErrBadOpenAPI is a spec the OpenAPI adapter cannot read.
var ErrBadOpenAPI = errors.New("agentauth: the OpenAPI document is not valid JSON with unique operationIds")

// OperationInfo is one OpenAPI operation as a filter sees it.
type OperationInfo struct {
	// Name is the operationId, the capability's name.
	Name string
	// Method is the HTTP method, upper case.
	Method      string
	Description string
}

// openAPIParam is one resolved operation parameter.
type openAPIParam struct {
	Name        string         `json:"name"`
	In          string         `json:"in"`
	Required    bool           `json:"required"`
	Schema      map[string]any `json:"schema"`
	Description string         `json:"description"`
}

// openAPIOperation is one operation, resolved against the spec.
type openAPIOperation struct {
	info    OperationInfo
	path    string
	params  []openAPIParam
	hasBody bool
	input   json.RawMessage
	output  json.RawMessage
}

// openAPIDoc is a parsed spec.
type openAPIDoc struct {
	title, description string
	ops                []openAPIOperation
}

// parseOpenAPI reads an OpenAPI 3.x document: every operation with an
// operationId, in path order, then method order. Local $refs
// ("#/components/...") are resolved one level.
func parseOpenAPI(spec []byte) (openAPIDoc, error) {
	var root map[string]any
	if err := json.Unmarshal(spec, &root); err != nil {
		return openAPIDoc{}, fmt.Errorf("%w: %w", ErrBadOpenAPI, err)
	}
	var doc openAPIDoc
	if info, ok := root["info"].(map[string]any); ok {
		doc.title, _ = info["title"].(string)
		doc.description, _ = info["description"].(string)
	}
	paths, _ := root["paths"].(map[string]any)
	keys := make([]string, 0, len(paths))
	for k := range paths {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	seen := map[string]bool{}
	for _, path := range keys {
		item, ok := resolveRef(root, paths[path]).(map[string]any)
		if !ok {
			continue
		}
		for _, method := range openAPIMethods {
			op, ok := resolveRef(root, item[method]).(map[string]any)
			if !ok {
				continue
			}
			id, _ := op["operationId"].(string)
			if id == "" {
				continue
			}
			if seen[id] {
				return openAPIDoc{}, fmt.Errorf("%w: operationId %q twice", ErrBadOpenAPI, id)
			}
			seen[id] = true
			desc, _ := op["description"].(string)
			if desc == "" {
				desc, _ = op["summary"].(string)
			}
			if desc == "" {
				desc = id
			}
			o := openAPIOperation{info: OperationInfo{Name: id, Method: strings.ToUpper(method), Description: desc}, path: path}
			o.params = mergeParams(root, item["parameters"], op["parameters"])
			body, _ := resolveRef(root, op["requestBody"]).(map[string]any)
			o.hasBody = body != nil
			o.input, o.output = inputSchema(root, o.params, body), outputSchema(root, op)
			doc.ops = append(doc.ops, o)
		}
	}
	return doc, nil
}

// resolveRef resolves a local JSON Reference against the spec root; anything
// else is returned as it is.
func resolveRef(root map[string]any, node any) any {
	m, ok := node.(map[string]any)
	if !ok {
		return node
	}
	ref, ok := m["$ref"].(string)
	if !ok || !strings.HasPrefix(ref, "#/") {
		return node
	}
	var cur any = root
	for _, part := range strings.Split(ref[2:], "/") {
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		next, ok := cur.(map[string]any)
		if !ok {
			return node
		}
		cur = next[part]
	}
	if cur == nil {
		return node
	}
	return cur
}

// mergeParams merges path-level and operation-level parameters, the
// operation's winning for the same name and location.
func mergeParams(root map[string]any, lists ...any) []openAPIParam {
	var out []openAPIParam
	for _, list := range lists {
		items, _ := list.([]any)
		for _, it := range items {
			raw, _ := json.Marshal(resolveRef(root, it)) // decoded from JSON, so it encodes
			var p openAPIParam
			if json.Unmarshal(raw, &p) != nil || p.Name == "" {
				continue
			}
			if i := slices.IndexFunc(out, func(q openAPIParam) bool { return q.Name == p.Name && q.In == p.In }); i >= 0 {
				out[i] = p
				continue
			}
			out = append(out, p)
		}
	}
	return out
}

// inputSchema is the JSON Schema of an operation's arguments: its
// parameters, then the properties of its JSON request body. Every value in
// it was decoded from the JSON document, so it always encodes.
func inputSchema(root map[string]any, params []openAPIParam, body map[string]any) json.RawMessage {
	props := map[string]any{}
	var required []string
	for _, p := range params {
		s := map[string]any{"type": "string"}
		if p.Schema != nil {
			s = map[string]any{}
			for k, v := range p.Schema {
				s[k] = v
			}
		}
		if p.Description != "" {
			s["description"] = p.Description
		}
		props[p.Name] = s
		if p.Required {
			required = append(required, p.Name)
		}
	}
	if schema, ok := jsonSchemaOf(root, body); ok {
		if bp, ok := schema["properties"].(map[string]any); ok {
			for k, v := range bp {
				props[k] = v
			}
		}
		if br, ok := schema["required"].([]any); ok {
			for _, r := range br {
				if s, ok := r.(string); ok && !slices.Contains(required, s) {
					required = append(required, s)
				}
			}
		}
	}
	if len(props) == 0 {
		return nil
	}
	out := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		out["required"] = required
	}
	b, _ := json.Marshal(out)
	return b
}

// outputSchema is the JSON Schema of the operation's 200 (else 201) JSON
// answer, decoded from the document and so always encodable.
func outputSchema(root map[string]any, op map[string]any) json.RawMessage {
	responses, _ := op["responses"].(map[string]any)
	res, ok := resolveRef(root, responses["200"]).(map[string]any)
	if !ok {
		if res, ok = resolveRef(root, responses["201"]).(map[string]any); !ok {
			return nil
		}
	}
	schema, ok := jsonSchemaOf(root, res)
	if !ok {
		return nil
	}
	b, _ := json.Marshal(schema)
	return b
}

// jsonSchemaOf is the resolved application/json schema of a request body
// or a response.
func jsonSchemaOf(root map[string]any, holder map[string]any) (map[string]any, bool) {
	content, _ := holder["content"].(map[string]any)
	media, _ := content[contentTypeJSON].(map[string]any)
	schema, ok := resolveRef(root, media["schema"]).(map[string]any)
	return schema, ok
}

// capabilities turns the operations into capabilities.
func (d openAPIDoc) capabilities() []Capability {
	out := make([]Capability, 0, len(d.ops))
	for _, o := range d.ops {
		out = append(out, Capability{Name: o.info.Name, Description: o.info.Description, Input: o.input, Output: o.output})
	}
	return out
}

// FromOpenAPI derives capabilities from an OpenAPI 3.x document, one per
// operation with an operationId: the name is
// the operationId, the description its description or summary, the input
// schema its parameters and JSON body, the output schema its 200 or 201
// JSON answer.
func FromOpenAPI(spec []byte) ([]Capability, error) {
	d, err := parseOpenAPI(spec)
	if err != nil {
		return nil, err
	}
	return d.capabilities(), nil
}

// HeadersFunc returns the headers a proxied call carries upstream, such as
// the user's access token there. They win
// over header parameters taken from the arguments, so an agent can never
// replace the credentials.
type HeadersFunc func(ctx context.Context, capability string, s AgentSession) (http.Header, error)

// OpenAPIHandlerOptions configures OpenAPIHandler.
type OpenAPIHandlerOptions struct {
	// BaseURL is the upstream API's base URL; each operation's path is
	// appended to it. Required.
	BaseURL string
	// Headers adds headers to every upstream request.
	Headers HeadersFunc
	// Client sends the requests; nil is http.DefaultClient.
	Client *http.Client
}

// ErrUpstream wraps an upstream answer that was not a success.
var ErrUpstream = errors.New("agentauth: upstream API error")

// OpenAPIHandler returns an ExecuteFunc that proxies each capability to its
// OpenAPI operation: path parameters
// are escaped into the path, query and header parameters set, the other
// arguments sent as the JSON body (not for GET or HEAD). A JSON answer is
// returned verbatim, any other as text; a 202's body is returned as it
// is. An answer that is neither 2xx is ErrUpstream, which reaches the
// agent as an internal error.
func OpenAPIHandler(spec []byte, o OpenAPIHandlerOptions) (ExecuteFunc, error) {
	d, err := parseOpenAPI(spec)
	if err != nil {
		return nil, err
	}
	return d.handler(o)
}

func (d openAPIDoc) handler(o OpenAPIHandlerOptions) (ExecuteFunc, error) {
	base, err := url.Parse(strings.TrimSuffix(o.BaseURL, "/"))
	if err != nil || !base.IsAbs() || base.Host == "" {
		return nil, fmt.Errorf("%w: BaseURL %q is not an absolute URL", ErrBadOpenAPI, o.BaseURL)
	}
	ops := make(map[string]openAPIOperation, len(d.ops))
	for _, op := range d.ops {
		ops[op.info.Name] = op
	}
	client := o.Client
	if client == nil {
		client = http.DefaultClient
	}
	return func(ctx context.Context, ex Execution) (any, error) {
		op, ok := ops[ex.Capability.Name]
		if !ok {
			return nil, ErrCapabilityNotFound
		}
		req, err := op.request(ctx, base.String(), ex.Arguments)
		if err != nil {
			return nil, err
		}
		if o.Headers != nil {
			h, err := o.Headers(ctx, ex.Capability.Name, ex.Session)
			if err != nil {
				return nil, err
			}
			for k, vs := range h {
				req.Header[http.CanonicalHeaderKey(k)] = vs
			}
		}
		res, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()
		body, err := io.ReadAll(io.LimitReader(res.Body, maxUpstreamBytes+1))
		if err != nil {
			return nil, err
		}
		if len(body) > maxUpstreamBytes {
			return nil, fmt.Errorf("%w: answer larger than %d bytes", ErrUpstream, maxUpstreamBytes)
		}
		if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
			return nil, fmt.Errorf("%w %d: %s", ErrUpstream, res.StatusCode, truncate(string(body), maxReasonRunes))
		}
		if strings.HasPrefix(res.Header.Get(headerContentType), contentTypeJSONPrefix) && json.Valid(body) {
			return json.RawMessage(body), nil
		}
		return string(body), nil
	}, nil
}

// request builds the upstream request for args.
func (op openAPIOperation) request(ctx context.Context, base string, args map[string]any) (*http.Request, error) {
	path := op.path
	query := url.Values{}
	headers := http.Header{}
	consumed := map[string]bool{}
	for _, p := range op.params {
		v, ok := args[p.Name]
		if !ok || v == nil {
			continue
		}
		s := argString(v)
		consumed[p.Name] = true
		switch p.In {
		case paramInPath:
			// A dot segment would walk the upstream path.
			if s == "" || s == "." || s == ".." {
				return nil, ErrInvalidRequest
			}
			path = strings.ReplaceAll(path, "{"+p.Name+"}", url.PathEscape(s))
		case paramInQuery:
			query.Set(p.Name, s)
		case paramInHeader:
			headers.Set(p.Name, s)
		}
	}
	target := base + path
	if q := query.Encode(); q != "" {
		target += "?" + q
	}
	var body io.Reader
	if op.hasBody && op.info.Method != http.MethodGet && op.info.Method != http.MethodHead {
		rest := map[string]any{}
		for k, v := range args {
			if !consumed[k] {
				rest[k] = v
			}
		}
		if len(rest) > 0 {
			b, err := json.Marshal(rest)
			if err != nil {
				return nil, ErrInvalidRequest
			}
			body = bytes.NewReader(b)
		}
	}
	req, err := http.NewRequestWithContext(ctx, op.info.Method, target, body)
	if err != nil {
		return nil, err
	}
	req.Header = headers
	req.Header.Set(headerContentType, contentTypeJSON)
	return req, nil
}

// argString is an argument as a URL or header value: JavaScript's
// String(value) for the JSON scalars, the JSON text otherwise.
func argString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	case json.Number:
		return x.String()
	}
	b, _ := json.Marshal(v) // a value JSON decoded always re-encodes
	return string(b)
}

// OperationFilter decides per operation: AllOperations takes every one,
// OperationsWithMethod those of a method or a list of methods, and any other
// function its callback, which also receives the host's context.
type OperationFilter func(ctx context.Context, op OperationInfo, hc HostCapabilitiesContext) (bool, error)

// AllOperations selects every operation.
func AllOperations() OperationFilter {
	return func(context.Context, OperationInfo, HostCapabilitiesContext) (bool, error) { return true, nil }
}

// OperationsWithMethod selects the operations of the given HTTP methods,
// in any case, such as "GET" and "HEAD" for read-only access.
func OperationsWithMethod(methods ...string) OperationFilter {
	upper := make([]string, 0, len(methods))
	for _, m := range methods {
		upper = append(upper, strings.ToUpper(m))
	}
	return func(_ context.Context, op OperationInfo, _ HostCapabilitiesContext) (bool, error) {
		return slices.Contains(upper, op.Method), nil
	}
}

// StrengthFunc assigns an approval strength per operation: StrengthForAll and
// StrengthByMethod, or any function.
type StrengthFunc func(op OperationInfo) ApprovalStrength

// StrengthForAll gives every operation s.
func StrengthForAll(s ApprovalStrength) StrengthFunc {
	return func(OperationInfo) ApprovalStrength { return s }
}

// StrengthByMethod maps HTTP methods to strengths, such as
// {"GET": StrengthSession, "POST": StrengthWebAuthn}; a method it does not
// name keeps the default.
func StrengthByMethod(m map[string]ApprovalStrength) StrengthFunc {
	upper := make(map[string]ApprovalStrength, len(m))
	for k, v := range m {
		upper[strings.ToUpper(k)] = v
	}
	return func(op OperationInfo) ApprovalStrength { return upper[op.Method] }
}

// OpenAPIOptions configures FromOpenAPISpec.
type OpenAPIOptions struct {
	OpenAPIHandlerOptions
	// HostCapabilities picks the default host budget among the
	// operations; nil leaves the budget to other options.
	HostCapabilities OperationFilter
	// Strength assigns each capability's approval strength.
	Strength StrengthFunc
	// Location is set on every capability, for an API whose agents call
	// it directly rather than through the execute endpoint.
	Location string
}

// FromOpenAPISpec derives the plugin's options from an OpenAPI 3.x
// document: ProviderName and
// ProviderDescription from its info, the Capabilities, an OnExecute that
// proxies to the upstream API, and, with HostCapabilities, the default
// host budget. Pass them to New before any option that should override
// them:
//
//	opts, err := agentauth.FromOpenAPISpec(spec, agentauth.OpenAPIOptions{...})
//	p := agentauth.New(append(opts, agentauth.Issuer(iss))...)
func FromOpenAPISpec(spec []byte, o OpenAPIOptions) ([]Option, error) {
	d, err := parseOpenAPI(spec)
	if err != nil {
		return nil, err
	}
	exec, err := d.handler(o.OpenAPIHandlerOptions)
	if err != nil {
		return nil, err
	}
	caps := d.capabilities()
	for i, op := range d.ops {
		if o.Strength != nil {
			caps[i].ApprovalStrength = o.Strength(op.info)
		}
		caps[i].Location = o.Location
	}
	var opts []Option
	if d.title != "" {
		opts = append(opts, ProviderName(d.title))
	}
	if d.description != "" {
		opts = append(opts, ProviderDescription(d.description))
	}
	opts = append(opts, Capabilities(caps...), OnExecute(exec))
	if o.HostCapabilities != nil {
		filter := o.HostCapabilities
		infos := make([]OperationInfo, 0, len(d.ops))
		for _, op := range d.ops {
			infos = append(infos, op.info)
		}
		opts = append(opts, DefaultHostCapabilitiesFunc(func(ctx context.Context, hc HostCapabilitiesContext) ([]string, error) {
			names := []string{}
			for _, info := range infos {
				ok, err := filter(ctx, info, hc)
				if err != nil {
					return nil, err
				}
				if ok {
					names = append(names, info.Name)
				}
			}
			return names, nil
		}))
	}
	return opts, nil
}
