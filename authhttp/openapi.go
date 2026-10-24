package authhttp

import (
	"encoding/json"
	"html/template"
	"net/http"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ubgo/auth"
)

// OpenAPIPath is the route OpenAPI adds under the prefix. The document is
// built once, when Handler is built, from the same operation list the routes
// come from, so it can never describe a route that is not served.
//
//ds:def id=authhttp-openapipath-5nq8wk2d owner=@khanakia stability=stable
const OpenAPIPath = "/openapi.json"

// OpenAPIVersion is the specification version the document declares. 3.1 is
// the first whose schemas are plain JSON Schema, which is what a nullable
// pointer field needs (`"type": ["string", "null"]`).
//
//ds:def id=authhttp-openapiversion-7rt3mv9x owner=@khanakia stability=stable
const OpenAPIVersion = "3.1.0"

// Names inside the document that clients and other tools refer to: the two
// security schemes (a request is signed in by the session cookie or by a
// bearer token, never both), the error schema every operation shares, and
// the media types the transport accepts.
const (
	openAPISecurityCookie = "sessionCookie"
	openAPISecurityBearer = "bearerToken"
	openAPIErrorSchema    = "Error"
	openAPIMediaJSON      = "application/json"
	openAPIMediaForm      = "application/x-www-form-urlencoded"
	openAPIAnonymous      = "Anonymous"
	// openAPIStatusOK and openAPIStatusDefault are the two responses every
	// operation has: its output, and the one error shape for every failure.
	openAPIStatusOK      = "200"
	openAPIStatusDefault = "default"
)

// OpenAPIInfo is the part of the document the library cannot know: what the
// app is called, which version this is, and where it is served.
//
//ds:def id=authhttp-openapiinfo-3kx9pz4w owner=@khanakia stability=stable
type OpenAPIInfo struct {
	// Title and Version are required by the specification; empty values are
	// written as empty strings rather than invented.
	Title       string
	Version     string
	Description string
	// Servers are the base URLs the routes are reachable at, without the
	// prefix (the paths carry it). Empty means the document names none, and
	// a client uses the URL it fetched the document from.
	Servers []string
}

// OpenAPI makes Handler serve GET prefix+OpenAPIPath: the OpenAPI 3.1
// document of every operation it serves, with input and output schemas
// derived from the operations' Go types. Opt-in, like Health, so an existing
// route table gains nothing it did not ask for; the document is public,
// because it describes routes a client can discover by calling them anyway
// and holds no deployment value.
//
//ds:def id=authhttp-openapi-8wq2nr5t owner=@khanakia stability=stable
func OpenAPI(info OpenAPIInfo) Option { return func(c *config) { c.openapi = &info } }

// ReferencePath is the route Reference adds under the prefix: a page that
// renders the OpenAPI document as an interactive API reference.
//
//ds:def id=authhttp-referencepath-3nk8wq5m owner=@khanakia stability=stable
const ReferencePath = "/reference"

// DefaultReferenceScript is the viewer the reference page loads when
// ReferenceOptions.ScriptURL is empty: Scalar's standalone bundle from
// jsDelivr, pinned to one release so the page does not change under an app
// that never asked it to. An app that will not load scripts from a third
// party serves the bundle itself and names its URL.
//
//ds:def id=authhttp-defaultreferencescript-9vt2px6r owner=@khanakia stability=stable
const DefaultReferenceScript = "https://cdn.jsdelivr.net/npm/@scalar/api-reference@1.72.4/dist/browser/standalone.js"

// defaultReferenceTitle is the page title when OpenAPIInfo has none.
const defaultReferenceTitle = "API reference"

// ReferenceOptions configures the page Reference serves.
//
//ds:def id=authhttp-referenceoptions-5wq8mn2k owner=@khanakia stability=stable
type ReferenceOptions struct {
	// ScriptURL is the viewer script; empty means DefaultReferenceScript.
	ScriptURL string
	// Nonce, when set, is called per request and its answer becomes the
	// nonce attribute of both script tags, for an app whose
	// Content-Security-Policy allows scripts by nonce. The app's own
	// middleware sets the policy header; the page only carries the nonce.
	Nonce func(r *http.Request) string
	// Theme is the viewer's colour theme; empty keeps the viewer's own
	// default. Reference panics at start-up on a value outside
	// ReferenceThemeValues, as it does for every misconfiguration it can see.
	Theme ReferenceTheme
}

// ReferenceTheme is one of the viewer's (Scalar's) named themes.
type ReferenceTheme string

// The themes the default viewer ships.
//
//ds:def id=authhttp-referencethemes-6tq2nw8k owner=@khanakia stability=stable
const (
	ThemeDefault    ReferenceTheme = "default"
	ThemeAlternate  ReferenceTheme = "alternate"
	ThemeMoon       ReferenceTheme = "moon"
	ThemePurple     ReferenceTheme = "purple"
	ThemeSolarized  ReferenceTheme = "solarized"
	ThemeBluePlanet ReferenceTheme = "bluePlanet"
	ThemeSaturn     ReferenceTheme = "saturn"
	ThemeKepler     ReferenceTheme = "kepler"
	ThemeMars       ReferenceTheme = "mars"
	ThemeDeepSpace  ReferenceTheme = "deepSpace"
	ThemeLaserwave  ReferenceTheme = "laserwave"
	// ThemeNone loads no theme stylesheet, for a page the app styles.
	ThemeNone ReferenceTheme = "none"
)

// ReferenceThemeValues is every ReferenceTheme, for validation and docs.
var ReferenceThemeValues = []ReferenceTheme{
	ThemeDefault, ThemeAlternate, ThemeMoon, ThemePurple, ThemeSolarized, ThemeBluePlanet,
	ThemeSaturn, ThemeKepler, ThemeMars, ThemeDeepSpace, ThemeLaserwave, ThemeNone,
}

// Reference makes Handler serve GET prefix+ReferencePath: an HTML page that
// loads an OpenAPI viewer and points it at the document OpenAPI serves, so
// the routes an app wired can be browsed and tried from a browser. It needs
// OpenAPI, and Handler panics at start-up without it, because a page that
// renders a document nobody serves is a misconfiguration, not a runtime
// case. Opt-in, like OpenAPI: it is a development convenience, and it loads
// a script from a third party by default (DefaultReferenceScript), which an
// app decides for itself; the page itself holds nothing but two script tags.
//
//ds:def id=authhttp-reference-2kx7mv9q owner=@khanakia stability=stable
func Reference(opts ReferenceOptions) Option {
	if opts.Theme != "" && !slices.Contains(ReferenceThemeValues, opts.Theme) {
		panic("authhttp: Reference: " + strconv.Quote(string(opts.Theme)) + " is not a ReferenceTheme")
	}
	return func(c *config) { c.reference = &opts }
}

// referencePage is the whole page: the viewer reads the document URL from the
// first script tag's data attribute (Scalar's documented embedding). The
// values are attribute-escaped by html/template, so a prefix or a nonce with
// a quote cannot break out of the attribute.
var referencePage = template.Must(template.New("reference").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{{.Title}}</title></head>
<body><script id="api-reference" data-url="{{.DocumentURL}}"{{if .Configuration}} data-configuration="{{.Configuration}}"{{end}}{{if .Nonce}} nonce="{{.Nonce}}"{{end}}></script><script src="{{.ScriptURL}}"{{if .Nonce}} nonce="{{.Nonce}}"{{end}}></script></body></html>
`))

// referenceData fills referencePage.
type referenceData struct {
	Title       string
	DocumentURL string
	ScriptURL   string
	Nonce       string
	// Configuration is the viewer's data-configuration JSON, or "".
	Configuration string
}

// serveReference renders the page per request, because the nonce may differ
// per request; everything else is fixed at Handler time.
func serveReference(cfg config) http.Handler {
	script := cfg.reference.ScriptURL
	if script == "" {
		script = DefaultReferenceScript
	}
	title := cfg.openapi.Title
	if title == "" {
		title = defaultReferenceTitle
	}
	configuration := ""
	if cfg.reference.Theme != "" {
		// A theme is one of a fixed set of plain words, so the JSON is
		// built from it directly; html/template escapes the attribute.
		configuration = `{"theme":"` + string(cfg.reference.Theme) + `"}`
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := referenceData{Title: title, DocumentURL: cfg.prefix + OpenAPIPath, ScriptURL: script, Configuration: configuration}
		if cfg.reference.Nonce != nil {
			data.Nonce = cfg.reference.Nonce(r)
		}
		w.Header().Set(headerContentType, contentTypeHTML)
		_ = referencePage.Execute(w, data) // a fixed template over strings cannot fail to render; a client that hung up cannot be told
	})
}

// OpenAPIDocument is the document OpenAPI serves, for a generator that writes
// it to a file and checks the committed copy (task docs:api). It takes the
// same options as Handler so the prefix, AcceptForms and Health in the
// document match the routes. It cannot fail: the document is nested maps of
// strings, numbers and booleans, which encoding/json always encodes.
//
//ds:def id=authhttp-openapidocument-2hn6ty8v owner=@khanakia stability=stable
func OpenAPIDocument(a *auth.Auth, info OpenAPIInfo, opts ...Option) []byte {
	return marshalOpenAPI(buildOpenAPI(a, info, newConfig(opts)))
}

// marshalOpenAPI renders the document, indented so a committed copy diffs
// line by line.
func marshalOpenAPI(doc openAPIDoc) []byte {
	b, _ := json.MarshalIndent(doc, "", "  ") // nested maps of JSON scalars cannot fail to encode
	return b
}

// serveOpenAPI answers the document built once at Handler time.
func serveOpenAPI(doc []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(headerContentType, contentTypeJSON)
		_, _ = w.Write(doc) // a client that hung up cannot be told
	})
}

// openAPIDoc is the document, built as nested maps so encoding/json writes
// every object's keys sorted and two builds of one Auth are byte-identical,
// which is what a drift check needs. The ordered parts (required fields,
// enum values) are slices.
type openAPIDoc = map[string]any

// openAPIBuilder accumulates component schemas while it walks the operations.
type openAPIBuilder struct {
	schemas map[string]any
	// building names the schemas whose fields are being walked, so a type
	// that refers to itself gets a $ref instead of infinite recursion.
	building map[string]bool
}

func buildOpenAPI(a *auth.Auth, info OpenAPIInfo, cfg config) openAPIDoc {
	b := &openAPIBuilder{schemas: map[string]any{}, building: map[string]bool{}}
	b.schemas[openAPIErrorSchema] = openAPIDoc{
		"type":        "object",
		"description": "Every failure, whatever the status: a stable code to match on and a message for people.",
		"required":    []string{"error"},
		"properties": openAPIDoc{"error": openAPIDoc{
			"type":     "object",
			"required": []string{"code", "message"},
			"properties": openAPIDoc{
				"code":    openAPIDoc{"type": "string"},
				"message": openAPIDoc{"type": "string"},
			},
		}},
	}
	paths := openAPIDoc{}
	tags := map[string]bool{}
	for _, op := range a.Operations() {
		opInfo := op.Info()
		path := cfg.prefix + op.Route()
		item, _ := paths[path].(openAPIDoc)
		if item == nil {
			item = openAPIDoc{}
			paths[path] = item
		}
		tags[op.Plugin()] = true
		item[strings.ToLower(MethodOf(opInfo.Kind))] = b.operation(op, cfg)
	}
	if cfg.health {
		paths[cfg.prefix+HealthPath] = openAPIDoc{"get": openAPIDoc{
			"operationId": "health",
			"summary":     "Liveness: the routes are mounted and the process answers. Reads no database.",
			"tags":        []string{auth.CorePluginName},
			"responses": openAPIDoc{openAPIStatusOK: openAPIDoc{
				"description": "OK",
				"content":     openAPIDoc{openAPIMediaJSON: openAPIDoc{"schema": b.schemaOf(reflect.TypeFor[healthBody]())}},
			}},
		}}
		tags[auth.CorePluginName] = true
	}
	tagList := make([]any, 0, len(tags))
	for _, name := range sortedKeys(tags) {
		tagList = append(tagList, openAPIDoc{"name": name})
	}
	doc := openAPIDoc{
		"openapi": OpenAPIVersion,
		"info":    openAPIDoc{"title": info.Title, "version": info.Version, "description": info.Description},
		"tags":    tagList,
		"paths":   paths,
		"components": openAPIDoc{
			"schemas": b.schemas,
			"securitySchemes": openAPIDoc{
				openAPISecurityCookie: openAPIDoc{"type": "apiKey", "in": "cookie", "name": cfg.sessionCookieName(),
					"description": "The session cookie a browser receives at sign-in. A mutation sent with it must carry a trusted Origin header."},
				openAPISecurityBearer: openAPIDoc{"type": "http", "scheme": "bearer",
					"description": "A session token received with `" + TokenModeHeader + ": " + TokenModeBearer + "`, or an API key."},
			},
		},
	}
	if len(info.Servers) > 0 {
		servers := make([]any, 0, len(info.Servers))
		for _, s := range info.Servers {
			servers = append(servers, openAPIDoc{"url": s})
		}
		doc["servers"] = servers
	}
	return doc
}

// operation describes one route: the requirement as security, a Query's
// input as query parameters, a Mutation's as a request body, and the output
// and error responses.
func (b *openAPIBuilder) operation(op auth.Operation, cfg config) openAPIDoc {
	info := op.Info()
	inT, outT := op.InputType(), op.OutputType()
	o := openAPIDoc{
		"operationId": string(info.ID),
		"tags":        []string{op.Plugin()},
		"summary":     string(info.ID) + " (" + string(info.Require) + ")",
		"description": requirementText(info.Require),
		"responses": openAPIDoc{
			openAPIStatusOK: openAPIDoc{
				"description": "OK",
				"content":     openAPIDoc{openAPIMediaJSON: openAPIDoc{"schema": b.schemaOf(outT)}},
			},
			openAPIStatusDefault: openAPIDoc{
				"description": "Refused or failed; the status is the code's own.",
				"content":     openAPIDoc{openAPIMediaJSON: openAPIDoc{"schema": openAPIDoc{"$ref": "#/components/schemas/" + openAPIErrorSchema}}},
			},
		},
	}
	if info.Require != auth.Public {
		o["security"] = []any{openAPIDoc{openAPISecurityCookie: []string{}}, openAPIDoc{openAPISecurityBearer: []string{}}}
	}
	if info.Kind == auth.Query {
		if params := b.queryParameters(inT); len(params) > 0 {
			o["parameters"] = params
		}
		return o
	}
	content := openAPIDoc{openAPIMediaJSON: openAPIDoc{"schema": b.schemaOf(inT)}}
	if cfg.forms || info.CrossSiteForm {
		content[openAPIMediaForm] = openAPIDoc{"schema": b.schemaOf(inT)}
	}
	o["requestBody"] = openAPIDoc{"required": false, "content": content}
	return o
}

// requirementText words a requirement for the description, so a reader of
// the document learns what the request must carry before the operation runs.
func requirementText(r auth.Requirement) string {
	switch r {
	case auth.Public:
		return "Runs for anyone, signed in or not."
	case auth.SignedIn:
		return "Needs a valid session (cookie or bearer token). While the session has tasks pending (GET /session lists them), only the operations those tasks allow run; any other answers 403 auth.session_task_pending."
	case auth.FreshSignIn:
		return "Needs a session created or re-authenticated (password.reauthenticate, passkey.reauthenticate-finish) within the fresh window; otherwise 403 auth.fresh_session_required."
	case auth.PendingSecondFactor:
		return "Needs a session waiting for its second factor; to every other operation that session is signed out."
	}
	return string(r)
}

// queryParameters turns a Query's input struct into one query parameter per
// field. A Query's input is decoded from flat string values, so every field
// is described as a string whatever its Go type, which is what the decoder
// accepts.
func (b *openAPIBuilder) queryParameters(t reflect.Type) []any {
	var params []any
	for _, f := range jsonFields(t) {
		params = append(params, openAPIDoc{
			"name":     f.name,
			"in":       "query",
			"required": !f.optional,
			"schema":   openAPIDoc{"type": "string"},
		})
	}
	return params
}

// jsonField is one serialised field of a struct: its wire name, whether
// omitempty or omitzero marks it optional, whether the `,string` option quotes its value,
// and its type.
//
// optional is the one signal of requiredness for a body and a query alike:
// the decoders refuse no missing key (an absent key is the zero value), so
// an input type declares a field the caller may leave out with omitempty,
// or with omitzero where an empty value means something a missing one does
// not (a nil scope list takes the defaults, an empty one grants none), and a
// generated schema or TypeScript type reads that declaration.
type jsonField struct {
	name     string
	optional bool
	quoted   bool
	typ      reflect.Type
}

// jsonFields lists the fields encoding/json would write for t, in order,
// with embedded structs flattened the way the encoder flattens them,
// including its rule for a name two fields share: the shallowest wins, a tie
// goes to the one field with a json tag, and any other tie drops the name.
// A nil or non-struct type has none.
func jsonFields(t reflect.Type) []jsonField {
	if t == nil {
		return nil
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	var all []candidateField
	collectFields(t, 0, map[reflect.Type]bool{}, &all)
	byName := map[string][]candidateField{}
	var order []string
	for _, c := range all {
		if _, seen := byName[c.name]; !seen {
			order = append(order, c.name)
		}
		byName[c.name] = append(byName[c.name], c)
	}
	var out []jsonField
	for _, name := range order {
		if f, ok := dominant(byName[name]); ok {
			out = append(out, f)
		}
	}
	return out
}

// candidateField is a field that may be written, before name conflicts are
// settled: its depth of embedding and whether its tag named it.
type candidateField struct {
	jsonField
	depth  int
	tagged bool
}

// collectFields appends t's candidate fields in declaration order, walking
// into embedded structs; seen stops a type embedded in itself.
func collectFields(t reflect.Type, depth int, seen map[reflect.Type]bool, out *[]candidateField) {
	if seen[t] {
		return
	}
	seen[t] = true
	defer delete(seen, t)
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		if f.Anonymous {
			ft := f.Type
			if ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if name == "" && ft.Kind() == reflect.Struct {
				// Flattened, exported or not: its exported fields are
				// promoted.
				collectFields(ft, depth+1, seen, out)
				continue
			}
			if !f.IsExported() {
				continue
			}
		} else if !f.IsExported() {
			continue
		}
		tagged := name != ""
		if !tagged {
			name = f.Name
		}
		*out = append(*out, candidateField{
			jsonField: jsonField{name: name, optional: hasOption(opts, "omitempty") || hasOption(opts, "omitzero"), quoted: hasOption(opts, "string") && quotable(f.Type), typ: f.Type},
			depth:     depth,
			tagged:    tagged,
		})
	}
}

// dominant is encoding/json's choice among fields sharing a name: the
// shallowest, and among the shallowest the only tagged one; no field when
// that leaves more than one.
func dominant(fs []candidateField) (jsonField, bool) {
	min := fs[0].depth
	for _, f := range fs {
		if f.depth < min {
			min = f.depth
		}
	}
	var top []candidateField
	for _, f := range fs {
		if f.depth == min {
			top = append(top, f)
		}
	}
	if len(top) == 1 {
		return top[0].jsonField, true
	}
	var tagged []candidateField
	for _, f := range top {
		if f.tagged {
			tagged = append(tagged, f)
		}
	}
	if len(tagged) == 1 {
		return tagged[0].jsonField, true
	}
	return jsonField{}, false
}

// hasOption reports whether a json tag's option list (after the name) holds
// opt.
func hasOption(opts, opt string) bool { return strings.Contains(","+opts+",", ","+opt+",") }

// quotable reports whether encoding/json applies the `,string` option to a
// field of type t: strings, numbers and booleans, through one pointer. On any
// other kind the option is ignored.
func quotable(t reflect.Type) bool {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.String, reflect.Bool, reflect.Float32, reflect.Float64,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return true
	}
	return false
}

// Reflect types the schema derivation treats specially: time.Time encodes as
// RFC 3339 text, and any other type with its own MarshalJSON (json.RawMessage
// among them) writes whatever it decides, so its fields say nothing about
// its JSON.
var (
	timeType      = reflect.TypeFor[time.Time]()
	jsonMarshaler = reflect.TypeFor[json.Marshaler]()
)

// customJSON reports whether t's fields or elements do not describe its
// JSON: it or its pointer implements json.Marshaler, it is not time.Time,
// and it is a struct, map, slice or array. A string, number or boolean type
// with its own MarshalJSON (auth.Token, which writes "[redacted]") still
// decodes as its kind, and that is what an input of it takes.
func customJSON(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Struct, reflect.Map, reflect.Slice, reflect.Array:
	default:
		return false
	}
	return t != timeType && (t.Implements(jsonMarshaler) || reflect.PointerTo(t).Implements(jsonMarshaler))
}

// fieldSchema is the schema of one struct field: a `,string` field is a
// JSON string whatever its Go type, because that is what the encoder writes
// and the decoder reads.
func (b *openAPIBuilder) fieldSchema(f jsonField) openAPIDoc {
	if f.quoted {
		s := openAPIDoc{"type": "string"}
		if f.typ.Kind() == reflect.Pointer {
			return nullable(s)
		}
		return s
	}
	return b.schemaOf(f.typ)
}

// schemaOf is the JSON Schema of t. Named structs become components, named
// by package and type ("password.SignInRequest") so two plugins' SignInRequest
// never collide, and are referred to by $ref; everything else is inline.
func (b *openAPIBuilder) schemaOf(t reflect.Type) openAPIDoc {
	if t == nil {
		return openAPIDoc{"type": "object"}
	}
	if customJSON(t) {
		// Its fields do not describe its JSON: any JSON.
		return openAPIDoc{}
	}
	switch t.Kind() {
	case reflect.Pointer:
		return nullable(b.schemaOf(t.Elem()))
	case reflect.Bool:
		return openAPIDoc{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return openAPIDoc{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return openAPIDoc{"type": "number"}
	case reflect.String:
		return openAPIDoc{"type": "string"}
	case reflect.Slice, reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 {
			// encoding/json writes a byte slice as base64 text.
			return openAPIDoc{"type": "string", "contentEncoding": "base64"}
		}
		return openAPIDoc{"type": "array", "items": b.schemaOf(t.Elem())}
	case reflect.Map:
		return openAPIDoc{"type": "object", "additionalProperties": b.schemaOf(t.Elem())}
	case reflect.Struct:
		if t == timeType {
			return openAPIDoc{"type": "string", "format": "date-time"}
		}
		return b.structSchema(t)
	}
	// Interfaces, json.RawMessage's underlying kinds and anything else the
	// encoder writes as whatever the value is: any JSON.
	return openAPIDoc{}
}

// structSchema registers a named struct as a component and returns a $ref to
// it, or returns an anonymous struct inline.
func (b *openAPIBuilder) structSchema(t reflect.Type) openAPIDoc {
	name := componentName(t)
	if name == openAPIAnonymous {
		return b.objectSchema(t)
	}
	ref := openAPIDoc{"$ref": "#/components/schemas/" + name}
	if _, done := b.schemas[name]; done || b.building[name] {
		return ref
	}
	b.building[name] = true
	b.schemas[name] = b.objectSchema(t)
	delete(b.building, name)
	return ref
}

// objectSchema is the object schema of a struct's JSON fields.
func (b *openAPIBuilder) objectSchema(t reflect.Type) openAPIDoc {
	props := openAPIDoc{}
	required := []string{}
	for _, f := range jsonFields(t) {
		props[f.name] = b.fieldSchema(f)
		if !f.optional {
			required = append(required, f.name)
		}
	}
	s := openAPIDoc{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

// componentName is "<package>.<Type>" for a named struct type, so the
// password plugin's SignInRequest and the phone plugin's never share a name,
// or openAPIAnonymous for a struct literal.
func componentName(t reflect.Type) string {
	if t.Name() == "" {
		return openAPIAnonymous
	}
	pkg := t.PkgPath()
	if i := strings.LastIndex(pkg, "/"); i >= 0 {
		pkg = pkg[i+1:]
	}
	if pkg == "" {
		return t.Name()
	}
	return pkg + "." + t.Name()
}

// nullable marks a schema as also accepting null, the way a Go pointer field
// encodes a nil: a $ref cannot take a type list, so it becomes a oneOf.
func nullable(s openAPIDoc) openAPIDoc {
	if _, isRef := s["$ref"]; isRef {
		return openAPIDoc{"oneOf": []any{s, openAPIDoc{"type": "null"}}}
	}
	if t, ok := s["type"].(string); ok {
		s["type"] = []string{t, "null"}
	}
	return s
}

// sortedKeys is the keys of m in order, for the parts of the document that
// are lists rather than objects.
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
