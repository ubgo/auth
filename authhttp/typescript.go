package authhttp

import (
	_ "embed" // the hand-written TypeScript runtime ships inside the generator
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/ubgo/auth"
)

// The files TypeScriptClient writes, by name. They import each other by these
// names, so a client is the five files in one directory.
//
//ds:def id=authhttp-tsfiles-6qm2xw8k owner=@khanakia stability=stable
const (
	// TSFileClient is the generated part: one TypeScript type per Go input
	// and output type, one operation table and plugin factory per plugin,
	// and createAuthClient typed with the core's operations.
	TSFileClient = "client.ts"
	// TSFileRuntime is the hand-written fetch runtime, the same for every
	// app: request encoding, token modes, error decoding.
	TSFileRuntime = "runtime.ts"
	// TSFileErrorCodes is every error code the linked packages declare
	// (auth.Errors), the same module docs/reference/error-codes.ts is.
	TSFileErrorCodes = "error-codes.ts"
	// TSFileExtensions is the hand-written plugins that are not one
	// request each, the same for every app: oauthPopup() (the popup
	// sign-in of plugin/oauthproxy/oauthpopup) and lastLoginMethod().
	TSFileExtensions = "extensions.ts"
	// TSFileIndex re-exports the four, the module an app imports.
	TSFileIndex = "index.ts"
)

// tsRuntime is TSFileRuntime. It lives beside the generator, not in the
// prebuilt package, so the app-exact client (`auth client ts`) and the
// prebuilt one ship the same bytes from one source.
//
//go:embed tsclient/runtime.ts
var tsRuntime []byte

// tsExtensions is TSFileExtensions, embedded for the same reason.
//
//go:embed tsclient/extensions.ts
var tsExtensions []byte

// tsIndex is TSFileIndex: fixed, because the four modules it re-exports
// export distinct names (TypeScriptClient refuses a plugin or type name that
// would collide with a runtime or extension export).
const tsIndex = tsGeneratedHeader + `export * from "./client.ts";
export * from "./runtime.ts";
export * from "./error-codes.ts";
export * from "./extensions.ts";
`

// tsGeneratedHeader opens every generated file, so nobody edits one by hand.
const tsGeneratedHeader = "// Generated from the operation list of github.com/ubgo/auth (authhttp.TypeScriptClient). Do not edit.\n\n"

// tsEmpty is the runtime's type of an input with no fields: only {} fits,
// and the method's input argument becomes optional.
const tsEmpty = "EmptyInput"

// tsEndsSession are the operations after which a bearer client forgets its
// token. The server answers a bearer sign-out with no header (a bearer
// client "discards its own token", see applyEffects), so the client must
// know which operations end the session it holds.
var tsEndsSession = map[auth.EndpointID]bool{auth.EndpointSignOut: true, auth.EndpointSignOutAll: true}

// tsInputFills maps an input's JSON field to where the client fills it from
// when a call leaves it out (the runtime's InputFill). oauth_query is the
// signed query plugin/oauthprovider hands its consent and login pages, which
// every operation those pages call posts back (consent, continue,
// public-client-prelogin): a page passes nothing and the client sends its own
// location.search.
var tsInputFills = map[string]string{"oauth_query": "oauthQuery"}

// tsExport finds the names a TypeScript module exports at the top level.
var tsExport = regexp.MustCompile(`(?m)^export (?:async )?(?:function|type|interface|const|class) ([A-Za-z_$][A-Za-z0-9_$]*)`)

// tsFixedExports are the names client.ts exports whatever the plugins:
// createAuthClient and the core's table.
var tsFixedExports = []string{"createAuthClient", "CoreOps", "coreOps"}

// tsTakenNames maps every name runtime.ts, extensions.ts, error-codes.ts and
// the fixed part of client.ts export to where it comes from. A generated name equal to one
// would make index.ts's re-exports ambiguous, so TypeScriptClient refuses
// it. Read from the modules themselves, so a new runtime export is covered
// without a list to update.
func tsTakenNames(errorCodes []byte) map[string]string {
	taken := map[string]string{}
	for _, m := range tsExport.FindAllSubmatch(tsRuntime, -1) {
		taken[string(m[1])] = TSFileRuntime
	}
	for _, m := range tsExport.FindAllSubmatch(tsExtensions, -1) {
		taken[string(m[1])] = TSFileExtensions
	}
	for _, m := range tsExport.FindAllSubmatch(errorCodes, -1) {
		taken[string(m[1])] = TSFileErrorCodes
	}
	for _, n := range tsFixedExports {
		taken[n] = TSFileClient
	}
	return taken
}

// tsReserved are the words TypeScript does not allow as a function name, so
// a plugin named one cannot have a factory.
var tsReserved = map[string]bool{
	"break": true, "case": true, "catch": true, "class": true, "const": true, "continue": true, "debugger": true,
	"default": true, "delete": true, "do": true, "else": true, "enum": true, "export": true, "extends": true,
	"false": true, "finally": true, "for": true, "function": true, "if": true, "import": true, "in": true,
	"instanceof": true, "new": true, "null": true, "return": true, "super": true, "switch": true, "this": true,
	"throw": true, "true": true, "try": true, "typeof": true, "var": true, "void": true, "while": true, "with": true,
	"let": true, "static": true, "yield": true, "await": true, "implements": true, "interface": true,
	"package": true, "private": true, "protected": true, "public": true,
}

// ErrTypeScriptName is returned by TypeScriptClient when two things would
// get one TypeScript name: two operations of a plugin whose ids differ only
// in punctuation, two Go types whose package and name concatenate alike, a
// plugin named after a TypeScript keyword or a runtime export. The message
// names both, so the plugin can be renamed.
var ErrTypeScriptName = errors.New("authhttp: TypeScript name collision")

// TypeScriptClient writes a typed TypeScript client for every operation a
// serves, from the same operation list Handler and OpenAPIDocument read, so
// the client can never call a route that is not served or miss one that is.
// The answer maps a file name (TSFileClient, TSFileRuntime,
// TSFileErrorCodes, TSFileExtensions, TSFileIndex) to its contents; the
// five go in one directory.
//
// Each plugin becomes a factory (password(), twofactor()) whose operation
// table carries the input and output types; createAuthClient({plugins})
// types the client as the core's methods plus one namespace per plugin it
// was given, so calling a plugin that was not enabled is a compile error.
// Paths are the routes without a mount prefix: the client's baseURL carries
// it ("https://app.example.com/auth"), so one client serves any mount.
//
// The types follow what encoding/json writes and the decoders read: a field
// without omitempty is required, a pointer, slice or map may be null, a
// `,string` field is a string, and a type with its own MarshalJSON is
// unknown. Run against an app's own *auth.Auth (authcli's `auth client ts`),
// it types that app's custom plugins and their error codes exactly.
//
//ds:def id=authhttp-typescriptclient-4vn8kq2r owner=@khanakia stability=stable
func TypeScriptClient(a *auth.Auth) (map[string][]byte, error) {
	b, byPlugin, err := tsCollect(a)
	if err != nil {
		return nil, err
	}
	codes := TypeScriptErrorCodes()
	client, err := renderTSClient(b, byPlugin, tsTakenNames(codes))
	if err != nil {
		return nil, err
	}
	return map[string][]byte{
		TSFileClient:     client,
		TSFileRuntime:    tsRuntime,
		TSFileErrorCodes: codes,
		TSFileExtensions: tsExtensions,
		TSFileIndex:      []byte(tsIndex),
	}, nil
}

// TSMethod is one method of the client TypeScriptClient writes, for a
// reference page or a tool that lists the client's surface without parsing
// TypeScript (apiref writes docs/reference/ts-client.md from it).
type TSMethod struct {
	// Namespace is where the method sits: "" for the core's methods on the
	// client's root, otherwise the plugin's factory and namespace name
	// (password() and client.password).
	Namespace string
	// Plugin is the plugin that registered the operation, as auth names it
	// (auth.CorePluginName for the core's).
	Plugin string
	// Name is the method's name: the operation id after the plugin's
	// prefix, in camelCase ("organization.invite-member" is inviteMember).
	Name string
	// ID is the operation it calls.
	ID auth.EndpointID
	// HTTPMethod and Path are the route, Path without a mount prefix.
	HTTPMethod, Path string
	// Require is what the call must carry before the operation runs.
	Require auth.Requirement
	// Input and Output are the TypeScript types of the method's argument and
	// of its result's data (EmptyInput when the operation takes no fields).
	Input, Output string
}

// TypeScriptMethods lists the methods of the client TypeScriptClient writes
// for a, sorted by namespace (the core's first) and then by name. It fails
// exactly when TypeScriptClient does, so a listed method always exists.
//
//ds:def id=authhttp-typescriptmethods-7hq4mz2c owner=@khanakia stability=stable
func TypeScriptMethods(a *auth.Auth) ([]TSMethod, error) {
	b, byPlugin, err := tsCollect(a)
	if err != nil {
		return nil, err
	}
	// Render once for its refusals (keywords, names taken by the runtime);
	// it also sorts each plugin's operations by method name.
	if _, err := renderTSClient(b, byPlugin, tsTakenNames(TypeScriptErrorCodes())); err != nil {
		return nil, err
	}
	plugins := make([]string, 0, len(byPlugin))
	for p := range byPlugin {
		plugins = append(plugins, p)
	}
	sort.Slice(plugins, func(i, j int) bool {
		// The core first: its methods are the client's root.
		if (plugins[i] == auth.CorePluginName) != (plugins[j] == auth.CorePluginName) {
			return plugins[i] == auth.CorePluginName
		}
		return plugins[i] < plugins[j]
	})
	var out []TSMethod
	for _, p := range plugins {
		ns := ""
		if p != auth.CorePluginName {
			ns = tsCamel(p)
		}
		for _, op := range byPlugin[p] {
			out = append(out, TSMethod{
				Namespace: ns, Plugin: p, Name: op.name, ID: auth.EndpointID(op.id),
				HTTPMethod: op.method, Path: op.path, Require: auth.Requirement(op.require), Input: op.in, Output: op.out,
			})
		}
	}
	return out, nil
}

// tsCollect walks a's operations once: the TypeScript types of every input
// and output, and the operations grouped by plugin.
func tsCollect(a *auth.Auth) (*tsBuilder, map[string][]tsOp, error) {
	b := &tsBuilder{decls: map[string]string{}, owners: map[string]reflect.Type{}}
	byPlugin := map[string][]tsOp{}
	// methodIDs maps "<plugin> <method>" to the operation that took it, so
	// two ids that differ only in punctuation are refused.
	methodIDs := map[string]auth.EndpointID{}
	for _, op := range a.Operations() {
		info := op.Info()
		plugin := op.Plugin()
		name := tsCamel(strings.TrimPrefix(string(info.ID), plugin+"."))
		if prev, ok := methodIDs[plugin+" "+name]; ok {
			return nil, nil, fmt.Errorf("%w: operations %s and %s are both %s", ErrTypeScriptName, prev, info.ID, name)
		}
		methodIDs[plugin+" "+name] = info.ID
		fills := tsFillsOf(op.InputType())
		in := b.typeOf(op.InputType())
		if len(fills) > 0 {
			in = "Fill<" + in + ", " + tsFillKeys(fills) + ">"
		}
		byPlugin[plugin] = append(byPlugin[plugin], tsOp{
			name: name, id: string(info.ID), method: MethodOf(info.Kind), path: op.Route(),
			require: string(info.Require), in: in, out: b.typeOf(op.OutputType()),
			endsSession: tsEndsSession[info.ID],
			// A second factor's promotion finishes a sign-in another
			// operation started and named, as plugin/lastlogin records it.
			signIn: info.SignIn && info.Require != auth.PendingSecondFactor,
			fills:  fills,
		})
	}
	if b.err != nil {
		return nil, nil, b.err
	}
	return b, byPlugin, nil
}

// tsOp is one operation as the client sees it.
type tsOp struct {
	name, id, method, path, require string
	in, out                         string
	endsSession, signIn             bool
	// fills are the input's fields the client fills (tsInputFills), sorted.
	fills []string
}

// tsFillsOf lists the top-level string fields of an input struct that the
// client fills (tsInputFills), sorted by name.
func tsFillsOf(t reflect.Type) []string {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil || t.Kind() != reflect.Struct || customJSON(t) {
		return nil
	}
	var out []string
	for _, f := range jsonFields(t) {
		if _, ok := tsInputFills[f.name]; ok && f.typ.Kind() == reflect.String {
			out = append(out, f.name)
		}
	}
	sort.Strings(out)
	return out
}

// tsFillKeys is the union of field names Fill makes optional.
func tsFillKeys(fills []string) string {
	keys := make([]string, len(fills))
	for i, f := range fills {
		keys[i] = tsString(f)
	}
	return strings.Join(keys, " | ")
}

// tsBuilder accumulates one declaration per named Go struct while the
// operations' types are walked.
type tsBuilder struct {
	// decls maps a TypeScript type name to its declaration.
	decls map[string]string
	// owners maps a TypeScript type name to the Go type it declares, so two
	// Go types that would share a name are refused rather than merged.
	owners map[string]reflect.Type
	err    error
}

// typeOf is the TypeScript type of t's JSON. Named structs become exported
// interfaces, referred to by name; everything else is inline.
func (b *tsBuilder) typeOf(t reflect.Type) string {
	if t == nil {
		return tsEmpty
	}
	if customJSON(t) {
		return "unknown"
	}
	switch t.Kind() {
	case reflect.Pointer:
		return tsNullable(b.typeOf(t.Elem()))
	case reflect.Bool:
		return "boolean"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return "number"
	case reflect.String:
		return "string"
	case reflect.Slice:
		// A nil slice encodes as null, and Go code returns nil slices.
		if t.Elem().Kind() == reflect.Uint8 {
			return "string | null" // base64 text
		}
		return tsArray(b.typeOf(t.Elem())) + " | null"
	case reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 {
			return "string"
		}
		return tsArray(b.typeOf(t.Elem()))
	case reflect.Map:
		// A nil map encodes as null; keys are always strings in JSON.
		return "{ [key: string]: " + b.typeOf(t.Elem()) + " } | null"
	case reflect.Struct:
		if t == timeType {
			return "string" // RFC 3339
		}
		return b.structType(t)
	}
	// Interfaces, and kinds encoding/json cannot write: any JSON.
	return "unknown"
}

// structType declares a named struct once and returns its name, or returns
// an anonymous struct inline.
func (b *tsBuilder) structType(t reflect.Type) string {
	if t.Name() == "" {
		return b.objectType(t, false)
	}
	name := tsTypeName(t)
	if owner, ok := b.owners[name]; ok {
		if owner != t && b.err == nil {
			b.err = fmt.Errorf("%w: %s and %s are both %s", ErrTypeScriptName, owner, t, name)
		}
		return name
	}
	b.owners[name] = t // before the fields, so a type that refers to itself terminates
	if body := b.objectType(t, true); body == tsEmpty {
		b.decls[name] = "export type " + name + " = " + tsEmpty + ";\n"
	} else {
		b.decls[name] = "export interface " + name + " " + body + "\n"
	}
	return name
}

// objectType is the object type of a struct's JSON fields: one field per
// line for a declaration, one line for an anonymous struct written inline.
// An empty struct is EmptyInput, which accepts only {}.
func (b *tsBuilder) objectType(t reflect.Type, multiline bool) string {
	fields := jsonFields(t)
	if len(fields) == 0 {
		return tsEmpty
	}
	members := make([]string, 0, len(fields))
	for _, f := range fields {
		typ := ""
		if f.quoted {
			typ = "string"
			if f.typ.Kind() == reflect.Pointer {
				typ = tsNullable(typ)
			}
		} else {
			typ = b.typeOf(f.typ)
		}
		opt := ""
		if f.optional {
			opt = "?"
		}
		members = append(members, tsPropName(f.name)+opt+": "+typ+";")
	}
	if !multiline {
		return "{ " + strings.Join(members, " ") + " }"
	}
	return "{\n  " + strings.Join(members, "\n  ") + "\n}"
}

// tsNullable adds null to a type once.
func tsNullable(t string) string {
	if strings.HasSuffix(t, " | null") || t == "unknown" {
		return t
	}
	return t + " | null"
}

// tsArray is an array of elem, parenthesised when elem is a union.
func tsArray(elem string) string {
	if strings.Contains(elem, "|") {
		return "(" + elem + ")[]"
	}
	return elem + "[]"
}

// tsTypeName is the TypeScript name of a named Go type: its package and its
// name in PascalCase ("password.SignInRequest" → PasswordSignInRequest), so
// two plugins' SignInRequest never collide. A generic type's arguments are
// dropped to letters and digits.
func tsTypeName(t reflect.Type) string {
	return tsPascal(componentName(t))
}

// tsWord splits identifiers on anything that is not a letter or a digit.
var tsWord = regexp.MustCompile(`[^A-Za-z0-9]+`)

// tsPascal joins the words of s, each with its first letter upper-cased.
func tsPascal(s string) string {
	var out strings.Builder
	for _, w := range tsWord.Split(s, -1) {
		if w == "" {
			continue
		}
		r := []rune(w)
		r[0] = unicode.ToUpper(r[0])
		out.WriteString(string(r))
	}
	return out.String()
}

// tsCamel is tsPascal with the first letter lower-cased: an operation id's
// local part ("sign-in") becomes its method name (signIn). A name that would
// start with a digit gets a leading underscore.
func tsCamel(s string) string {
	p := []rune(tsPascal(s))
	if len(p) == 0 {
		return "_"
	}
	p[0] = unicode.ToLower(p[0])
	if unicode.IsDigit(p[0]) {
		return "_" + string(p)
	}
	return string(p)
}

// tsIdent matches a property name that needs no quotes.
var tsIdent = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`)

// tsPropName is a property name, quoted when it is not an identifier.
func tsPropName(name string) string {
	if tsIdent.MatchString(name) {
		return name
	}
	return tsString(name)
}

// tsString quotes s as a TypeScript string literal; JSON quoting is valid
// TypeScript.
func tsString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r < ' ' || r == '\u2028' || r == '\u2029':
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// renderTSClient writes TSFileClient: the declarations, then the core's
// operation table and createAuthClient, then one table and factory per
// plugin, every list sorted so two runs are byte-identical.
func renderTSClient(b *tsBuilder, byPlugin map[string][]tsOp, taken map[string]string) ([]byte, error) {
	claim := func(name, what string) error {
		if prev, ok := taken[name]; ok {
			return fmt.Errorf("%w: %s and %s are both %s", ErrTypeScriptName, prev, what, name)
		}
		taken[name] = what
		return nil
	}
	typeNames := make([]string, 0, len(b.decls))
	for n := range b.decls {
		typeNames = append(typeNames, n)
	}
	sort.Strings(typeNames)
	for _, n := range typeNames {
		if err := claim(n, "Go type "+b.owners[n].String()); err != nil {
			return nil, err
		}
	}
	plugins := make([]string, 0, len(byPlugin))
	for p := range byPlugin {
		if p != auth.CorePluginName {
			plugins = append(plugins, p)
		}
	}
	sort.Strings(plugins)

	var s strings.Builder
	s.WriteString(tsGeneratedHeader)
	s.WriteString("import type { AnyPlugin, AuthClient, ClientOptions, EmptyInput, Fill, Op, Plugin } from \"./runtime.ts\";\n")
	s.WriteString("import { createClient } from \"./runtime.ts\";\n\n")
	for _, n := range typeNames {
		s.WriteString("/** The JSON of Go type " + b.owners[n].String() + ". */\n")
		s.WriteString(b.decls[n])
		s.WriteString("\n")
	}

	core := byPlugin[auth.CorePluginName]
	writeTSOps(&s, "CoreOps", "the core (sessions, profile, account); its methods sit on the client's root", core)
	s.WriteString("/** The core's operation table, which every client has. */\n")
	s.WriteString("export const coreOps: CoreOps = ")
	writeTSTable(&s, core, "")
	s.WriteString(";\n\n")
	s.WriteString("/**\n * Builds a client: the core's methods on the root, and one namespace per plugin in `options.plugins`.\n * A plugin left out has no namespace, so calling it is a compile error. E is the session extras'\n * type, inferred from `options.sessionExtras`.\n */\n")
	s.WriteString("export function createAuthClient<const P extends readonly AnyPlugin[] = [], E = unknown>(options: ClientOptions<P, E>): AuthClient<CoreOps, P, E> {\n  return createClient(coreOps, options);\n}\n")

	coreMethods := map[string]bool{}
	for _, op := range core {
		coreMethods[op.name] = true
	}
	for _, p := range plugins {
		ns := tsCamel(p)
		if tsReserved[ns] {
			return nil, fmt.Errorf("%w: plugin %q is the TypeScript keyword %s", ErrTypeScriptName, p, ns)
		}
		// auth.New refuses a plugin named "core", so only the core's
		// method names can collide here.
		if coreMethods[ns] {
			return nil, fmt.Errorf("%w: plugin %q and the core's method %s", ErrTypeScriptName, p, ns)
		}
		opsType := tsPascal(p) + "Ops"
		if err := claim(ns, "plugin "+p); err != nil {
			return nil, err
		}
		if err := claim(opsType, "plugin "+p+"'s operations"); err != nil {
			return nil, err
		}
		s.WriteString("\n")
		writeTSOps(&s, opsType, "the "+p+" plugin", byPlugin[p])
		fmt.Fprintf(&s, "/** Enables the %s plugin's methods as `client.%s`. */\n", p, ns)
		fmt.Fprintf(&s, "export function %s(): Plugin<%s, %s> {\n  return { name: %s, ops: ", ns, tsString(ns), opsType, tsString(ns))
		writeTSTable(&s, byPlugin[p], "  ")
		s.WriteString(" };\n}\n")
	}
	return []byte(s.String()), nil
}

// writeTSOps writes the operation table's type: one Op per operation, sorted
// by method name, with the route and requirement as its doc comment.
// Method names are unique per table: TypeScriptClient refused duplicates.
func writeTSOps(s *strings.Builder, typeName, what string, ops []tsOp) {
	sort.Slice(ops, func(i, j int) bool { return ops[i].name < ops[j].name })
	fmt.Fprintf(s, "/** The operations of %s. */\n", what)
	fmt.Fprintf(s, "export type %s = {\n", typeName)
	for _, op := range ops {
		fmt.Fprintf(s, "  /** `%s %s` (%s), requires %s. */\n", op.method, op.path, op.id, op.require)
		fmt.Fprintf(s, "  readonly %s: Op<%s, %s>;\n", op.name, op.in, op.out)
	}
	s.WriteString("};\n\n")
}

// writeTSTable writes the operation table's value: where each operation is
// served. The types ride on the table's declared type, not on the value.
// Every table has an operation: a plugin is listed only for the operations
// it registered, and the core always serves the session reads.
func writeTSTable(s *strings.Builder, ops []tsOp, indent string) {
	s.WriteString("{\n")
	for _, op := range ops {
		fmt.Fprintf(s, "%s  %s: { id: %s, method: %s, path: %s", indent, op.name, tsString(op.id), tsString(op.method), tsString(op.path))
		if op.endsSession {
			s.WriteString(", endsSession: true")
		}
		if op.signIn {
			s.WriteString(", signIn: true")
		}
		if len(op.fills) > 0 {
			pairs := make([]string, len(op.fills))
			for i, f := range op.fills {
				pairs[i] = tsPropName(f) + ": " + tsString(tsInputFills[f])
			}
			s.WriteString(", fill: { " + strings.Join(pairs, ", ") + " }")
		}
		s.WriteString(" },\n")
	}
	s.WriteString(indent + "}")
}

// tsErrorCodesConst is the exported constant of TSFileErrorCodes.
const tsErrorCodesConst = "AUTH_ERROR_CODES"

// TypeScriptErrorCodes is TSFileErrorCodes: a TypeScript module with every
// error code the linked packages declare (auth.Errors), sorted, as a const
// object of status, message and owning plugin, the union type of the codes,
// the wire shape of an error answer and a guard that narrows a string to a
// known code. The plugin is the code's prefix, or the core's name for the
// core's own codes (prefix "auth" or none). apiref writes the same bytes to
// docs/reference/error-codes.ts.
//
//ds:def id=authhttp-typescripterrorcodes-8kw3nq5v owner=@khanakia stability=stable
func TypeScriptErrorCodes() []byte {
	codes := auth.Errors() // sorted by code
	var b strings.Builder
	b.WriteString("// Generated by task docs:api from the errors ubgo/auth and its plugins declare. Do not edit.\n\n")
	b.WriteString("/** Every error code the auth routes can answer, with the HTTP status and the message for people. Match on the code: messages may change. */\n")
	b.WriteString("export const " + tsErrorCodesConst + " = {\n")
	for _, c := range codes {
		plugin := auth.CorePluginName
		if p, _, ok := strings.Cut(c.Code, "."); ok && p != "auth" {
			plugin = p
		}
		fmt.Fprintf(&b, "  %s: { status: %d, message: %s, plugin: %s },\n", tsString(c.Code), c.Status, tsString(c.Message), tsString(plugin))
	}
	b.WriteString("} as const;\n\n")
	b.WriteString("/** A code the routes can answer. */\n")
	b.WriteString("export type AuthErrorCode = keyof typeof " + tsErrorCodesConst + ";\n\n")
	b.WriteString("/** The body of every error answer: `{ error: { code, message } }` with the status of the code. */\n")
	b.WriteString("export interface AuthErrorBody {\n  error: { code: AuthErrorCode | (string & {}); message: string };\n}\n\n")
	b.WriteString("/** Whether a code is one this list knows, narrowing it to AuthErrorCode. */\n")
	b.WriteString("export function isAuthErrorCode(code: string): code is AuthErrorCode {\n  return Object.prototype.hasOwnProperty.call(" + tsErrorCodesConst + ", code);\n}\n")
	return []byte(b.String())
}
