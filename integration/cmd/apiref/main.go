// Command apiref writes the generated reference files under docs/reference:
// the table of every HTTP route the library serves when every built-in plugin
// is wired (http-api.md), the OpenAPI document of the same routes
// (openapi.json) with input and output schemas derived from the operations'
// Go types, and the list of every error code the core and the plugins declare
// (error-codes.md, error-codes.json and error-codes.ts for a TypeScript
// frontend), and the method reference of the TypeScript client
// (ts-client.md). With -client it also writes (or checks) the prebuilt
// TypeScript client in clients/ts/src, from authhttp.TypeScriptClient over
// the same wiring.
//
// Why they are generated: the routes are the operation list, decided when
// auth.New wires the plugins, and a hand-kept table drifts the first time a
// plugin gains an operation. The generator wires every plugin without a
// database, the way examples/poc does, and reads the list back; task
// docs:api writes the files and task check fails when a committed copy is
// stale.
//
// Usage:
//
//	go run ./cmd/apiref -dir ../docs/reference -client ../clients/ts/src
//	go run ./cmd/apiref -check ../docs/reference -client ../clients/ts/src
//	go run ./cmd/apiref                       # prints http-api.md
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ubgo/auth"
	_ "github.com/ubgo/auth/authgate" // declares authgate's error codes for the error-code list
	"github.com/ubgo/auth/authhttp"
	_ "github.com/ubgo/auth/authui" // declares authui's error codes for the error-code list
	"github.com/ubgo/auth/plugin/admin"
	_ "github.com/ubgo/auth/plugin/agentauth" // declares agentauth's error codes for the error-code list
	"github.com/ubgo/auth/plugin/anonymous"
	"github.com/ubgo/auth/plugin/apikey"
	"github.com/ubgo/auth/plugin/audit"
	// captcha is a rate challenger like pow, and auth.New refuses two; it adds
	// no route, so pow is the one wired and captcha is imported for its error
	// codes alone.
	_ "github.com/ubgo/auth/plugin/captcha"
	"github.com/ubgo/auth/plugin/deviceauth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/emailchallenge"
	"github.com/ubgo/auth/plugin/handoff"
	"github.com/ubgo/auth/plugin/invite"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/lastlogin"
	"github.com/ubgo/auth/plugin/ldap"
	"github.com/ubgo/auth/plugin/magiclink"
	"github.com/ubgo/auth/plugin/metadata"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/oauthprovider"
	_ "github.com/ubgo/auth/plugin/oauthproxy"            // declares oauthproxy's error codes for the error-code list
	_ "github.com/ubgo/auth/plugin/oauthproxy/oauthpopup" // declares oauthpopup's error codes for the error-code list
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/passkey"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/phone"
	"github.com/ubgo/auth/plugin/pow"
	"github.com/ubgo/auth/plugin/referral"
	_ "github.com/ubgo/auth/plugin/samlidp" // declares samlidp's error codes; its routes are self-served
	_ "github.com/ubgo/auth/plugin/scim"    // declares scim's managed-connection error codes; SCIM routes answer their own schema
	"github.com/ubgo/auth/plugin/siwe"
	_ "github.com/ubgo/auth/plugin/sso" // declares sso's error codes for the error-code list
	"github.com/ubgo/auth/plugin/terms"
	"github.com/ubgo/auth/plugin/twofactor"
	"github.com/ubgo/auth/plugin/username"
	_ "github.com/ubgo/auth/plugin/webhook" // declares webhook's Go-only error codes for the error-code list
	"github.com/ubgo/sqlb"
)

// Wiring values. None reaches a database or a network; they exist so every
// plugin's Validate passes and its operations are registered.
const (
	baseURL = "https://app.example.com"
	// prefix is the mount path the table shows, the one every example uses.
	prefix = "/auth"
	// Placeholder credentials for the OAuth providers; the routes do not
	// depend on them.
	placeholderClientID     = "client-id"
	placeholderClientSecret = "client-secret"
	// termsVersion is any version string; terms.Current refuses an empty one.
	termsVersion = "2026-01"
	// apiScope is one scope so apikey.Validate passes.
	apiScope = "read"
	// sealKeySize is the AES-256 key the two-factor plugin seals secrets with.
	sealKeySize = 32
)

// The generated files, by name under the output directory.
const (
	fileHTTPAPI  = "http-api.md"
	fileOpenAPI  = "openapi.json"
	fileTSClient = "ts-client.md"
)

// OpenAPI document header. The title and version describe the library's
// routes as a whole, not any one app; an app serving its own document passes
// its own OpenAPIInfo to authhttp.OpenAPI.
const (
	openAPITitle       = "ubgo/auth HTTP API"
	openAPIVersion     = "main"
	openAPIDescription = "Every route the library serves when every built-in plugin is wired, mounted at " + prefix + ". An app serves only the routes of the plugins it wires. Generated by task docs:api."
)

// guideDir is where the plugin guides live, relative to the generated file.
const guideDir = "../plugins/"

// coreGuide is the guide the core's own operations (sessions, profile) link to.
const coreGuide = "../concepts/sessions.md"

// ErrStale is returned by check when a committed file differs from what the
// generator writes now.
var ErrStale = errors.New("apiref: docs/reference is stale; run task docs:api")

func main() {
	dir := flag.String("dir", "", "write every generated file into this directory (default: print http-api.md)")
	check := flag.String("check", "", "compare the files in this directory with the generated ones and exit 1 when one differs")
	concepts := flag.String("concepts", defaultConceptsPage, "the hand-written errors page every declared code must have a row on; empty skips the check")
	client := flag.String("client", "", "with -dir or -check, also write or check the TypeScript client's generated files in this directory")
	flag.Parse()
	if err := run(*dir, *check, *client, *concepts, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "apiref:", err)
		os.Exit(1)
	}
}

// defaultConceptsPage is the errors concept page, relative to the
// integration module where task runs the generator.
const defaultConceptsPage = "../docs/concepts/errors.md"

// run generates the documents and writes, checks or prints them; with
// client, the TypeScript client's files are written or checked there too.
// With a concepts page, every declared code must have a row on it, in every
// mode: a code without a "when" is a frontend mapping nobody can write.
func run(dir, check, client, concepts string, stdout io.Writer) error {
	docs, ts, err := generate()
	if err != nil {
		return err
	}
	if concepts != "" {
		if err := checkDocumented(concepts, errorCodes()); err != nil {
			return err
		}
	}
	switch {
	case check != "":
		if err := checkFiles(check, docs); err != nil {
			return err
		}
		if client != "" {
			return checkFiles(client, ts)
		}
		return nil
	case dir != "":
		if err := writeFiles(dir, docs); err != nil {
			return err
		}
		if client != "" {
			return writeFiles(client, ts)
		}
		return nil
	default:
		_, err := stdout.Write(docs[fileHTTPAPI])
		return err
	}
}

// checkFiles fails with ErrStale when a file in dir differs from files or
// is missing.
func checkFiles(dir string, files map[string][]byte) error {
	for _, name := range sortedNames(files) {
		have, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return fmt.Errorf("%w: %v", ErrStale, err)
		}
		if !bytes.Equal(have, files[name]) {
			return fmt.Errorf("%w: %s differs", ErrStale, filepath.Join(dir, name))
		}
	}
	return nil
}

// writeFiles writes files into dir, which must exist.
func writeFiles(dir string, files map[string][]byte) error {
	for _, name := range sortedNames(files) {
		if err := os.WriteFile(filepath.Join(dir, name), files[name], 0o644); err != nil {
			return err
		}
	}
	return nil
}

func sortedNames(docs map[string][]byte) []string {
	names := make([]string, 0, len(docs))
	for n := range docs {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// plugins is every built-in plugin, wired with the least configuration that
// passes its Validate. Mail and SMS senders are stubs that are never called.
func plugins() ([]auth.Plugin, error) {
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	key := make([]byte, sealKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	// One jwt plugin signs the app's tokens and the provider's ID tokens.
	jw := jwt.New(jwt.WithSigningKey(signing), jwt.Issuer(baseURL))
	// passkey's security-key store makes twofactor list its security-key
	// routes, which exist only with WithSecurityKeys.
	pk := passkey.New(passkey.WithSignUp())
	return []auth.Plugin{
		email.New(email.Login(), email.Recover(), email.Multiple(), email.SignInWithCode(), email.VerifyByCode(), email.WithMailer(email.MailerFunc(noMail))),
		phone.New(phone.Login(), phone.Recover(), phone.Multiple(), phone.SignInWithCode(), phone.WithSMS(phone.SMSFunc(noSMS))),
		username.New(username.Login()),
		password.New(),
		// StoreTokens (sealed under the derived secret key) with
		// ExposeAccessTokens, so the reference lists the opt-in
		// POST /oauth/access-token route.
		oauth.New(oauth.WithProviders(oauth.Google(placeholderClientID, placeholderClientSecret), oauth.GitHub(placeholderClientID, placeholderClientSecret)), oauth.StoreTokens(), oauth.ExposeAccessTokens()),
		twofactor.New(twofactor.WithEncryptionKey(key), twofactor.DeliveredCodes(), twofactor.TrustDevices(0), twofactor.ReadableTOTPURI(), twofactor.RecoveryCodeStorage(twofactor.StoreEncrypted), twofactor.WithSecurityKeys(pk.SecurityKeys())),
		pk,
		magiclink.New(),
		admin.New(),
		audit.New(),
		apikey.New(apikey.Scopes(apiScope)),
		jw,
		oauthprovider.New(jw, oauthprovider.Issuer(baseURL), oauthprovider.LoginPage("/login"), oauthprovider.ConsentPage("/consent")),
		terms.New(terms.Current(termsVersion)),
		anonymous.New(),
		handoff.New(),
		deviceauth.New(),
		lastlogin.New(),
		pow.New(),
		organization.New(organization.Teams(organization.TeamsConfig{}), organization.DynamicRoles(organization.DynamicRolesConfig{}), organization.Domains(organization.DomainsConfig{})),
		emailchallenge.New(),
		invite.New(),
		referral.New(),
		ldap.New(ldap.WithDirectory(ldap.DirectoryFunc(noDirectory))),
		siwe.New(),
		// WithAdmin, so the reference lists the opt-in admin routes.
		metadata.New(metadata.WithAdmin(metadata.AuthorizerFunc(denyMetadata))),
	}, nil
}

// denyMetadata is the metadata admin authorizer the generator wires; it is
// never asked.
func denyMetadata(context.Context, metadata.AccessRequest) (bool, error) { return false, nil }

// noMail and noSMS satisfy the sender interfaces; the generator sends nothing.
func noMail(context.Context, email.Mail) error    { return nil }
func noSMS(context.Context, string, string) error { return nil }

// noDirectory is the LDAP directory the generator wires: it knows nobody, so
// the ldap plugin's route is listed without a server to reach.
func noDirectory(context.Context, string, string) (ldap.Entry, error) {
	return ldap.Entry{}, ldap.ErrInvalidCredentials
}

// row is one route of the table.
type row struct {
	method, path, require, id, plugin string
}

// generate wires every plugin and renders every document and every file of
// the TypeScript client, each by file name.
func generate() (docs, client map[string][]byte, err error) {
	ps, err := plugins()
	if err != nil {
		return nil, nil, err
	}
	// The core's opt-in operations are wired too, so the reference lists
	// every route an app can turn on.
	// A secret, because twofactor's StoreEncrypted derives its key from one.
	secret := make([]byte, auth.MinSecretSize)
	if _, err := rand.Read(secret); err != nil {
		return nil, nil, err
	}
	a, err := auth.New(auth.WithDialect(sqlb.PostgresDialect{}), auth.WithBaseURL(baseURL), auth.WithSecret(secret), auth.WithPlugins(ps...),
		auth.WithAccountDeletion(auth.AccountDeletion{}), auth.WithMultiSession(0), auth.WithDeferredSessionRefresh())
	if err != nil {
		return nil, nil, err
	}
	var rows []row
	for _, op := range a.Operations() {
		info := op.Info()
		rows = append(rows, row{method: authhttp.MethodOf(info.Kind), path: prefix + op.Route(), require: string(info.Require), id: string(info.ID), plugin: op.Plugin()})
	}
	// Stable order whatever the plugin list's order: by path, then method.
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].path != rows[j].path {
			return rows[i].path < rows[j].path
		}
		return rows[i].method < rows[j].method
	})
	openapi := authhttp.OpenAPIDocument(a, authhttp.OpenAPIInfo{Title: openAPITitle, Version: openAPIVersion, Description: openAPIDescription, Servers: []string{baseURL}}, authhttp.Prefix(prefix))
	if err := checkConflicts(); err != nil {
		return nil, nil, err
	}
	codes := errorCodes()
	codesJSON, err := renderErrorCodesJSON(codes)
	if err != nil {
		return nil, nil, err
	}
	client, err = authhttp.TypeScriptClient(a)
	if err != nil {
		return nil, nil, err
	}
	methods, err := authhttp.TypeScriptMethods(a)
	if err != nil {
		return nil, nil, err
	}
	return map[string][]byte{
		fileHTTPAPI:        render(rows),
		fileOpenAPI:        append(openapi, '\n'),
		fileTSClient:       renderTSClient(methods),
		fileErrorCodesMD:   renderErrorCodesMD(codes),
		fileErrorCodesJSON: codesJSON,
		// The same bytes as the client's own error-codes.ts.
		fileErrorCodesTS: client[authhttp.TSFileErrorCodes],
	}, client, nil
}

// render writes the Markdown. One physical line per paragraph and row, as
// the repository's docs rule requires.
func render(rows []row) []byte {
	var b strings.Builder
	b.WriteString("# HTTP API reference\n\n")
	b.WriteString("Every route the library serves when every built-in plugin is wired, mounted at `" + prefix + "` as the examples do. This file is generated by `task docs:api` from the operation list `auth.New` builds; do not edit it by hand, `task check` fails when it is stale. An app serves only the routes of the plugins it wires, and the OAuth routes exist once per configured provider (here `google` and `github`). The same routes with their input and output schemas are in [`openapi.json`](openapi.json), an OpenAPI 3.1 document; an app serves its own with `authhttp.OpenAPI`.\n\n")
	b.WriteString("Every mutation is a `POST` with a JSON body; every query is a `GET` with its input in the query string. A mutation sent with a session cookie must carry a trusted `Origin` header. The requirement column is what the request must have before the operation runs: `public` anyone, `signed_in` a session, `fresh_sign_in` a session created within the fresh window, `pending_second_factor` a session waiting for its second step. Errors come back as `{\"error\":{\"code\":…,\"message\":…}}` with the status of the code; the codes are listed in [errors](../concepts/errors.md).\n\n")
	b.WriteString("| Method | Path | Requirement | Operation | Plugin |\n|---|---|---|---|---|\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "| `%s` | `%s` | `%s` | `%s` | %s |\n", r.method, r.path, r.require, r.id, guideLink(r.plugin))
	}
	b.WriteString("\nRead the plugin guides in [plugins](" + guideDir + ") for each flow end to end, and each plugin's README for its options, tables and errors.\n")
	return []byte(b.String())
}

// guideLink renders the plugin column: the plugin's guide, or the sessions
// concept page for the core's own operations.
func guideLink(plugin string) string {
	if plugin == auth.CorePluginName {
		return "[core](" + coreGuide + ")"
	}
	page := plugin
	if g, ok := guidePages[plugin]; ok {
		page = g
	}
	return "[" + plugin + "](" + guideDir + page + ".md)"
}

// guidePages names the guide of a plugin whose page is not called after the
// plugin: deviceauth registers as "device" (its routes are /auth/device/*),
// and its guide is deviceauth.md.
var guidePages = map[string]string{deviceauth.PluginName: "deviceauth"}

// clientGuide is the TypeScript client's plugin page, relative to the
// generated file.
const clientGuide = "../client/plugins.md"

// renderTSClient writes the TypeScript client's method reference: one
// section per namespace, the core's first, each method with its route, its
// requirement and its input and output types, as authhttp.TypeScriptMethods
// lists them. One physical line per paragraph and row.
func renderTSClient(methods []authhttp.TSMethod) []byte {
	var b strings.Builder
	b.WriteString("# TypeScript client reference\n\n")
	b.WriteString("Every method of the prebuilt TypeScript client in [`clients/ts`](../../clients/ts/), the client `task docs:api` generates with every built-in plugin wired. This file is generated by `task docs:api` from the same operation list as the client (`authhttp.TypeScriptMethods`); do not edit it by hand, `task check` fails when it is stale. A client your app generates with `auth client ts` has the core's methods, the methods of the plugins your app wires, and your own plugins' methods, named by the same rule.\n\n")
	b.WriteString("A plugin's methods exist on the client only when its factory is passed to `createAuthClient({ plugins: [...] })` (see [plugins](" + clientGuide + ")). A method's name is the operation id after the plugin's prefix, in camelCase. The route is below the mount prefix the client's `baseURL` carries (`" + prefix + "` here). Every method resolves to `{ data, error }`: `data` has the output type, and the input type is the argument (it may be left out when it is `EmptyInput` or every field is optional). The types are declared in `client.ts`; the requirement column is the one the [HTTP API reference](http-api.md) explains.\n")
	// The table of contents: one row per namespace, with its factory.
	b.WriteString("\n## Plugins\n\n| Factory | Namespace | Methods | Plugin guide |\n|---|---|---|---|\n")
	for i := 0; i < len(methods); {
		j := i
		for j < len(methods) && methods[j].Namespace == methods[i].Namespace {
			j++
		}
		m := methods[i]
		if m.Namespace == "" {
			fmt.Fprintf(&b, "| none: every client has them | the root ([core](#core-on-the-clients-root)) | %d | %s |\n", j-i, guideLink(m.Plugin))
		} else {
			fmt.Fprintf(&b, "| `%s()` | [`client.%s`](#%s) | %d | %s |\n", m.Namespace, m.Namespace, strings.ToLower(m.Namespace), j-i, guideLink(m.Plugin))
		}
		i = j
	}
	for i, m := range methods {
		if i == 0 || m.Namespace != methods[i-1].Namespace {
			if m.Namespace == "" {
				b.WriteString("\n## Core (on the client's root)\n\nEvery client has these methods, whatever its plugins: `client.session()`, `client.signOut()`.\n\n")
			} else {
				fmt.Fprintf(&b, "\n## %s\n\nEnable with `%s()`; call as `client.%s.<method>`. Plugin guide: %s.\n\n", m.Namespace, m.Namespace, m.Namespace, guideLink(m.Plugin))
			}
			b.WriteString("| Method | Route | Requirement | Input | Output |\n|---|---|---|---|---|\n")
		}
		call := m.Name
		if m.Namespace != "" {
			call = m.Namespace + "." + m.Name
		}
		fmt.Fprintf(&b, "| `%s` | `%s %s` | `%s` | `%s` | `%s` |\n", call, m.HTTPMethod, prefix+m.Path, m.Require, tsCell(m.Input), tsCell(m.Output))
	}
	return []byte(b.String())
}

// tsCell escapes the union bar of a TypeScript type for a Markdown table
// cell, where an unescaped | would end the cell.
func tsCell(t string) string {
	return strings.ReplaceAll(t, "|", "\\|")
}
