package main

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
)

const (
	// newcomer is an address nobody created, used to try sign-up.
	newcomer = "bob@example.com"
	// newcomerPassword is a password long enough for the default policy, so a
	// refusal can only come from the disabled operation.
	newcomerPassword = "another long password"
	// evilOrigin is a site the app does not trust.
	evilOrigin = "https://evil.example"
	// headerFetchSite is the Fetch Metadata request header a browser sets.
	headerFetchSite = "Sec-Fetch-Site"
	// fetchSameOrigin is the value of a request from the app's own page.
	fetchSameOrigin = "same-origin"
	// fakeDriverName registers a database/sql driver that is none of the three
	// engines, so WithDBAuto has nothing to detect.
	fakeDriverName = "core-options-unknown"
	// pathSignUp and pathSignIn are the password plugin's routes under the prefix.
	pathSignUp = authPrefix + "/password/sign-up"
	pathSignIn = authPrefix + "/password/sign-in"
)

// uuidV7Pattern matches what newUUIDv7 returns: lowercase hex in 8-4-4-4-12
// groups, version 7, RFC 9562 variant.
var uuidV7Pattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// TestDisabledOperations: sign-up has no route and its Go method refuses,
// while sign-in, which was not switched off, works for the account the app
// created itself. A typo in a disabled id fails auth.New.
func TestDisabledOperations(t *testing.T) {
	p, _ := newTestApp(t)
	b := newBrowser(t, newHandler(p.auth))

	refused := post[errorAnswer](t, b, pathSignUp, fields{"identifier": newcomer, "password": newcomerPassword}, http.StatusNotFound, nil)
	if refused.Error.Code != auth.ErrUnknownOperation.Code {
		t.Fatalf("sign-up over HTTP = %+v, want %s", refused.Error, auth.ErrUnknownOperation.Code)
	}
	_, err := p.passwords.SignUp(context.Background(), password.SignUpRequest{Identifier: newcomer, Password: newcomerPassword})
	if !errors.Is(err, auth.ErrUnknownOperation) {
		t.Fatalf("sign-up from Go = %v, want ErrUnknownOperation", err)
	}
	signIn(t, b, fetchSameOrigin, baseURL, http.StatusOK)

	_, err = auth.New(auth.WithDialect(sqlb.SQLiteDialect{}), auth.WithBaseURL(baseURL),
		auth.WithDisabledOperations("password.signup"), auth.WithPlugins(testPlugins()...))
	if !errors.Is(err, auth.ErrUnknownHookTarget) {
		t.Fatalf("a misspelled disabled id = %v, want ErrUnknownHookTarget", err)
	}
}

// TestDBAuto: the dialect comes from the driver, and a database that is none
// of the three engines fails auth.New instead of being guessed.
func TestDBAuto(t *testing.T) {
	p, _ := newTestApp(t)
	if got := p.auth.Engine(); got != auth.EngineSQLite {
		t.Fatalf("Engine() = %q, want %q", got, auth.EngineSQLite)
	}
	db, err := sql.Open(fakeDriverName, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := newApp(db); !errors.Is(err, auth.ErrUnknownDialect) {
		t.Fatalf("newApp on an unknown database = %v, want ErrUnknownDialect", err)
	}
}

// TestIDs: the user, its identity and its session all carry ids from
// newUUIDv7, and a generator that fails makes the write fail with its error.
func TestIDs(t *testing.T) {
	p, db := newTestApp(t)
	b := newBrowser(t, newHandler(p.auth))
	userID := signIn(t, b, fetchSameOrigin, baseURL, http.StatusOK).User.ID
	if got := get[meResponse](t, b, "/me", http.StatusOK); got.ID != userID {
		t.Fatalf("/me = %+v, want %s", got, userID)
	}
	for _, table := range []string{"auth_user", "auth_identity", "auth_session"} {
		var id string
		if err := db.QueryRow("SELECT id FROM " + table).Scan(&id); err != nil {
			t.Fatalf("%s: %v", table, err)
		}
		if !uuidV7Pattern.MatchString(id) {
			t.Fatalf("%s id = %q, want a UUIDv7", table, id)
		}
	}

	errNoEntropy := errors.New("no entropy")
	a, err := auth.New(auth.WithDBAuto(db), auth.WithBaseURL(baseURL), auth.WithPlugins(testPlugins()...),
		auth.WithIDs(func(string) (string, error) { return "", errNoEntropy }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.CreateUser(context.Background(), auth.NewUser{}); !errors.Is(err, errNoEntropy) {
		t.Fatalf("CreateUser with a failing generator = %v, want its error", err)
	}
}

// TestSQLTypes: the Postgres script types ids and the columns referring to
// them UUID, where the built-in spelling is TEXT, and an engine the core
// cannot write DDL for fails auth.New.
func TestSQLTypes(t *testing.T) {
	typed, err := postgresMigrationSQL()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"auth_user (id UUID NOT NULL", "auth_session (id UUID NOT NULL PRIMARY KEY, user_id UUID NOT NULL", "auth_password (user_id UUID NOT NULL"} {
		if !strings.Contains(typed, want) {
			t.Fatalf("the typed script lacks %q:\n%s", want, typed)
		}
	}
	plain, err := auth.New(auth.WithDialect(sqlb.PostgresDialect{}), auth.WithBaseURL(baseURL), auth.WithPlugins(testPlugins()...))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = plain.Close() })
	builtin, err := plain.MigrationSQL()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(builtin, "auth_user (id TEXT NOT NULL") {
		t.Fatalf("the built-in script does not type ids TEXT:\n%s", builtin)
	}

	_, err = auth.New(auth.WithDialect(sqlb.PostgresDialect{}), auth.WithBaseURL(baseURL),
		auth.WithSQLTypes("sqlserver", postgresTypes), auth.WithPlugins(testPlugins()...))
	if !errors.Is(err, auth.ErrEngineNotSupported) {
		t.Fatalf("WithSQLTypes for sqlserver = %v, want ErrEngineNotSupported", err)
	}
}

// TestFetchMetadata: a sign-in the browser marks cross-site from an untrusted
// origin is refused, though it carries no cookie; the same request from the
// app's page passes, and so does one with no header at all (curl, a native
// app). Without WithFetchMetadata the cross-site request signs in, which is
// the login CSRF the option closes.
func TestFetchMetadata(t *testing.T) {
	p, db := newTestApp(t)
	b := newBrowser(t, newHandler(p.auth))
	refused := post[errorAnswer](t, b, pathSignIn, demoCredentials(), http.StatusForbidden,
		map[string]string{"Origin": evilOrigin, headerFetchSite: auth.FetchSiteCrossSite})
	if refused.Error.Code != auth.ErrOriginNotTrusted.Code {
		t.Fatalf("cross-site sign-in = %+v, want %s", refused.Error, auth.ErrOriginNotTrusted.Code)
	}
	if b.hasCookie() {
		t.Fatal("a refused cross-site sign-in set a session cookie")
	}
	signIn(t, b, fetchSameOrigin, baseURL, http.StatusOK)
	signIn(t, newBrowser(t, newHandler(p.auth)), "", evilOrigin, http.StatusOK)

	open, err := auth.New(auth.WithDBAuto(db), auth.WithBaseURL(baseURL), auth.WithPlugins(testPlugins()...))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = open.Close() })
	signIn(t, newBrowser(t, newHandler(open)), auth.FetchSiteCrossSite, evilOrigin, http.StatusOK)
}

// newTestApp builds the app on a fresh SQLite file, migrated, with the demo
// account created the way main creates it (twice, to prove a restart is safe).
func newTestApp(t *testing.T) (*app, *sql.DB) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	p, err := newApp(db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.auth.Close() })
	ctx := context.Background()
	if _, err := p.auth.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := p.ensureAccount(ctx, demoEmail, demoPassword); err != nil {
			t.Fatal(err)
		}
	}
	return p, db
}

// testPlugins is the plugin list of newApp, for the contrasting configurations.
func testPlugins() []auth.Plugin {
	return []auth.Plugin{email.New(email.Login(), email.Recover(), email.WithMailer(logMailer{})), password.New()}
}

// demoCredentials is the sign-in body of the demo account.
func demoCredentials() fields {
	return fields{"identifier": demoEmail, "password": demoPassword}
}

// signInAnswer is the part of the password sign-in answer the test reads.
type signInAnswer struct {
	User struct {
		ID string `json:"id"`
	} `json:"user"`
}

// signIn signs the demo account in with the given Sec-Fetch-Site ("" sends
// none) and Origin, and checks the status.
func signIn(t *testing.T, b *browser, fetchSite, origin string, status int) signInAnswer {
	t.Helper()
	h := map[string]string{"Origin": origin}
	if fetchSite != "" {
		h[headerFetchSite] = fetchSite
	}
	return post[signInAnswer](t, b, pathSignIn, demoCredentials(), status, h)
}

// unknownDriver is a database/sql driver for a database that is none of the
// three engines: every statement fails, so DetectDialect's probes all fail.
type unknownDriver struct{}

// Open returns a connection that refuses every statement.
func (unknownDriver) Open(string) (driver.Conn, error) { return unknownConn{}, nil }

// unknownConn refuses every statement and transaction.
type unknownConn struct{}

// errUnknownEngine is what the unknown database answers to everything.
var errUnknownEngine = errors.New("this database speaks no SQL the library knows")

func (unknownConn) Prepare(string) (driver.Stmt, error) { return nil, errUnknownEngine }
func (unknownConn) Close() error                        { return nil }
func (unknownConn) Begin() (driver.Tx, error)           { return nil, errUnknownEngine }

// init registers the unknown engine, once per test binary, as sql.Register
// panics on a second registration of one name.
func init() { sql.Register(fakeDriverName, unknownDriver{}) }

// browser is an HTTPS test server and a client with a cookie jar, because the
// session cookie is __Host- and Secure and a jar keeps it only for https.
type browser struct {
	srv    *httptest.Server
	client *http.Client
}

// newBrowser serves h over TLS.
func newBrowser(t *testing.T, h http.Handler) *browser {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := srv.Client()
	client.Jar = jar
	return &browser{srv: srv, client: client}
}

// hasCookie reports whether the jar holds any cookie for the server.
func (b *browser) hasCookie() bool {
	req := httptest.NewRequest(http.MethodGet, b.srv.URL, nil)
	return len(b.client.Jar.Cookies(req.URL)) > 0
}

// fields is a JSON request body as a client writes it. The library's request
// types are not used to send: their secrets encode as "[redacted]" on purpose.
type fields map[string]string

// errorAnswer is the JSON shape of every error the library answers.
type errorAnswer struct {
	Error auth.ErrorInfo `json:"error"`
}

// post sends in as JSON with the given headers (Origin defaults to the app's
// own), checks the status and decodes the answer as Out.
func post[Out, In any](t *testing.T, b *browser, path string, in In, status int, headers map[string]string) Out {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, b.srv.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", baseURL)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return do[Out](t, b, req, status)
}

// get fetches path, checks the status and decodes the answer as Out.
func get[Out any](t *testing.T, b *browser, path string, status int) Out {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, b.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return do[Out](t, b, req, status)
}

// do sends req, checks the status and decodes the answer as Out.
func do[Out any](t *testing.T, b *browser, req *http.Request, status int) Out {
	t.Helper()
	var out Out
	res, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(res.Body); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != status {
		t.Fatalf("%s %s: status %d, want %d: %s", req.Method, req.URL.Path, res.StatusCode, status, buf.String())
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("%s %s: decode %q: %v", req.Method, req.URL.Path, buf.String(), err)
	}
	return out
}
