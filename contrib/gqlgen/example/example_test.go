package example

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	authgql "github.com/ubgo/auth/contrib/gqlgen"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	"github.com/vektah/gqlparser/v2/gqlerror"
	_ "modernc.org/sqlite"
)

const origin = "https://app.example.com"

func setup(t *testing.T, opts ...authhttp.Option) http.Handler {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "a.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	pw := password.New(password.Argon2(password.Argon2Params{Memory: 64, Time: 1, Threads: 1}))
	a, err := auth.New(auth.WithDB(db, sqlb.SQLiteDialect{}), auth.WithBaseURL(origin), auth.WithPlugins(
		email.New(email.Login(), email.Recover(), email.WithMailer(email.MailerFunc(func(context.Context, email.Mail) error { return nil }))), pw))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return Handler(a, pw, opts...)
}

type gqlResponse struct {
	Data   map[string]json.RawMessage `json:"data"`
	Errors []*gqlerror.Error          `json:"errors"`
}

func post(t *testing.T, h http.Handler, query string, cookie *http.Cookie) (*httptest.ResponseRecorder, gqlResponse) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"query": query})
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", origin)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var res gqlResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("response %q: %v", rec.Body.String(), err)
	}
	return rec, res
}

func sessionCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == authhttp.CookieName {
			return c
		}
	}
	return nil
}

func TestGraphQL_SignUpSetsTheCookieAndMeReadsIt(t *testing.T) {
	h := setup(t)
	rec, res := post(t, h, `mutation { signUp(identifier: "ada@example.com", password: "correct horse battery", name: "Ada") { user { id name } } }`, nil)
	if len(res.Errors) != 0 {
		t.Fatalf("signUp errors: %v", res.Errors)
	}
	cookie := sessionCookie(rec)
	if cookie == nil || cookie.Value == "" {
		t.Fatal("the sign-up mutation must set the session cookie on the GraphQL response")
	}
	if strings.Contains(rec.Body.String(), cookie.Value) {
		t.Fatal("the token reached the GraphQL body")
	}

	_, res = post(t, h, `{ me { name } }`, cookie)
	if len(res.Errors) != 0 || !strings.Contains(string(res.Data["me"]), `"Ada"`) {
		t.Fatalf("me = %s %v", res.Data["me"], res.Errors)
	}

	_, res = post(t, h, `mutation { signOut }`, cookie)
	if len(res.Errors) != 0 {
		t.Fatalf("signOut: %v", res.Errors)
	}
	_, res = post(t, h, `{ me { name } }`, cookie)
	if len(res.Errors) != 1 || authgql.Code(res.Errors[0]) != auth.ErrSignedOut.Code {
		t.Fatalf("me after sign-out: %v, want code %s", res.Errors, auth.ErrSignedOut.Code)
	}
}

func TestGraphQL_ErrorsCarryTheStableCode(t *testing.T) {
	h := setup(t)
	_, res := post(t, h, `mutation { signIn(identifier: "nobody@example.com", password: "whatever passphrase") { user { id } } }`, nil)
	if len(res.Errors) != 1 || authgql.Code(res.Errors[0]) != password.ErrInvalidCredentials.Code || res.Errors[0].Message != password.ErrInvalidCredentials.Message {
		t.Fatalf("errors = %+v", res.Errors)
	}
}

func TestGraphQL_CrossSiteMutationIsRefused(t *testing.T) {
	h := setup(t)
	rec, _ := post(t, h, `mutation { signUp(identifier: "ada@example.com", password: "correct horse battery") { user { id } } }`, nil)
	cookie := sessionCookie(rec)
	body, _ := json.Marshal(map[string]string{"query": `mutation { signOut }`})
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var res gqlResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if len(res.Errors) != 1 || authgql.Code(res.Errors[0]) != auth.ErrOriginNotTrusted.Code {
		t.Fatalf("cross-site signOut: %+v", res.Errors)
	}
}

// TestSchema_CopyMatchesTheLibrary keeps the example's copy of the schema in
// step with authgql.Schema.
func TestSchema_CopyMatchesTheLibrary(t *testing.T) {
	b, err := os.ReadFile("graph/auth.graphqls")
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != authgql.Schema {
		t.Fatal("graph/auth.graphqls differs from authgql.Schema; copy it again")
	}
}

// TestGraphQL_HonoursTheCookiePrefix: the authhttp options the app passes to
// Handler shape the cookie the GraphQL endpoint sets and reads, so it agrees
// with the app's other routes about which cookie holds the session.
func TestGraphQL_HonoursTheCookiePrefix(t *testing.T) {
	h := setup(t, authhttp.CookiePrefix("myapp"))
	rec, res := post(t, h, `mutation { signUp(identifier: "ada@example.com", password: "correct horse battery", name: "Ada") { user { id name } } }`, nil)
	if len(res.Errors) != 0 {
		t.Fatalf("signUp errors: %v", res.Errors)
	}
	var prefixed *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == authhttp.CookieName {
			t.Fatalf("the default-named cookie was set under a prefix: %s", c)
		}
		if c.Name == "__Host-myapp_session" {
			prefixed = c
		}
	}
	if prefixed == nil || prefixed.Value == "" {
		t.Fatalf("no __Host-myapp_session cookie: %v", rec.Header()["Set-Cookie"])
	}
	if _, res = post(t, h, `{ me { name } }`, prefixed); len(res.Errors) != 0 || !strings.Contains(string(res.Data["me"]), `"Ada"`) {
		t.Fatalf("me with the prefixed cookie = %s %v", res.Data["me"], res.Errors)
	}
	// The same token under the default name is not a credential here.
	if _, res = post(t, h, `{ me { name } }`, &http.Cookie{Name: authhttp.CookieName, Value: prefixed.Value}); len(res.Errors) != 1 || authgql.Code(res.Errors[0]) != auth.ErrSignedOut.Code {
		t.Fatalf("me with the default-named cookie: %v, want %s", res.Errors, auth.ErrSignedOut.Code)
	}
}
