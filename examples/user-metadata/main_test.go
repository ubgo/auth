package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/metadata"
)

const (
	aliceEmail   = "alice@example.com"
	bobEmail     = "bob@example.com"
	testPassword = "correct horse battery staple"
	// privateMarker is the prefix of the billing id checkout writes to
	// private metadata; no answer a user can get may contain it.
	privateMarker = "cus_"
)

// TestMetadata_UserReadsPublicWritesUnsafe walks the user's side over HTTP:
// the documents start empty, a checkout fills public and private from the
// backend, the user patches unsafe (merge, then removal by null), the
// session answer carries public and unsafe, and nothing the user can fetch
// ever contains the private document.
func TestMetadata_UserReadsPublicWritesUnsafe(t *testing.T) {
	a, md, ad := newTestApp(t)
	h := newHandler(a, md, ad)
	alice := newBrowser(t, h)
	aliceID := signUp(t, alice, aliceEmail, "Alice")

	if m := get[metadata.UserMetadata](t, alice, "/auth/metadata/get", http.StatusOK); string(m.Public) != "{}" || string(m.Unsafe) != "{}" {
		t.Fatalf("fresh user = %s %s", m.Public, m.Unsafe)
	}
	post[checkoutResponse](t, alice, "/checkout", struct{}{}, http.StatusOK)

	m := post[metadata.UserMetadata](t, alice, "/auth/metadata/update", rawBody(`{"unsafe":{"theme":"dark","tour":{"step":2,"done":false}}}`), http.StatusOK)
	if string(m.Public) != `{"plan":"pro"}` || string(m.Unsafe) != `{"theme":"dark","tour":{"done":false,"step":2}}` {
		t.Fatalf("after update = %s %s", m.Public, m.Unsafe)
	}
	m = post[metadata.UserMetadata](t, alice, "/auth/metadata/update", rawBody(`{"unsafe":{"theme":null,"tour":{"step":3}}}`), http.StatusOK)
	if string(m.Unsafe) != `{"tour":{"done":false,"step":3}}` {
		t.Fatalf("after merge patch = %s", m.Unsafe)
	}

	var sess struct {
		Extras metadata.UserMetadata `json:"extras"`
	}
	body := getRaw(t, alice, "/auth/session", http.StatusOK)
	if err := json.Unmarshal(body, &sess); err != nil {
		t.Fatal(err)
	}
	if string(sess.Extras.Public) != `{"plan":"pro"}` || string(sess.Extras.Unsafe) != `{"tour":{"done":false,"step":3}}` {
		t.Fatalf("session extras = %s", body)
	}

	// The private document exists and holds the billing id...
	all, err := md.Get(context.Background(), aliceID)
	if err != nil || !strings.Contains(string(all.Private), privateMarker) {
		t.Fatalf("Get = %+v, %v", all, err)
	}
	// ...and no user-facing answer contains it.
	for _, path := range []string{"/auth/metadata/get", "/auth/session"} {
		if b := getRaw(t, alice, path, http.StatusOK); bytes.Contains(b, []byte(privateMarker)) || bytes.Contains(b, []byte("private")) {
			t.Fatalf("%s leaks private metadata: %s", path, b)
		}
	}
	if b := postRaw(t, alice, "/auth/metadata/update", rawBody(`{"unsafe":{}}`), http.StatusOK); bytes.Contains(b, []byte(privateMarker)) {
		t.Fatalf("update leaks private metadata: %s", b)
	}
}

// TestMetadata_UserCannotWritePublicOrPrivate: the update input has no field
// for the backend's documents, so naming one is refused before anything is
// written, alone or beside a valid unsafe patch.
func TestMetadata_UserCannotWritePublicOrPrivate(t *testing.T) {
	a, md, ad := newTestApp(t)
	h := newHandler(a, md, ad)
	alice := newBrowser(t, h)
	aliceID := signUp(t, alice, aliceEmail, "Alice")

	for _, b := range []string{
		`{"public":{"plan":"enterprise"}}`,
		`{"private":{"billingCustomer":"x"}}`,
		`{"unsafe":{"a":1},"public":{"plan":"enterprise"}}`,
		`{"unsafe":{"a":1},"private":{"x":1}}`,
	} {
		postRaw(t, alice, "/auth/metadata/update", rawBody(b), http.StatusBadRequest)
	}
	all, err := md.Get(context.Background(), aliceID)
	if err != nil || string(all.Public) != "{}" || string(all.Private) != "{}" || string(all.Unsafe) != "{}" {
		t.Fatalf("after refused writes = %s %s %s, %v", all.Public, all.Private, all.Unsafe, err)
	}
	// Signed out, both user routes are 401.
	stranger := newBrowser(t, h)
	getRaw(t, stranger, "/auth/metadata/get", http.StatusUnauthorized)
	postRaw(t, stranger, "/auth/metadata/update", rawBody(`{"unsafe":{"a":1}}`), http.StatusUnauthorized)
}

// TestMetadata_RefusesMalformedAndOversized: every patch that is not one JSON
// object is metadata.invalid, and a patch or a merged document over the
// bound is metadata.too_large; none of them changes the stored document.
func TestMetadata_RefusesMalformedAndOversized(t *testing.T) {
	const bound = 64
	a, md, ad := newTestApp(t, metadata.WithUnsafeMaxSize(bound))
	h := newHandler(a, md, ad)
	alice := newBrowser(t, h)
	aliceID := signUp(t, alice, aliceEmail, "Alice")
	post[metadata.UserMetadata](t, alice, "/auth/metadata/update", rawBody(`{"unsafe":{"keep":true}}`), http.StatusOK)

	for name, b := range map[string]string{
		"array":   `{"unsafe":[1,2]}`,
		"string":  `{"unsafe":"dark"}`,
		"number":  `{"unsafe":42}`,
		"null":    `{"unsafe":null}`,
		"missing": `{}`,
		"bool":    `{"unsafe":true}`,
	} {
		if e := postErr(t, alice, "/auth/metadata/update", rawBody(b), http.StatusBadRequest); e.Code != metadata.ErrInvalid.Code {
			t.Errorf("%s: %+v", name, e)
		}
	}
	// Bad JSON never reaches the plugin: the transport refuses the body.
	postRaw(t, alice, "/auth/metadata/update", rawBody(`{"unsafe":{"a":}`), http.StatusBadRequest)

	big := `{"unsafe":{"x":"` + strings.Repeat("a", bound) + `"}}`
	if e := postErr(t, alice, "/auth/metadata/update", rawBody(big), http.StatusRequestEntityTooLarge); e.Code != metadata.ErrTooLarge.Code {
		t.Fatalf("oversized patch: %+v", e)
	}
	// Small patches that together pass the bound are refused at the one
	// that would cross it.
	refused := false
	for i := range 10 {
		key := string(rune('a' + i))
		b := `{"unsafe":{"` + key + `":"` + strings.Repeat("z", 10) + `"}}`
		status := http.StatusOK
		if i >= 3 {
			status = http.StatusRequestEntityTooLarge
		}
		postRaw(t, alice, "/auth/metadata/update", rawBody(b), status)
		refused = refused || status != http.StatusOK
	}
	all, err := md.Get(context.Background(), aliceID)
	if err != nil || !refused || len(all.Unsafe) > bound || !strings.Contains(string(all.Unsafe), `"keep":true`) {
		t.Fatalf("after refusals = %s, %v", all.Unsafe, err)
	}
}

// TestMetadata_UpdateIsRateLimitedPerUser: WithUpdateRate counts per user, so
// Alice's last allowed call is followed by 429 while Bob still writes.
func TestMetadata_UpdateIsRateLimitedPerUser(t *testing.T) {
	a, md, ad := newTestApp(t, metadata.WithUpdateRate(2, time.Hour))
	h := newHandler(a, md, ad)
	alice, bob := newBrowser(t, h), newBrowser(t, h)
	signUp(t, alice, aliceEmail, "Alice")
	signUp(t, bob, bobEmail, "Bob")
	patch := rawBody(`{"unsafe":{"a":1}}`)
	postRaw(t, alice, "/auth/metadata/update", patch, http.StatusOK)
	postRaw(t, alice, "/auth/metadata/update", patch, http.StatusOK)
	if e := postErr(t, alice, "/auth/metadata/update", patch, http.StatusTooManyRequests); e.Code != auth.ErrRateLimited.Code {
		t.Fatalf("third update: %+v", e)
	}
	postRaw(t, bob, "/auth/metadata/update", patch, http.StatusOK)
}

// TestMetadata_AdminRoutesFollowTheAuthorizer: a plain user is refused the
// admin routes (for an existing and an unknown target alike, so the refusal
// reveals nothing), and an admin reads all three documents and patches any.
func TestMetadata_AdminRoutesFollowTheAuthorizer(t *testing.T) {
	a, md, ad := newTestApp(t)
	h := newHandler(a, md, ad)
	alice, bob := newBrowser(t, h), newBrowser(t, h)
	aliceID := signUp(t, alice, aliceEmail, "Alice")
	bobID := signUp(t, bob, bobEmail, "Bob")
	post[checkoutResponse](t, alice, "/checkout", struct{}{}, http.StatusOK)

	for _, target := range []string{aliceID, "usr_nobody"} {
		if e := getErr(t, bob, "/auth/metadata/admin-get?userId="+target, http.StatusForbidden); e.Code != metadata.ErrForbidden.Code {
			t.Fatalf("non-admin admin-get %s: %+v", target, e)
		}
		if e := postErr(t, bob, "/auth/metadata/admin-update", metadata.AdminUpdateRequest{UserID: target, Public: json.RawMessage(`{"plan":"free"}`)}, http.StatusForbidden); e.Code != metadata.ErrForbidden.Code {
			t.Fatalf("non-admin admin-update %s: %+v", target, e)
		}
	}

	if err := ad.SetRoleFor(context.Background(), bobID, admin.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	all := get[metadata.Metadata](t, bob, "/auth/metadata/admin-get?userId="+aliceID, http.StatusOK)
	if string(all.Public) != `{"plan":"pro"}` || !strings.Contains(string(all.Private), privateMarker) {
		t.Fatalf("admin-get = %s %s", all.Public, all.Private)
	}
	all = post[metadata.Metadata](t, bob, "/auth/metadata/admin-update", metadata.AdminUpdateRequest{UserID: aliceID, Public: json.RawMessage(`{"plan":"team","seats":5}`), Private: json.RawMessage(`{"note":"upsold"}`)}, http.StatusOK)
	if string(all.Public) != `{"plan":"team","seats":5}` || !strings.Contains(string(all.Private), `"note":"upsold"`) || string(all.Unsafe) != "{}" {
		t.Fatalf("admin-update = %s %s %s", all.Public, all.Private, all.Unsafe)
	}
	if e := getErr(t, bob, "/auth/metadata/admin-get?userId=usr_nobody", http.StatusNotFound); e.Code != auth.ErrUserNotFound.Code {
		t.Fatalf("admin-get unknown user: %+v", e)
	}
	// Alice sees the new public document and still no private one.
	if b := getRaw(t, alice, "/auth/metadata/get", http.StatusOK); !bytes.Contains(b, []byte(`"seats":5`)) || bytes.Contains(b, []byte("upsold")) {
		t.Fatalf("alice after admin-update: %s", b)
	}
}

// TestMetadata_ConcurrentMergesKeepEveryKey: merges of different keys for one
// user, fired at once, all land, because each runs under the row lock (and
// the first-write race retries).
func TestMetadata_ConcurrentMergesKeepEveryKey(t *testing.T) {
	a, md, ad := newTestApp(t)
	alice := newBrowser(t, newHandler(a, md, ad))
	aliceID := signUp(t, alice, aliceEmail, "Alice")
	const writers = 8
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := range writers {
		wg.Go(func() {
			key := string(rune('a' + i))
			_, err := md.Merge(context.Background(), aliceID, metadata.Private, json.RawMessage(`{"`+key+`":true}`))
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	all, err := md.Get(context.Background(), aliceID)
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]bool
	if err := json.Unmarshal(all.Private, &keys); err != nil || len(keys) != writers {
		t.Fatalf("private = %s, %v", all.Private, err)
	}
}

// rawBody is a request body sent exactly as written, malformed or not.
type rawBody string

// signUp creates an account with a password and returns its id.
func signUp(t *testing.T, b *browser, identifier, name string) string {
	t.Helper()
	up := post[signUpAnswer](t, b, "/auth/password/sign-up", map[string]string{"identifier": identifier, "password": testPassword, "name": name}, http.StatusOK)
	return up.User.ID
}

// signUpAnswer is the part of the sign-up answer the tests read.
type signUpAnswer struct {
	User auth.UserView `json:"user"`
}

// newTestApp builds the app on a fresh SQLite file.
func newTestApp(t *testing.T, opts ...metadata.Option) (*auth.Auth, *metadata.Plugin, *admin.Plugin) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	a, md, ad, err := newAuth(db, discardMailer{}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a, md, ad
}

// discardMailer drops every mail; these tests send none that matter.
type discardMailer struct{}

// Send drops m.
func (discardMailer) Send(context.Context, email.Mail) error { return nil }

// browser is an HTTPS test server and a client with a cookie jar that sends
// the app's Origin, like a real browser on the app.
type browser struct {
	srv    *httptest.Server
	client *http.Client
}

// newBrowser serves h over TLS, because the session cookie is __Host- and
// Secure.
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

// errorAnswer is the JSON shape of every error the library answers.
type errorAnswer struct {
	Error auth.ErrorInfo `json:"error"`
}

func post[Out, In any](t *testing.T, b *browser, path string, in In, status int) Out {
	t.Helper()
	var out Out
	if err := json.Unmarshal(postRaw(t, b, path, in, status), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func get[Out any](t *testing.T, b *browser, path string, status int) Out {
	t.Helper()
	var out Out
	if err := json.Unmarshal(getRaw(t, b, path, status), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func postErr[In any](t *testing.T, b *browser, path string, in In, status int) auth.ErrorInfo {
	t.Helper()
	return post[errorAnswer](t, b, path, in, status).Error
}

func getErr(t *testing.T, b *browser, path string, status int) auth.ErrorInfo {
	t.Helper()
	return get[errorAnswer](t, b, path, status).Error
}

// postRaw sends in as JSON (a rawBody as written) with the app's Origin and
// returns the body.
func postRaw[In any](t *testing.T, b *browser, path string, in In, status int) []byte {
	t.Helper()
	raw, err := encodeBody(in)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, b.srv.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", baseURL)
	return do(t, b, req, status)
}

// encodeBody is in as JSON, or a rawBody's bytes unchanged.
func encodeBody(in any) ([]byte, error) {
	if r, ok := in.(rawBody); ok {
		return []byte(r), nil
	}
	return json.Marshal(in)
}

// getRaw fetches path and returns the body.
func getRaw(t *testing.T, b *browser, path string, status int) []byte {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, b.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return do(t, b, req, status)
}

// do sends req, checks the status and returns the body.
func do(t *testing.T, b *browser, req *http.Request, status int) []byte {
	t.Helper()
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
	return buf.Bytes()
}
