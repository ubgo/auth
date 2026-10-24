package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authcli"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/audit"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
)

const (
	aliceEmail   = "alice@example.com"
	bobEmail     = "bob@example.com"
	carolEmail   = "carol@example.com"
	testPassword = "correct horse battery staple"
	// newPassword is what the admin sets for Bob.
	newPassword = "a brand new passphrase"
	// supportMinutes is the impersonation length an admin asks for; the
	// library caps it at auth.MaxImpersonationTTL.
	supportMinutes = 600
)

// TestAdminOps_GrantFindRevokeAndSetAdmin: the first admin comes from the
// grant command and needs a verified address; an admin finds a user by
// address or id, ends their sessions, and grants and removes admin rights,
// never leaving the app without one.
func TestAdminOps_GrantFindRevokeAndSetAdmin(t *testing.T) {
	a, ad, box := newTestApp(t)
	h := newHandler(a)
	ctx := context.Background()

	alice := newBrowser(t, h)
	aliceUp := post[password.SignInResult](t, alice, "/auth/password/sign-up", fields{"identifier": aliceEmail, "password": testPassword, "name": "Alice"}, http.StatusOK)
	if _, err := grantByEmail(ctx, a, ad, aliceEmail); !errors.Is(err, auth.ErrIdentityNotFound) {
		t.Fatalf("grant to an unverified address: %v, want ErrIdentityNotFound", err)
	}
	post[none](t, alice, "/auth/email/verify", fields{"token": box.lastToken(t, a, aliceEmail)}, http.StatusOK)
	if id, err := grantByEmail(ctx, a, ad, aliceEmail); err != nil || id != aliceUp.User.ID {
		t.Fatalf("grant = %q, %v", id, err)
	}

	bob := newBrowser(t, h)
	bobUp := post[password.SignInResult](t, bob, "/auth/password/sign-up", fields{"identifier": bobEmail, "password": testPassword, "name": "Bob"}, http.StatusOK)
	if e := get[errorAnswer](t, bob, "/auth/admin/users", http.StatusForbidden); e.Error.Code != admin.ErrForbidden.Code {
		t.Fatalf("non-admin listing: %+v", e.Error)
	}

	// Finding users: a page, an exact address, a user id; never a fragment.
	page := get[admin.UsersResult](t, alice, "/auth/admin/users?limit=1", http.StatusOK)
	if page.Total != 2 || len(page.Users) != 1 || page.Limit != 1 || page.Page != 1 {
		t.Fatalf("page = %+v", page)
	}
	if found := get[admin.UsersResult](t, alice, "/auth/admin/users?query="+url.QueryEscape(" Bob@Example.com "), http.StatusOK); found.Total != 1 || found.Users[0].ID != bobUp.User.ID {
		t.Fatalf("search by address = %+v", found)
	}
	if found := get[admin.UsersResult](t, alice, "/auth/admin/users?query="+bobUp.User.ID, http.StatusOK); found.Total != 1 || found.Users[0].Name != "Bob" {
		t.Fatalf("search by id = %+v", found)
	}
	if part := get[admin.UsersResult](t, alice, "/auth/admin/users?query=bob", http.StatusOK); part.Total != 0 {
		t.Fatalf("a fragment must match nothing: %+v", part)
	}
	// A fragment goes to search-users: email by default, case ignored; a
	// name keeps its case; % is text.
	if hit := get[admin.UsersResult](t, alice, "/auth/admin/search-users?value=BOB", http.StatusOK); hit.Total != 1 || hit.Users[0].ID != bobUp.User.ID {
		t.Fatalf("email fragment = %+v", hit)
	}
	if hit := get[admin.UsersResult](t, alice, "/auth/admin/search-users?field=name&operator=starts_with&value=bo", http.StatusOK); hit.Total != 0 {
		t.Fatalf("name keeps case = %+v", hit)
	}
	if hit := get[admin.UsersResult](t, alice, "/auth/admin/search-users?value="+url.QueryEscape("%"), http.StatusOK); hit.Total != 0 {
		t.Fatalf("%% is text = %+v", hit)
	}
	if e := get[errorAnswer](t, bob, "/auth/admin/search-users?value=bob", http.StatusForbidden); e.Error.Code != admin.ErrForbidden.Code {
		t.Fatalf("non-admin search = %+v", e)
	}
	detail := get[admin.UserDetail](t, alice, "/auth/admin/user?userId="+bobUp.User.ID, http.StatusOK)
	if detail.User.ID != bobUp.User.ID || detail.Sessions != 1 || len(detail.Identities) != 1 || detail.Identities[0].Verified {
		t.Fatalf("detail = %+v", detail)
	}
	if e := get[errorAnswer](t, alice, "/auth/admin/user?userId=usr_doesnotexist", http.StatusNotFound); e.Error.Code != auth.ErrUserNotFound.Code {
		t.Fatalf("unknown user: %+v", e.Error)
	}

	// Revoking ends Bob's session but does not ban him.
	post[auth.Done](t, alice, "/auth/admin/revoke-sessions", admin.UserRequest{UserID: bobUp.User.ID}, http.StatusOK)
	get[errorAnswer](t, bob, "/me", http.StatusUnauthorized)
	post[none](t, bob, "/auth/password/sign-in", fields{"identifier": bobEmail, "password": testPassword}, http.StatusOK)
	get[meResponse](t, bob, "/me", http.StatusOK)

	// Admin rights: the last admin stays; a second admin can then be removed.
	if e := post[errorAnswer](t, alice, "/auth/admin/set-admin", admin.SetAdminRequest{UserID: aliceUp.User.ID, Admin: false}, http.StatusConflict); e.Error.Code != admin.ErrLastAdmin.Code {
		t.Fatalf("removing the last admin: %+v", e.Error)
	}
	post[auth.Done](t, alice, "/auth/admin/set-admin", admin.SetAdminRequest{UserID: bobUp.User.ID, Admin: true}, http.StatusOK)
	if d := get[admin.UserDetail](t, bob, "/auth/admin/user?userId="+aliceUp.User.ID, http.StatusOK); !d.User.Admin {
		t.Fatalf("bob, now an admin, sees alice as %+v", d.User)
	}
	if e := post[errorAnswer](t, alice, "/auth/admin/ban", admin.BanRequest{UserID: bobUp.User.ID, Reason: "test"}, http.StatusConflict); e.Error.Code != admin.ErrAdminTarget.Code {
		t.Fatalf("banning an admin: %+v", e.Error)
	}
	post[auth.Done](t, alice, "/auth/admin/set-admin", admin.SetAdminRequest{UserID: bobUp.User.ID, Admin: false}, http.StatusOK)
	if e := get[errorAnswer](t, bob, "/auth/admin/users", http.StatusForbidden); e.Error.Code != admin.ErrForbidden.Code {
		t.Fatalf("bob after losing admin: %+v", e.Error)
	}
}

// TestAdminOps_ImpersonationIsLimitedVisibleAndStoppable: an admin acts as
// Bob for support. The session is capped at an hour, Bob sees it in his own
// session list, it cannot change anything that proves Bob's identity, and
// stopping it ends it.
func TestAdminOps_ImpersonationIsLimitedVisibleAndStoppable(t *testing.T) {
	a, ad, box := newTestApp(t)
	h := newHandler(a)
	ctx := context.Background()

	alice := newBrowser(t, h)
	post[none](t, alice, "/auth/password/sign-up", fields{"identifier": aliceEmail, "password": testPassword, "name": "Alice"}, http.StatusOK)
	post[none](t, alice, "/auth/email/verify", fields{"token": box.lastToken(t, a, aliceEmail)}, http.StatusOK)
	aliceID, err := grantByEmail(ctx, a, ad, aliceEmail)
	if err != nil {
		t.Fatal(err)
	}
	bob := newBrowser(t, h)
	bobUp := post[password.SignInResult](t, bob, "/auth/password/sign-up", fields{"identifier": bobEmail, "password": testPassword, "name": "Bob"}, http.StatusOK)

	if e := post[errorAnswer](t, alice, "/auth/admin/impersonate", admin.ImpersonateRequest{UserID: aliceID}, http.StatusConflict); e.Error.Code != admin.ErrAdminTarget.Code {
		t.Fatalf("impersonating an admin: %+v", e.Error)
	}
	before := time.Now()
	as := post[admin.ImpersonateResult](t, alice, "/auth/admin/impersonate", admin.ImpersonateRequest{UserID: bobUp.User.ID, Minutes: supportMinutes}, http.StatusOK)
	if as.User.ID != bobUp.User.ID || as.ExpiresAt.Sub(before) > auth.MaxImpersonationTTL+time.Minute {
		t.Fatalf("impersonation = %+v, want bob for at most %v", as, auth.MaxImpersonationTTL)
	}
	// The cookie in Alice's browser is now Bob's impersonation session.
	if me := get[meResponse](t, alice, "/me", http.StatusOK); me.Name != "Bob" {
		t.Fatalf("acting as %+v", me)
	}
	if e := post[errorAnswer](t, alice, "/auth/password/change", fields{"current": testPassword, "new": "hijacked passphrase"}, http.StatusForbidden); e.Error.Code != auth.ErrImpersonationRefused.Code {
		t.Fatalf("password change while impersonating: %+v", e.Error)
	}
	if e := get[errorAnswer](t, alice, "/auth/admin/users", http.StatusForbidden); e.Error.Code != admin.ErrForbidden.Code {
		t.Fatalf("admin routes as bob: %+v", e.Error)
	}
	seen := false
	for _, s := range get[auth.SessionsResult](t, bob, "/auth/sessions", http.StatusOK).Sessions {
		seen = seen || s.Impersonated
	}
	if !seen {
		t.Fatal("bob's session list must show the impersonation")
	}

	// Stopping gives Alice her own session back: the admin token was kept
	// in the flow cookie and is re-issued; it is not fresh, because it is
	// the same session as before.
	if r := post[admin.StopResult](t, alice, "/auth/admin/stop-impersonating", none{}, http.StatusOK); !r.OK || !r.Restored {
		t.Fatalf("stop = %+v", r)
	}
	if me := get[meResponse](t, alice, "/me", http.StatusOK); me.Name != "Alice" {
		t.Fatalf("after stopping, acting as %+v", me)
	}
	if e := post[errorAnswer](t, bob, "/auth/admin/stop-impersonating", none{}, http.StatusConflict); e.Error.Code != admin.ErrNotImpersonating.Code {
		t.Fatalf("stop on an ordinary session: %+v", e.Error)
	}
}

// newTestApp builds the app on a fresh SQLite file with a recording mailbox.
func newTestApp(t *testing.T) (*auth.Auth, *admin.Plugin, *mailbox) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	box := &mailbox{}
	a, ad, err := newAuth(db, box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a, ad, box
}

// mailbox records every mail sent.
type mailbox struct {
	mu   sync.Mutex
	sent []email.Mail
}

// Send records m.
func (m *mailbox) Send(_ context.Context, mail email.Mail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, mail)
	return nil
}

// lastToken returns the token of the newest link mailed to addr. Mail goes
// out after the transaction commits, so it waits for deliveries first.
func (m *mailbox) lastToken(t *testing.T, a *auth.Auth, addr string) string {
	t.Helper()
	a.WaitDeliveries()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.sent) - 1; i >= 0; i-- {
		if m.sent[i].To != addr {
			continue
		}
		for _, field := range strings.Fields(m.sent[i].Text) {
			if u, err := url.Parse(field); err == nil && u.Query().Get("token") != "" {
				return u.Query().Get("token")
			}
		}
	}
	t.Fatalf("no link mailed to %s", addr)
	return ""
}

// browser is an HTTPS test server and a client with a cookie jar that sends
// the Origin a page of the app would, like a real browser on the app.
type browser struct {
	srv    *httptest.Server
	client *http.Client
	origin string
}

// newBrowser serves h over TLS, because the session cookie is __Host- and
// Secure, and a cookie jar keeps such a cookie only for an https URL.
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
	return &browser{srv: srv, client: client, origin: baseURL}
}

// fields is a JSON request body as a client writes it. The library's own
// request types are not used to send a secret: auth.Token and password.Secret
// encode as "[redacted]" on purpose, so a logged struct never leaks one.
type fields map[string]string

// none is the request body of a route that takes no input, and the answer
// of a call whose body the test does not read.
type none struct{}

// errorAnswer is the JSON shape of every error the library answers.
type errorAnswer struct {
	Error auth.ErrorInfo `json:"error"`
}

// post sends in as JSON with the browser's Origin, checks the status and
// decodes the answer as Out.
func post[Out, In any](t *testing.T, b *browser, path string, in In, status int) Out {
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
	req.Header.Set("Origin", b.origin)
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

// TestAdminOps_CreateUserBanMessageAndAuditLog: an admin creates a user who
// signs in at once, sets another user's password, bans a user who then reads
// the app's message at sign-in (and only after proving the password), and
// reads the audit log of all of it.
func TestAdminOps_CreateUserBanMessageAndAuditLog(t *testing.T) {
	a, ad, box := newTestApp(t)
	h := newHandler(a)
	ctx := context.Background()

	alice := newBrowser(t, h)
	post[none](t, alice, "/auth/password/sign-up", fields{"identifier": aliceEmail, "password": testPassword, "name": "Alice"}, http.StatusOK)
	post[none](t, alice, "/auth/email/verify", fields{"token": box.lastToken(t, a, aliceEmail)}, http.StatusOK)
	aliceID, err := grantByEmail(ctx, a, ad, aliceEmail)
	if err != nil {
		t.Fatal(err)
	}
	bob := newBrowser(t, h)
	bobUp := post[password.SignInResult](t, bob, "/auth/password/sign-up", fields{"identifier": bobEmail, "password": testPassword, "name": "Bob"}, http.StatusOK)

	// Create: a weak password is refused by the password plugin and leaves no
	// user; a good one makes a user who signs in at once.
	if e := post[errorAnswer](t, alice, "/auth/admin/create-user", fields{"name": "Carol", "email": carolEmail, "password": "short"}, http.StatusBadRequest); e.Error.Code != password.ErrTooShort.Code {
		t.Fatalf("weak password on create: %+v", e.Error)
	}
	carol := post[admin.CreateUserResult](t, alice, "/auth/admin/create-user", map[string]any{"name": "Carol", "email": carolEmail, "verified": true, "password": testPassword}, http.StatusOK)
	if carol.User.Name != "Carol" {
		t.Fatalf("created = %+v", carol)
	}
	carolBrowser := newBrowser(t, h)
	post[none](t, carolBrowser, "/auth/password/sign-in", fields{"identifier": carolEmail, "password": testPassword}, http.StatusOK)
	if me := get[meResponse](t, carolBrowser, "/me", http.StatusOK); me.ID != carol.User.ID {
		t.Fatalf("carol's /me = %+v", me)
	}

	// Set password: Bob's session ends and the new password works.
	post[auth.Done](t, alice, "/auth/admin/set-password", fields{"userId": bobUp.User.ID, "password": newPassword}, http.StatusOK)
	get[errorAnswer](t, bob, "/me", http.StatusUnauthorized)
	post[none](t, bob, "/auth/password/sign-in", fields{"identifier": bobEmail, "password": newPassword}, http.StatusOK)
	if e := post[errorAnswer](t, alice, "/auth/admin/set-password", fields{"userId": aliceID, "password": newPassword}, http.StatusConflict); e.Error.Code != admin.ErrAdminTarget.Code {
		t.Fatalf("setting an admin's password: %+v", e.Error)
	}

	// Ban: with the right password Bob reads why; with a wrong one he gets
	// the ordinary answer, as would anyone guessing at any account.
	post[auth.Done](t, alice, "/auth/admin/ban", admin.BanRequest{UserID: bobUp.User.ID, Reason: "chargeback"}, http.StatusOK)
	if e := post[errorAnswer](t, bob, "/auth/password/sign-in", fields{"identifier": bobEmail, "password": newPassword}, http.StatusForbidden); e.Error.Code != admin.ErrBanned.Code || e.Error.Message != "Your account is suspended: chargeback." {
		t.Fatalf("banned sign-in: %+v", e.Error)
	}
	if e := post[errorAnswer](t, bob, "/auth/password/sign-in", fields{"identifier": bobEmail, "password": "not it"}, http.StatusUnauthorized); e.Error.Code != password.ErrInvalidCredentials.Code {
		t.Fatalf("wrong password for a banned user must not reveal the ban: %+v", e.Error)
	}

	// The audit log: everything about Bob by id (the ban is newest), then
	// every attempt at his address (the two refused sign-ins, newest first,
	// which carry no user id because an attempt at an unknown address must
	// look the same); admins only.
	about := get[audit.Page](t, alice, "/auth/admin/audit?userId="+bobUp.User.ID+"&limit=1", http.StatusOK)
	if len(about.Events) != 1 || about.Total < 4 {
		t.Fatalf("audit page = %+v", about)
	}
	if e := about.Events[0]; e.Op != admin.EndpointBan || !e.OK || e.ActorID != aliceID || e.SubjectID != bobUp.User.ID {
		t.Fatalf("ban event = %+v", e)
	}
	attempts := get[audit.Page](t, alice, "/auth/admin/audit?identifier="+bobEmail+"&op="+string(password.EndpointSignIn)+"&limit=2", http.StatusOK)
	if len(attempts.Events) != 2 {
		t.Fatalf("attempts = %+v", attempts)
	}
	if e := attempts.Events[0]; e.OK || e.Code != password.ErrInvalidCredentials.Code || e.Identifier != bobEmail || e.ActorID != "" {
		t.Fatalf("newest attempt = %+v", e)
	}
	if e := attempts.Events[1]; e.OK || e.Code != admin.ErrBanned.Code || e.Identifier != bobEmail {
		t.Fatalf("banned attempt = %+v", e)
	}
	if e := get[errorAnswer](t, carolBrowser, "/auth/admin/audit", http.StatusForbidden); e.Error.Code != admin.ErrForbidden.Code {
		t.Fatalf("non-admin reading the log: %+v", e.Error)
	}
}

// TestAdminOps_AuthAdminCommands: the `auth` word hands the command line to
// authcli, whose `admin create` makes the first admin in one go and whose
// `admin grant` does what the grant command does, with exit codes a script
// can branch on.
func TestAdminOps_AuthAdminCommands(t *testing.T) {
	a, _, box := newTestApp(t)
	h := newHandler(a)
	ctx := context.Background()
	run := func(stdin string, args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		code := authcli.MainWithStdin(ctx, a, args, strings.NewReader(stdin), &out, &errOut)
		return code, out.String(), errOut.String()
	}
	code, out, errOut := run(testPassword+"\n", "admin", "create", "--email", carolEmail, "--name", "Carol", "--password-stdin")
	if code != authcli.ExitOK || !strings.HasPrefix(out, "created "+carolEmail+" (") || errOut != "" {
		t.Fatalf("create: %d %q %q", code, out, errOut)
	}
	carol := newBrowser(t, h)
	post[password.SignInResult](t, carol, "/auth/password/sign-in", fields{"identifier": carolEmail, "password": testPassword}, http.StatusOK)
	if page := get[admin.UsersResult](t, carol, "/auth/admin/users", http.StatusOK); page.Total != 1 {
		t.Fatalf("the created admin cannot list users: %+v", page)
	}

	alice := newBrowser(t, h)
	post[password.SignInResult](t, alice, "/auth/password/sign-up", fields{"identifier": aliceEmail, "password": testPassword, "name": "Alice"}, http.StatusOK)
	if code, _, errOut := run("", "admin", "grant", "--email", aliceEmail); code != authcli.ExitFailed || !strings.Contains(errOut, auth.ErrIdentityNotFound.Error()) {
		t.Fatalf("grant to an unverified address: %d %q", code, errOut)
	}
	post[none](t, alice, "/auth/email/verify", fields{"token": box.lastToken(t, a, aliceEmail)}, http.StatusOK)
	if code, out, _ := run("", "admin", "grant", "--email", aliceEmail); code != authcli.ExitOK || !strings.HasSuffix(out, "is an admin\n") {
		t.Fatalf("grant: %d %q", code, out)
	}
	if page := get[admin.UsersResult](t, alice, "/auth/admin/users", http.StatusOK); page.Total != 2 {
		t.Fatalf("the granted admin cannot list users: %+v", page)
	}
}
