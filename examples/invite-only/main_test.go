package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/invite"
)

const (
	bobEmail     = "bob@example.com"
	carolEmail   = "carol@example.com"
	daveEmail    = "dave@example.com"
	testPassword = "another horse battery staple"
	// publicUses is how many sign-ups the owner's shared link allows.
	publicUses = 1
)

// TestInviteOnly_SignUpNeedsAnInvite walks the whole life of an invite-only
// app: a sign-up without an invite is refused; the owner shares a one-use
// link, Bob opens it signed out and signs up through the cookie; Dave's later
// sign-up with the spent link is refused and leaves no account; a private
// invite mailed to Carol gives her the editor role; a member may invite but
// not hand out a role; the owner lists and cancels invites.
func TestInviteOnly_SignUpNeedsAnInvite(t *testing.T) {
	x, mail := newTestApp(t)
	h := x.handler()

	// No invite: 403 invite.required, and no account.
	stranger := newBrowser(t, h)
	if e := post[errorAnswer](t, stranger, "/auth/password/sign-up", signUp(bobEmail, "Bob"), nil, http.StatusForbidden); e.Error.Code != invite.ErrRequired.Code {
		t.Fatalf("sign-up without an invite: %+v", e.Error)
	}

	// The owner, created from Go, signs in and shares a one-use member link.
	owner := newBrowser(t, h)
	post[json.RawMessage](t, owner, "/auth/password/sign-in", fields{"identifier": ownerEmail, "password": ownerPassword}, nil, http.StatusOK)
	link := post[invite.Created](t, owner, "/auth/invite/create", invite.Request{Role: string(RoleMember), MaxUses: publicUses}, nil, http.StatusOK)
	// Over HTTP the token field reads "[redacted]", as every auth.Token in a
	// JSON answer does; the link is the value to share.
	linkToken := tokenOf(t, link.URL)

	// Bob opens the link signed out: the page shows the invite, activate
	// parks it in a cookie, and his sign-up spends it.
	bob := newBrowser(t, h)
	v := get[invite.View](t, bob, "/auth/invite/get?token="+url.QueryEscape(linkToken), nil, http.StatusOK)
	if v.InviterName != ownerName || v.Role != string(RoleMember) || v.Private {
		t.Fatalf("view = %+v", v)
	}
	act := post[invite.ActivateResult](t, bob, "/auth/invite/activate", fields{"token": linkToken}, nil, http.StatusOK)
	if act.Action != invite.ActionSignInRequired {
		t.Fatalf("activate signed out = %+v", act)
	}
	post[json.RawMessage](t, bob, "/auth/password/sign-up", signUp(bobEmail, "Bob"), nil, http.StatusOK)
	if me := get[meResponse](t, bob, "/me", nil, http.StatusOK); me.Role != RoleMember {
		t.Fatalf("bob /me = %+v", me)
	}

	// Dave brings the spent link in the header: the sign-up is refused and
	// rolled back, so his address is still free.
	dave := newBrowser(t, h)
	hdr := http.Header{invite.InviteHeader: {linkToken}}
	if e := post[errorAnswer](t, dave, "/auth/password/sign-up", signUp(daveEmail, "Dave"), hdr, http.StatusBadRequest); e.Error.Code != invite.ErrInvalid.Code {
		t.Fatalf("sign-up with a spent invite: %+v", e.Error)
	}
	if e := post[errorAnswer](t, dave, "/auth/password/sign-in", fields{"identifier": daveEmail, "password": testPassword}, nil, http.StatusUnauthorized); e.Error.Code == "" {
		t.Fatal("dave signed in after a refused sign-up")
	}

	// A private invite goes by mail, never in the answer, and carries a role.
	priv := post[invite.Created](t, owner, "/auth/invite/create", invite.Request{Email: carolEmail, Role: string(RoleEditor)}, nil, http.StatusOK)
	if priv.URL != "" {
		t.Fatalf("a private invite leaked its token: %+v", priv)
	}
	// The invite mail goes out in the background; wait for the send to finish
	// instead of racing it.
	x.auth.WaitDeliveries()
	carolToken := mail.tokenFor(t, carolEmail)
	carol := newBrowser(t, h)
	post[json.RawMessage](t, carol, "/auth/password/sign-up", signUp(carolEmail, "Carol"), http.Header{invite.InviteHeader: {carolToken}}, http.StatusOK)
	if me := get[meResponse](t, carol, "/me", nil, http.StatusOK); me.Role != RoleEditor {
		t.Fatalf("carol /me = %+v", me)
	}

	// A member may invite with no role, never with one; nobody grants owner.
	if e := post[errorAnswer](t, bob, "/auth/invite/create", invite.Request{Role: string(RoleEditor)}, nil, http.StatusForbidden); e.Error.Code != invite.ErrForbidden.Code {
		t.Fatalf("member granting a role: %+v", e.Error)
	}
	post[invite.Created](t, bob, "/auth/invite/create", invite.Request{}, nil, http.StatusOK)
	if e := post[errorAnswer](t, owner, "/auth/invite/create", invite.Request{Role: string(RoleOwner)}, nil, http.StatusForbidden); e.Error.Code != invite.ErrForbidden.Code {
		t.Fatalf("owner granting owner: %+v", e.Error)
	}

	// The owner sees their two invites, both used up, and none of the tokens.
	list := get[invite.ListResult](t, owner, "/auth/invite/list", nil, http.StatusOK)
	if list.Total != 2 {
		t.Fatalf("owner's invites = %+v", list)
	}
	for _, inv := range list.Invites {
		if inv.Status != invite.StatusUsed || inv.Uses != 1 {
			t.Fatalf("invite after use = %+v", inv)
		}
	}

	// A canceled invite stops working at once.
	spare := post[invite.Created](t, owner, "/auth/invite/create", invite.Request{}, nil, http.StatusOK)
	post[auth.Done](t, owner, "/auth/invite/cancel", invite.IDRequest{ID: spare.ID}, nil, http.StatusOK)
	if e := get[errorAnswer](t, stranger, "/auth/invite/get?token="+url.QueryEscape(tokenOf(t, spare.URL)), nil, http.StatusBadRequest); e.Error.Code != invite.ErrInvalid.Code {
		t.Fatalf("canceled invite: %+v", e.Error)
	}
}

// TestInviteOnly_SeedOwnerTwice: running the program again finds the owner's
// address taken and creates nothing, because the seed is one transaction.
func TestInviteOnly_SeedOwnerTwice(t *testing.T) {
	x, _ := newTestApp(t)
	if err := x.seedOwner(context.Background()); err == nil {
		t.Fatal("a second seed succeeded")
	}
	var n int
	if err := x.db.QueryRow(`SELECT COUNT(*) FROM app_member`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("members after a second seed = %d %v", n, err)
	}
}

// signUp is a password sign-up body.
func signUp(addr, name string) fields {
	return fields{"identifier": addr, "password": testPassword, "name": name}
}

// newTestApp builds the app on a fresh SQLite file, seeds the owner, and
// records mail instead of printing it.
func newTestApp(t *testing.T) (*app, *mailbox) {
	t.Helper()
	ctx := context.Background()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.ExecContext(ctx, memberSchema); err != nil {
		t.Fatal(err)
	}
	mail := &mailbox{}
	x, err := newApp(db, mail)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = x.auth.Close() })
	if _, err := x.auth.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := x.seedOwner(ctx); err != nil {
		t.Fatal(err)
	}
	return x, mail
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

// tokenFor returns the invite token of the last mail to addr, read from the
// link in its text the way a person would click it.
func (m *mailbox) tokenFor(t *testing.T, addr string) string {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.sent) - 1; i >= 0; i-- {
		if m.sent[i].To != addr {
			continue
		}
		for _, word := range strings.Fields(m.sent[i].Text) {
			if strings.HasPrefix(word, baseURL+invite.DefaultPage+"?") {
				return tokenOf(t, word)
			}
		}
	}
	t.Fatalf("no invite mailed to %s", addr)
	return ""
}

// tokenOf reads the token out of an invite link, as the invite page does.
func tokenOf(t *testing.T, link string) string {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil || u.Path != invite.DefaultPage || u.Query().Get("token") == "" {
		t.Fatalf("not an invite link: %q (%v)", link, err)
	}
	return u.Query().Get("token")
}

// browser is an HTTPS test server and a client with a cookie jar that sends
// the Origin a page of the app would, like a real browser on the app.
type browser struct {
	srv    *httptest.Server
	client *http.Client
	origin string
}

// newBrowser serves h over TLS, because the session and invite cookies are
// __Host- and Secure, and a cookie jar keeps such a cookie only for https.
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

// fields is a JSON request body as a client writes it.
type fields map[string]string

// errorAnswer is the JSON shape of every error the library answers.
type errorAnswer struct {
	Error auth.ErrorInfo `json:"error"`
}

// post sends in as JSON with the browser's Origin and extra headers, checks
// the status and decodes the answer as Out.
func post[Out, In any](t *testing.T, b *browser, path string, in In, extra http.Header, status int) Out {
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
	return do[Out](t, b, req, extra, status)
}

// get fetches path, checks the status and decodes the answer as Out.
func get[Out any](t *testing.T, b *browser, path string, extra http.Header, status int) Out {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, b.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return do[Out](t, b, req, extra, status)
}

// do sends req with extra headers, checks the status and decodes the answer.
func do[Out any](t *testing.T, b *browser, req *http.Request, extra http.Header, status int) Out {
	t.Helper()
	for k, vs := range extra {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
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
