package oidcclient_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ubgo/auth/oidcclient"
)

// The minimal setup: the login server, the client, the app's origin and a
// sealing secret. Sessions live in a sealed cookie for 7 days, the login
// server is asked again every minute, and every route but the four auth
// routes needs a signed-in person.
func ExampleNew() {
	c, err := oidcclient.New(oidcclient.Config{
		Issuer:        "https://login.example.com",
		ClientID:      "oac_admin",
		ClientSecret:  oidcclient.Secret(os.Getenv("OIDC_CLIENT_SECRET")),
		AppURL:        "https://admin.example.com",
		SessionSecret: oidcclient.Secret(os.Getenv("SESSION_SECRET")), // 32+ random bytes
	})
	if err != nil {
		log.Fatal(err)
	}

	app := http.NewServeMux()
	app.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		u, _ := oidcclient.UserFrom(r.Context())
		fmt.Fprintf(w, "Hello, %s", u.Name)
	})

	root := http.NewServeMux()
	root.Handle(oidcclient.DefaultRoutePrefix+"/", c.Handler()) // /auth/login, /auth/callback, /auth/logout, /auth/backchannel
	root.Handle("/", c.Require(app))
	log.Fatal(http.ListenAndServe(":8080", root))
}

// kvStore is a server-side SessionStore in the shape a Redis or SQL store
// takes: the session is kept under its ID, the cookie carries only the ID,
// and SessionRevoker finds sessions by subject or provider session for
// back-channel logout. A map stands in for the database here.
type kvStore struct {
	mu   sync.Mutex
	rows map[string][]byte // session ID → JSON; a real store sets a TTL from Session.ExpiresAt
}

func (s *kvStore) Save(_ context.Context, sess oidcclient.Session) ([]byte, error) {
	b, err := json.Marshal(sess)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows[sess.ID] = b
	return []byte(sess.ID), nil
}

func (s *kvStore) Load(_ context.Context, cookieValue []byte) (oidcclient.Session, error) {
	s.mu.Lock()
	b, ok := s.rows[string(cookieValue)]
	s.mu.Unlock()
	if !ok {
		return oidcclient.Session{}, oidcclient.ErrNoSession
	}
	var sess oidcclient.Session
	return sess, json.Unmarshal(b, &sess)
}

func (s *kvStore) Delete(_ context.Context, sess oidcclient.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rows, sess.ID)
	return nil
}

func (s *kvStore) RevokeSessions(_ context.Context, t oidcclient.LogoutTarget) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, b := range s.rows {
		var sess oidcclient.Session
		if json.Unmarshal(b, &sess) == nil && t.Matches(sess) {
			delete(s.rows, id)
			n++
		}
	}
	return n, nil
}

// A custom SessionStore keeps sessions on the server, so the cookie
// carries only a sealed session ID and a back-channel logout can end a
// session the browser still holds.
func ExampleWithSessionStore() {
	_, err := oidcclient.New(exampleConfig(), oidcclient.WithSessionStore(&kvStore{rows: map[string][]byte{}}))
	if err != nil {
		log.Fatal(err)
	}
}

// appUsers stands in for the app's own user table.
type appUsers struct {
	mu   sync.Mutex
	byID map[string]string // "iss sub" → app user id
}

// findOrCreate returns the app user id linked to the login server's
// person, creating the row on first sign-in.
func (a *appUsers) findOrCreate(_ context.Context, iss, sub string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	key := iss + " " + sub
	if id, ok := a.byID[key]; ok {
		return id, nil
	}
	id := rand.Text()
	a.byID[key] = id
	return id, nil
}

// The OnLogin hook: refuse an unverified email, link the login server's
// person to the app's own user (created on first sign-in), and take roles
// from the groups claim. Claims are dropped once read, to keep the cookie
// small. It runs again on every refresh that brings a new ID token, so a
// group removed at the server is a role removed here.
func ExampleWithUserMapper() {
	users := &appUsers{byID: map[string]string{}}
	mapUser := func(ctx context.Context, in oidcclient.MapUserRequest) (oidcclient.User, error) {
		if !in.Identity.EmailVerified {
			return oidcclient.User{}, oidcclient.ErrAccessDenied
		}
		u := oidcclient.DefaultUser(in.Identity)
		id, err := users.findOrCreate(ctx, u.Issuer, u.Subject)
		if err != nil {
			return oidcclient.User{}, err // a failure, not a "no": the person sees an error page and may retry
		}
		u.ID = id
		u.Roles, _ = in.Identity.Claims.Strings("groups")
		u.Claims = nil
		return u, nil
	}
	_, err := oidcclient.New(exampleConfig(), oidcclient.WithUserMapper(mapUser))
	if err != nil {
		log.Fatal(err)
	}
}

// roleAdmin is the role the admin area requires.
const roleAdmin = "admin"

// An Authorizer adds the app's own rule to the login server's: here, the
// /admin area needs the admin role. Its zero answer is Deny, and an error
// refuses even with Allow.
func ExampleWithAuthorizer() {
	authorize := func(_ context.Context, in oidcclient.AuthorizeRequest) (oidcclient.Decision, error) {
		if strings.HasPrefix(in.Request.URL.Path, "/admin/") && !slices.Contains(in.User.Roles, roleAdmin) {
			return oidcclient.Deny, nil
		}
		return oidcclient.Allow, nil
	}
	_, err := oidcclient.New(exampleConfig(), oidcclient.WithAuthorizer(authorize))
	if err != nil {
		log.Fatal(err)
	}
}

// A strict outage policy: ask the login server on every request, and
// refuse as soon as it cannot be reached instead of trusting the last
// "yes" for five minutes.
func ExampleWithOutageGrace() {
	_, err := oidcclient.New(exampleConfig(),
		oidcclient.WithRecheckInterval(oidcclient.RecheckEveryRequest),
		oidcclient.WithOutageGrace(oidcclient.NoOutageGrace),
		oidcclient.WithObserver(oidcclient.ObserverFunc(func(_ context.Context, e oidcclient.Event) {
			if e.Kind == oidcclient.EventRefuse && e.Reason == oidcclient.ReasonServerDown {
				log.Printf("login server unreachable: %v", e.Err)
			}
		})),
	)
	if err != nil {
		log.Fatal(err)
	}
}

// Back-channel logout: the login server posts a logout token to
// AppURL + /auth/backchannel when a person signs out there or is removed,
// and the sessions it names end at once, cookie or not. It needs a store
// that can find sessions without their cookie (NewMemoryStore here; Redis
// or SQL across instances). With it, the periodic re-check can stay as the
// safety net, or be turned off with RecheckBackchannelOnly.
func ExampleClient_BackchannelHandler() {
	c, err := oidcclient.New(exampleConfig(),
		oidcclient.WithSessionStore(oidcclient.NewMemoryStore()),
		oidcclient.WithRecheckInterval(5*time.Minute), // back-channel ends sessions at once; the re-check is the net
	)
	if err != nil {
		log.Fatal(err)
	}
	// Register https://admin.example.com/auth/backchannel as the client's
	// backchannel_logout_uri at the login server. Handler serves it; an app
	// that mounts routes one by one mounts it on its own.
	mux := http.NewServeMux()
	mux.Handle("POST "+oidcclient.PathsUnder(oidcclient.DefaultRoutePrefix).Backchannel, c.BackchannelHandler())
}

// exampleConfig is the Config the examples share.
func exampleConfig() oidcclient.Config {
	return oidcclient.Config{
		Issuer: "https://login.example.com", ClientID: "oac_admin", AppURL: "https://admin.example.com",
		ClientSecret: oidcclient.Secret(os.Getenv("OIDC_CLIENT_SECRET")), SessionSecret: oidcclient.Secret(os.Getenv("SESSION_SECRET")),
	}
}

// exampleRunnableConfig is a Config the runnable examples use: they make
// no call to the login server, because nobody in them is signed in.
func exampleRunnableConfig() oidcclient.Config {
	return oidcclient.Config{
		Issuer: "https://login.example.com", ClientID: "oac_admin", ClientSecret: "example-only", AppURL: "https://admin.example.com",
		SessionSecret: "example-only-session-secret-0123456789",
	}
}

// Require answers a person who is not signed in by what they asked for: a
// page is redirected to the login route (which comes back to the page), an
// API call gets 401 with the login URL in JSON for the SPA to follow.
func ExampleClient_Require() {
	c, err := oidcclient.New(exampleRunnableConfig())
	if err != nil {
		log.Fatal(err)
	}
	h := c.Require(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "secret page") }))

	page := httptest.NewRequest(http.MethodGet, "/reports?month=11", nil)
	page.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, page)
	fmt.Println(rec.Code, rec.Header().Get("Location"))

	api := httptest.NewRequest(http.MethodGet, "/api/reports", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, api)
	fmt.Print(rec.Code, " ", rec.Body.String())
	// Output:
	// 302 /auth/login?return_to=%2Freports%3Fmonth%3D11
	// 401 {"error":"login_required","login_url":"/auth/login?return_to=%2Fapi%2Freports"}
}

// Optional serves pages anyone may see and that show more to a signed-in
// person. It makes the same decision as Require but never refuses: without
// a live, re-checked session the page simply gets no User.
func ExampleClient_Optional() {
	c, err := oidcclient.New(exampleRunnableConfig())
	if err != nil {
		log.Fatal(err)
	}
	home := c.Optional(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, ok := oidcclient.UserFrom(r.Context()); ok {
			fmt.Fprintf(w, "Signed in as %s", u.Name)
			return
		}
		fmt.Fprint(w, "Welcome, guest")
	}))
	rec := httptest.NewRecorder()
	home.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	fmt.Println(rec.Code, rec.Body.String())
	// Output: 200 Welcome, guest
}

// ReturnToAllowed lands sign-ins only on listed pages; anything else goes
// to the first. Whatever a policy answers is still held to the same-site
// floor, so a policy can narrow the landing page but never open a redirect.
func ExampleReturnToAllowed() {
	policy := oidcclient.ReturnToAllowed("/dashboard", "/reports")
	for _, requested := range []string{"/reports?month=11", "/admin", "//evil.example"} {
		fmt.Println(policy(oidcclient.ReturnRequest{Requested: requested}))
	}
	// Output:
	// /reports?month=11
	// /dashboard
	// /dashboard
}
