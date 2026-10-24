package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
)

const (
	testBase    = "ou=people,dc=example,dc=com"
	testUserDN  = "uid=ada,ou=people,dc=example,dc=com"
	testPass    = "correct horse"
	serviceDN   = "cn=svc,dc=example,dc=com"
	servicePass = "svc-secret"
)

// fakeConn is a directory with one user, ada, that records every call. An
// optional delay per call stands in for the network round trip, so the
// timing test measures work, not Go overhead.
type fakeConn struct {
	mu        sync.Mutex
	calls     []string
	filters   []string
	delay     time.Duration
	entries   int // entries a search for ada returns; default 1
	searchErr error
	bindErr   error // returned by the user bind when set
	svcErr    error
	tlsErr    error // returned by StartTLS when set
	closed    bool
	// hang makes a search wait until Close, as a stalled server would; the
	// connection's Close is what lets the call go.
	hang    bool
	release chan struct{}
}

func (f *fakeConn) record(c string) {
	f.mu.Lock()
	f.calls = append(f.calls, c)
	f.mu.Unlock()
	time.Sleep(f.delay)
}

func (f *fakeConn) StartTLS(*tls.Config) error { f.record("starttls"); return f.tlsErr }

func (f *fakeConn) Bind(dn, password string) error {
	f.record("bind " + dn)
	switch {
	case dn == serviceDN:
		if f.svcErr != nil {
			return f.svcErr
		}
		if password != servicePass {
			return goldap.NewError(goldap.LDAPResultInvalidCredentials, errors.New("svc"))
		}
		return nil
	case dn == testUserDN && f.bindErr != nil:
		return f.bindErr
	case dn == testUserDN && password == testPass:
		return nil
	}
	return goldap.NewError(goldap.LDAPResultInvalidCredentials, errors.New("invalid credentials"))
}

func (f *fakeConn) Search(r *goldap.SearchRequest) (*goldap.SearchResult, error) {
	f.record("search")
	f.mu.Lock()
	f.filters = append(f.filters, r.Filter)
	f.mu.Unlock()
	if f.hang {
		<-f.release
		return nil, errors.New("connection closed")
	}
	if f.searchErr != nil {
		return nil, f.searchErr
	}
	if r.Filter != "(&(objectClass=person)(uid=ada))" {
		return &goldap.SearchResult{}, nil
	}
	n := f.entries
	if n == 0 {
		n = 1
	}
	if n > 1 {
		return &goldap.SearchResult{Entries: []*goldap.Entry{{DN: testUserDN}}}, goldap.NewError(goldap.LDAPResultSizeLimitExceeded, errors.New("size limit"))
	}
	e := goldap.NewEntry(testUserDN, map[string][]string{"mail": {"ada@example.com"}, "cn": {"Ada Lovelace"}, "entryUUID": {"5f1c-ada"}})
	return &goldap.SearchResult{Entries: []*goldap.Entry{e}}, nil
}

func (f *fakeConn) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.hang && !f.closed {
		close(f.release)
	}
	f.closed = true
	return nil
}

func (f *fakeConn) binds() int {
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, "bind ") {
			n++
		}
	}
	return n
}

func testClient(t *testing.T, f *fakeConn, mutate ...func(*Config)) *Client {
	t.Helper()
	cfg := Config{URL: "ldaps://ldap.example.com", BaseDN: testBase, BindDN: serviceDN, BindPassword: servicePass}
	for _, m := range mutate {
		m(&cfg)
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.dialer = func(context.Context) (conn, error) { return f, nil }
	return c
}

// TestNewClient_RefusesUnsafeConfigs: a configuration that would send
// passwords in clear text, or could never find a user, fails at
// construction, not at the first sign-in.
func TestNewClient_RefusesUnsafeConfigs(t *testing.T) {
	ok := Config{URL: "ldaps://ldap.example.com", BaseDN: testBase}
	cases := map[string]struct {
		mutate func(*Config)
		want   error
	}{
		"plain ldap":           {func(c *Config) { c.URL = "ldap://ldap.example.com" }, ErrInsecure},
		"ldaps with starttls":  {func(c *Config) { c.StartTLS = true }, ErrConfigTLS},
		"http url":             {func(c *Config) { c.URL = "http://ldap.example.com" }, ErrConfigURL},
		"no host":              {func(c *Config) { c.URL = "ldaps://" }, ErrConfigURL},
		"path":                 {func(c *Config) { c.URL = "ldaps://ldap.example.com/dc=x" }, ErrConfigURL},
		"no base":              {func(c *Config) { c.BaseDN = " " }, ErrConfigBaseDN},
		"filter without user":  {func(c *Config) { c.UserFilter = "(uid=ada)" }, ErrConfigFilter},
		"bind dn, no password": {func(c *Config) { c.BindDN = serviceDN }, ErrConfigBindPassword},
	}
	for name, tc := range cases {
		cfg := ok
		tc.mutate(&cfg)
		if _, err := NewClient(cfg); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	for name, cfg := range map[string]Config{
		"ldaps":          ok,
		"starttls":       {URL: "ldap://ldap.example.com", StartTLS: true, BaseDN: testBase},
		"allow insecure": {URL: "ldap://127.0.0.1:3890", AllowInsecure: true, BaseDN: testBase},
	} {
		c, err := NewClient(cfg)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if c.cfg.UserFilter != DefaultUserFilter || c.cfg.Timeout != DefaultTimeout || c.tls.MinVersion != tls.VersionTLS12 || c.tls.ServerName == "" {
			t.Errorf("%s: defaults not applied: %+v", name, c.cfg)
		}
	}
}

// TestAuthenticate_Success: the right password returns the user's entry,
// read as the service account, after binding as the user.
func TestAuthenticate_Success(t *testing.T) {
	f := &fakeConn{}
	e, err := testClient(t, f).Authenticate(context.Background(), "ada", testPass)
	if err != nil {
		t.Fatal(err)
	}
	if e.DN != testUserDN || e.Get("MAIL") != "ada@example.com" || e.Get("entryuuid") != "5f1c-ada" || e.Get("missing") != "" {
		t.Fatalf("entry = %+v", e)
	}
	want := []string{"bind " + serviceDN, "search", "bind " + testUserDN}
	if strings.Join(f.calls, "|") != strings.Join(want, "|") || !f.closed {
		t.Fatalf("calls = %v (closed %v), want %v", f.calls, f.closed, want)
	}
}

// TestAuthenticate_UnknownAndWrongAreOneAnswerAndOneCost: an unknown user
// and a wrong password return the same error after the same calls (the
// unknown user's password is bound against a decoy DN), so neither the
// answer nor the round-trip count tells them apart. Remove decoyBind and
// this fails.
func TestAuthenticate_UnknownAndWrongAreOneAnswerAndOneCost(t *testing.T) {
	wrong, unknown := &fakeConn{}, &fakeConn{}
	_, errWrong := testClient(t, wrong).Authenticate(context.Background(), "ada", "nope")
	_, errUnknown := testClient(t, unknown).Authenticate(context.Background(), "grace", "nope")
	if !errors.Is(errWrong, ErrInvalidCredentials) || !errors.Is(errUnknown, ErrInvalidCredentials) {
		t.Fatalf("wrong = %v, unknown = %v; want ErrInvalidCredentials for both", errWrong, errUnknown)
	}
	if len(wrong.calls) != len(unknown.calls) || wrong.binds() != unknown.binds() {
		t.Fatalf("wrong password made %v, unknown user made %v; the work must match", wrong.calls, unknown.calls)
	}
	decoy := unknown.calls[len(unknown.calls)-1]
	if !strings.HasPrefix(decoy, "bind cn=") || !strings.HasSuffix(decoy, ","+testBase) {
		t.Fatalf("unknown user's last call = %q, want a decoy bind under the base DN", decoy)
	}
}

// TestAuthenticate_TimingDoesNotRevealUsers: with every directory call
// taking a fixed time, as a network round trip does, an unknown user takes
// as long as a wrong password. A missing decoy bind makes the unknown path
// a third shorter, far outside the band.
func TestAuthenticate_TimingDoesNotRevealUsers(t *testing.T) {
	const delay = 15 * time.Millisecond
	const rounds = 5
	measure := func(user string) time.Duration {
		var total time.Duration
		for range rounds {
			c := testClient(t, &fakeConn{delay: delay})
			start := time.Now()
			_, _ = c.Authenticate(context.Background(), user, "nope")
			total += time.Since(start)
		}
		return total / rounds
	}
	wrong, unknown := measure("ada"), measure("grace")
	ratio := float64(unknown) / float64(wrong)
	if ratio < 0.85 || ratio > 1.15 {
		t.Fatalf("unknown user %v, wrong password %v (ratio %.2f): timing tells them apart", unknown, wrong, ratio)
	}
}

// TestAuthenticate_EmptyPasswordNeverBinds: LDAP treats an empty password
// as an anonymous bind, which succeeds; the client refuses it before
// dialing.
func TestAuthenticate_EmptyPasswordNeverBinds(t *testing.T) {
	f := &fakeConn{}
	c := testClient(t, f)
	dialed := false
	c.dialer = func(context.Context) (conn, error) { dialed = true; return f, nil }
	for _, in := range [][2]string{{"ada", ""}, {"", testPass}} {
		if _, err := c.Authenticate(context.Background(), in[0], in[1]); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("%q/%q: %v", in[0], in[1], err)
		}
	}
	if dialed {
		t.Fatal("an empty password or username reached the directory")
	}
}

// TestAuthenticate_FilterIsEscaped: filter metacharacters in a username
// match only themselves (RFC 4515), so "*" cannot sign in as anyone.
func TestAuthenticate_FilterIsEscaped(t *testing.T) {
	f := &fakeConn{}
	for _, u := range []string{"*", "ada)(uid=*", `ada\`} {
		if _, err := testClient(t, f).Authenticate(context.Background(), u, testPass); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("%q: %v", u, err)
		}
	}
	for _, flt := range f.filters {
		inner := strings.TrimSuffix(strings.TrimPrefix(flt, "(&(objectClass=person)(uid="), "))")
		if strings.ContainsAny(inner, "*()") {
			t.Fatalf("filter %q carries an unescaped metacharacter", flt)
		}
	}
}

// TestAuthenticate_AmbiguousIsReported: a filter that matches two entries
// is ErrAmbiguousUser (logged by the plugin, answered as a wrong password),
// after the decoy bind, never a bind as whichever entry came first.
func TestAuthenticate_AmbiguousIsReported(t *testing.T) {
	f := &fakeConn{entries: 2}
	_, err := testClient(t, f).Authenticate(context.Background(), "ada", testPass)
	if !errors.Is(err, ErrAmbiguousUser) {
		t.Fatalf("err = %v", err)
	}
	for _, c := range f.calls {
		if c == "bind "+testUserDN {
			t.Fatal("bound as the first of two matching entries")
		}
	}
}

// TestAuthenticate_StartTLSFirst: with StartTLS the upgrade happens before
// any credential is sent.
func TestAuthenticate_StartTLSFirst(t *testing.T) {
	f := &fakeConn{}
	c := testClient(t, f, func(c *Config) { c.URL, c.StartTLS = "ldap://ldap.example.com", true })
	if _, err := c.Authenticate(context.Background(), "ada", testPass); err != nil {
		t.Fatal(err)
	}
	if f.calls[0] != "starttls" {
		t.Fatalf("calls = %v, want starttls first", f.calls)
	}
}

// TestAuthenticate_AFailedUpgradeSendsNoCredential: when the server refuses
// StartTLS the call stops there, with an operational error, before any bind
// puts a password on a connection that is still in clear text.
func TestAuthenticate_AFailedUpgradeSendsNoCredential(t *testing.T) {
	f := &fakeConn{tlsErr: errors.New("no tls here")}
	c := testClient(t, f, func(c *Config) { c.URL, c.StartTLS = "ldap://ldap.example.com", true })
	_, err := c.Authenticate(context.Background(), "ada", testPass)
	if err == nil || errors.Is(err, ErrInvalidCredentials) || !strings.Contains(err.Error(), "start TLS") {
		t.Fatalf("err = %v", err)
	}
	if f.binds() != 0 {
		t.Fatalf("a bind went out over a connection that failed to upgrade: %v", f.calls)
	}
}

// TestAuthenticate_OperationalErrorsAreNotWrongPasswords: a dial failure, a
// refused service account, a failed search and a user bind failing for
// another reason are errors to report, never ErrInvalidCredentials, so an
// outage does not tell people their password is wrong.
func TestAuthenticate_OperationalErrorsAreNotWrongPasswords(t *testing.T) {
	boom := errors.New("boom")
	cases := map[string]func(*Client, *fakeConn){
		"dial":         func(c *Client, _ *fakeConn) { c.dialer = func(context.Context) (conn, error) { return nil, boom } },
		"service bind": func(_ *Client, f *fakeConn) { f.svcErr = boom },
		"search":       func(_ *Client, f *fakeConn) { f.searchErr = boom },
		"user bind":    func(_ *Client, f *fakeConn) { f.bindErr = goldap.NewError(goldap.LDAPResultBusy, boom) },
	}
	for name, setup := range cases {
		f := &fakeConn{}
		c := testClient(t, f)
		setup(c, f)
		_, err := c.Authenticate(context.Background(), "ada", testPass)
		if err == nil || errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("%s: err = %v, want an operational error", name, err)
		}
	}
}

// TestAuthenticate_AnonymousSearch: without a BindDN the client searches
// without binding first.
func TestAuthenticate_AnonymousSearch(t *testing.T) {
	f := &fakeConn{}
	c := testClient(t, f, func(c *Config) { c.BindDN, c.BindPassword = "", "" })
	if _, err := c.Authenticate(context.Background(), "ada", testPass); err != nil {
		t.Fatal(err)
	}
	if f.calls[0] != "search" {
		t.Fatalf("calls = %v", f.calls)
	}
}

// TestAuthenticate_CancelClosesTheConnection: a request cancelled while the
// server is not answering closes the connection, which ends the call at
// once instead of after the timeout.
func TestAuthenticate_CancelClosesTheConnection(t *testing.T) {
	f := &fakeConn{hang: true, release: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	c := testClient(t, f)
	done := make(chan error, 1)
	go func() { _, err := c.Authenticate(ctx, "ada", testPass); done <- err }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil || errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("a cancelled call answered %v, want an operational error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the call outlived its cancelled context")
	}
	if !f.closed {
		t.Fatal("connection left open")
	}
}

// TestDial_RealDialerFailsCleanly: the go-ldap dialer against a port
// nothing listens on returns a dial error, which Authenticate reports as an
// operational error.
func TestDial_RealDialerFailsCleanly(t *testing.T) {
	c, err := NewClient(Config{URL: "ldap://127.0.0.1:1", AllowInsecure: true, BaseDN: testBase, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Authenticate(context.Background(), "ada", testPass); err == nil || errors.Is(err, ErrInvalidCredentials) || !strings.Contains(err.Error(), "dial") {
		t.Fatalf("err = %v", err)
	}
}

// TestDial_AConnectedServerGetsTheConfiguredTimeout: the go-ldap dialer, once
// it has a connection, applies the configured timeout to it, so a server
// that accepts and then says nothing ends the call with an operational error
// after about that long, instead of hanging the sign-in until the client
// gives up.
func TestDial_AConnectedServerGetsTheConfiguredTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var held []net.Conn
	var mu sync.Mutex
	defer func() {
		ln.Close()
		mu.Lock()
		for _, c := range held {
			_ = c.Close()
		}
		mu.Unlock()
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c) // accepted and never answered
			mu.Unlock()
		}
	}()
	c, err := NewClient(Config{URL: "ldap://" + ln.Addr().String(), AllowInsecure: true, BaseDN: testBase, Timeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := c.Authenticate(context.Background(), "ada", testPass); done <- err }()
	select {
	case err := <-done:
		if err == nil || errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("err = %v, want an operational error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a silent server hung the call past its timeout")
	}
}
