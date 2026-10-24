package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// The compact cache, the mirror store, the revocation list, the stateless
// read interval and the device-session extras: everything that runs with no
// database. The database paths are in integration/sessions_r14_test.go.

var r14Now = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

func TestCompactCache_IsReadableSignedAndBoundToItsToken(t *testing.T) {
	ctx := context.Background()
	c := NewCompactSessionCache(sessKey)
	key := CacheKey{TokenHash: HashToken("t")}
	sess, u := Session{ID: "s", UserID: "u", ExpiresAt: r14Now.Add(time.Hour)}, User{ID: "u", Name: "Ada"}
	v, err := c.Put(ctx, key, sess, u, r14Now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	payload, sig, ok := strings.Cut(v, compactSeparator)
	if !ok || sig == "" {
		t.Fatalf("value %q is not payload.mac", v)
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("the claims must be readable JSON: %v", err)
	}
	if !strings.Contains(string(claims["u"]), `"Ada"`) {
		t.Fatalf("claims = %s, want the user readable", raw)
	}
	if bytes.Contains(raw, key.TokenHash) || strings.Contains(string(raw), base64.StdEncoding.EncodeToString(key.TokenHash)) || len(claims) != 3 {
		t.Fatalf("claims = %s; the token hash must be in the MAC, not the payload", raw)
	}
	if gs, gu, ok, err := c.Get(ctx, CacheKey{TokenHash: key.TokenHash, Client: v}, r14Now); err != nil || !ok || gs.ID != "s" || gu.Name != "Ada" {
		t.Fatalf("Get = %+v %+v %v %v", gs, gu, ok, err)
	}

	// A readable payload is not a writable one: changing a claim and keeping
	// the MAC is a miss, and so is every malformed value.
	forged := strings.Replace(string(raw), `"Ada"`, `"Eve"`, 1)
	notJSON := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	notB64 := "!!!"
	other := NewCompactSessionCache(bytes.Repeat([]byte{7}, SealKeySize))
	foreign, _ := other.Put(ctx, key, sess, u, r14Now.Add(time.Minute))
	for name, client := range map[string]string{
		"a forged claim":               base64.RawURLEncoding.EncodeToString([]byte(forged)) + "." + sig,
		"no MAC":                       payload,
		"two dots":                     v + ".x",
		"a MAC that is not base64":     payload + ".!!!",
		"another key's value":          foreign,
		"a valid MAC over non-JSON":    notJSON + "." + base64.RawURLEncoding.EncodeToString(compactMAC(sessKey, key.TokenHash, notJSON)),
		"a valid MAC over non-base64":  notB64 + "." + base64.RawURLEncoding.EncodeToString(compactMAC(sessKey, key.TokenHash, notB64)),
		"no value":                     "",
		"another purpose's HMAC shape": payload + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	} {
		if _, _, ok, err := c.Get(ctx, CacheKey{TokenHash: key.TokenHash, Client: client}, r14Now); ok || err != nil {
			t.Errorf("%s: ok=%v err=%v, want a miss", name, ok, err)
		}
	}
	if _, _, ok, _ := c.Get(ctx, CacheKey{TokenHash: HashToken("other"), Client: v}, r14Now); ok {
		t.Error("a copy must not serve another token")
	}
	if _, _, ok, _ := c.Get(ctx, CacheKey{TokenHash: key.TokenHash, Client: v}, r14Now.Add(time.Minute)); ok {
		t.Error("a copy at its expiry must be a miss")
	}
	if err := c.Drop(ctx, key); err != nil {
		t.Fatal(err)
	}

	// Rotation: the first key signs, every key verifies.
	newKey := bytes.Repeat([]byte{3}, SealKeySize)
	if _, _, ok, _ := NewCompactSessionCache(newKey, sessKey).Get(ctx, CacheKey{TokenHash: key.TokenHash, Client: v}, r14Now); !ok {
		t.Error("a copy signed with the previous key must verify while it is in the ring")
	}
	if _, _, ok, _ := NewCompactSessionCache(newKey).Get(ctx, CacheKey{TokenHash: key.TokenHash, Client: v}, r14Now); ok {
		t.Error("a copy signed with a dropped key must be a miss")
	}
}

func TestCompactCache_RefusesMissingOrShortKeys(t *testing.T) {
	ctx := context.Background()
	key := CacheKey{TokenHash: HashToken("t")}
	for name, tc := range map[string]struct {
		c    SessionCache
		want error
	}{
		"no key":      {NewCompactSessionCache(), ErrNoKeys},
		"a short key": {NewCompactSessionCache(sessKey, []byte("short")), ErrBadOperation},
	} {
		if _, err := tc.c.Put(ctx, key, Session{}, User{}, r14Now); !errors.Is(err, tc.want) {
			t.Errorf("%s: Put = %v, want %v", name, err, tc.want)
		}
		if _, _, _, err := tc.c.Get(ctx, CacheKey{TokenHash: key.TokenHash, Client: "a.b"}, r14Now); !errors.Is(err, tc.want) {
			t.Errorf("%s: Get = %v, want %v", name, err, tc.want)
		}
	}
	bad := NewCompactSessionCache(sessKey)
	if _, err := bad.Put(ctx, key, Session{Data: AppData("{not json")}, User{}, r14Now); err == nil {
		t.Error("Put of unencodable data must fail")
	}
}

func TestNew_CompactCacheTakesTheDerivedKey(t *testing.T) {
	secret := bytes.Repeat([]byte{5}, MinSecretSize)
	c := NewCompactSessionCache()
	a, err := New(WithPlugins(scriptSignIn{}), WithSecret(secret), WithSessionCache(c, 0))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := a.Config().DeriveKey(KeyLabelCompactCache)
	if got := c.(*compactCache).keys; len(got) != 1 || !bytes.Equal(got[0], want) {
		t.Fatalf("keys = %x, want the key derived under %q", got, KeyLabelCompactCache)
	}
	if snap, _ := a.Config().DeriveKey(KeyLabelSnapshotCache); bytes.Equal(snap, want) {
		t.Fatal("the compact and snapshot caches must not share a key")
	}
	if _, err := New(WithPlugins(scriptSignIn{}), WithSessionCache(NewCompactSessionCache(), 0)); !errors.Is(err, ErrNoKeys) {
		t.Fatalf("no key and no secret: %v, want ErrNoKeys", err)
	}
}

func TestMemoryRevocations_PrunesByTheCoreClock(t *testing.T) {
	ctx := context.Background()
	r := NewMemorySessionRevocations().(*memoryRevocations)
	if err := r.Revoke(ctx, "a", r14Now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := r.Revoke(ctx, "b", r14Now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if ok, _ := r.Revoked(ctx, "a", r14Now); !ok || len(r.m) != 2 {
		t.Fatalf("revoked=%v entries=%d, want a revoked and both kept", ok, len(r.m))
	}
	// Within a minute of the last prune nothing is scanned.
	if ok, _ := r.Revoked(ctx, "b", r14Now.Add(30*time.Second)); !ok || len(r.m) != 2 {
		t.Fatalf("entries = %d, want no prune yet", len(r.m))
	}
	if ok, _ := r.Revoked(ctx, "b", r14Now.Add(2*time.Minute)); !ok || len(r.m) != 1 {
		t.Fatalf("entries = %d, want the expired entry pruned and b still revoked", len(r.m))
	}
}

// failingStore wraps a store and fails every method named in fail.
type failingStore struct {
	SessionStore
	fail map[string]bool
}

var errFailingStore = errors.New("store down")

func (f failingStore) err(name string) error {
	if f.fail[name] {
		return errFailingStore
	}
	return nil
}

func (f failingStore) Insert(ctx context.Context, s Session, h []byte) error {
	if err := f.err("insert"); err != nil {
		return err
	}
	return f.SessionStore.Insert(ctx, s, h)
}

func (f failingStore) Find(ctx context.Context, h []byte, now time.Time) (Session, error) {
	if err := f.err("find"); err != nil {
		return Session{}, err
	}
	return f.SessionStore.Find(ctx, h, now)
}

func (f failingStore) Touch(ctx context.Context, id string, exp, seen time.Time) (bool, error) {
	if err := f.err("touch"); err != nil {
		return false, err
	}
	return f.SessionStore.Touch(ctx, id, exp, seen)
}

func (f failingStore) Delete(ctx context.Context, user, id string) error {
	if err := f.err("delete"); err != nil {
		return err
	}
	return f.SessionStore.Delete(ctx, user, id)
}

func (f failingStore) DeleteUser(ctx context.Context, user, except string) error {
	if err := f.err("deleteUser"); err != nil {
		return err
	}
	return f.SessionStore.DeleteUser(ctx, user, except)
}

func (f failingStore) Sweep(ctx context.Context, now time.Time) (int64, error) {
	if err := f.err("sweep"); err != nil {
		return 0, err
	}
	return f.SessionStore.Sweep(ctx, now)
}

func (f failingStore) SetData(ctx context.Context, id string, d AppData) error {
	if err := f.err("setData"); err != nil {
		return err
	}
	return f.SessionStore.SetData(ctx, id, d)
}

// r14Session is a live session for the mirror tests.
func r14Session(id string) Session {
	return Session{ID: id, UserID: "u", CreatedAt: r14Now, LastSeenAt: r14Now, ExpiresAt: r14Now.Add(time.Hour)}
}

// mirrorWithLog is a mirror of primary and secondary logging into the
// returned buffer, as New binds it.
func mirrorWithLog(primary, secondary SessionStore) (SessionStore, *bytes.Buffer) {
	var log bytes.Buffer
	m := MirrorSessionStore(primary, secondary).(mirrorSessionStore)
	m.logger = slog.New(slog.NewTextHandler(&log, nil))
	return m, &log
}

func TestMirrorSessionStore_ASecondaryFailureNeverLetsAnEndedSessionIn(t *testing.T) {
	ctx := context.Background()
	h := HashToken("t")
	t.Run("reads fall back to the primary", func(t *testing.T) {
		primary := NewMemorySessionStore()
		m, log := mirrorWithLog(primary, failingStore{NewMemorySessionStore(), map[string]bool{"find": true, "insert": true, "touch": true, "sweep": true}})
		if err := m.Insert(ctx, r14Session("s"), h); err != nil {
			t.Fatalf("Insert with a failing secondary: %v, want success", err)
		}
		if got, err := m.Find(ctx, h, r14Now); err != nil || got.ID != "s" {
			t.Fatalf("Find = %v %v, want the primary's session", got, err)
		}
		if moved, err := m.Touch(ctx, "s", r14Now.Add(2*time.Hour), r14Now); err != nil || !moved {
			t.Fatalf("Touch = %v %v, want the primary's answer", moved, err)
		}
		if n, err := m.Sweep(ctx, r14Now.Add(3*time.Hour)); err != nil || n != 1 {
			t.Fatalf("Sweep = %d %v, want the primary's count", n, err)
		}
		for _, op := range []string{mirrorOpFind, mirrorOpInsert, mirrorOpTouch, mirrorOpSweep} {
			if !strings.Contains(log.String(), "op="+op) {
				t.Errorf("no log line for the secondary's %s failure:\n%s", op, log)
			}
		}
	})
	t.Run("the secondary is read first", func(t *testing.T) {
		secondary := NewMemorySessionStore()
		m, _ := mirrorWithLog(failingStore{NewMemorySessionStore(), map[string]bool{"find": true}}, secondary)
		if err := secondary.Insert(ctx, r14Session("s"), h); err != nil {
			t.Fatal(err)
		}
		if got, err := m.Find(ctx, h, r14Now); err != nil || got.ID != "s" {
			t.Fatalf("Find = %v %v, want the secondary's copy without asking the primary", got, err)
		}
		if _, err := m.Find(ctx, HashToken("none"), r14Now); !errors.Is(err, errFailingStore) {
			t.Fatalf("a secondary miss must ask the primary: %v", err)
		}
	})
	for _, op := range []string{"delete", "deleteUser"} {
		t.Run(op+" fails and ends nothing in the primary when the secondary fails", func(t *testing.T) {
			primary, secondary := NewMemorySessionStore(), NewMemorySessionStore()
			m, _ := mirrorWithLog(primary, failingStore{secondary, map[string]bool{op: true}})
			if err := m.Insert(ctx, r14Session("s"), h); err != nil {
				t.Fatal(err)
			}
			var err error
			if op == "delete" {
				err = m.Delete(ctx, "u", "s")
			} else {
				err = m.DeleteUser(ctx, "u", "")
			}
			if !errors.Is(err, errFailingStore) {
				t.Fatalf("%s with a failing secondary = %v, want its failure", op, err)
			}
			if _, err := primary.Find(ctx, h, r14Now); err != nil {
				t.Fatalf("the primary lost the session the failed %s did not end: %v", op, err)
			}
		})
	}
	t.Run("a successful delete ends both", func(t *testing.T) {
		primary, secondary := NewMemorySessionStore(), NewMemorySessionStore()
		m, _ := mirrorWithLog(primary, secondary)
		for _, id := range []string{"s1", "s2"} {
			if err := m.Insert(ctx, r14Session(id), HashToken(Token(id))); err != nil {
				t.Fatal(err)
			}
		}
		if err := m.Delete(ctx, "u", "s1"); err != nil {
			t.Fatal(err)
		}
		if err := m.DeleteUser(ctx, "u", ""); err != nil {
			t.Fatal(err)
		}
		for _, s := range []SessionStore{primary, secondary} {
			for _, id := range []string{"s1", "s2"} {
				if _, err := s.Find(ctx, HashToken(Token(id)), r14Now); !errors.Is(err, ErrSessionNotFound) {
					t.Fatalf("%s survived in one side: %v", id, err)
				}
			}
		}
	})
	t.Run("SetData must reach both", func(t *testing.T) {
		m, _ := mirrorWithLog(NewMemorySessionStore(), failingStore{NewMemorySessionStore(), map[string]bool{"setData": true}})
		if err := m.SetData(ctx, "s", AppData(`{}`)); !errors.Is(err, errFailingStore) {
			t.Fatalf("SetData with a failing secondary = %v, want its failure", err)
		}
	})
	t.Run("a primary failure is the call's failure", func(t *testing.T) {
		m, _ := mirrorWithLog(failingStore{NewMemorySessionStore(), map[string]bool{"insert": true, "touch": true, "sweep": true, "setData": true, "delete": true}}, NewMemorySessionStore())
		if err := m.Insert(ctx, r14Session("s"), h); !errors.Is(err, errFailingStore) {
			t.Errorf("Insert = %v", err)
		}
		if _, err := m.Touch(ctx, "s", r14Now, r14Now); !errors.Is(err, errFailingStore) {
			t.Errorf("Touch = %v", err)
		}
		if _, err := m.Sweep(ctx, r14Now); !errors.Is(err, errFailingStore) {
			t.Errorf("Sweep = %v", err)
		}
		if err := m.SetData(ctx, "s", nil); !errors.Is(err, errFailingStore) {
			t.Errorf("SetData = %v", err)
		}
		if err := m.Delete(ctx, "u", "s"); !errors.Is(err, errFailingStore) {
			t.Errorf("Delete = %v", err)
		}
	})
	t.Run("List reads the primary alone", func(t *testing.T) {
		primary, secondary := NewMemorySessionStore(), NewMemorySessionStore()
		m, _ := mirrorWithLog(primary, secondary)
		if err := secondary.Insert(ctx, r14Session("copy-only"), h); err != nil {
			t.Fatal(err)
		}
		if list, err := m.List(ctx, "u", r14Now); err != nil || len(list) != 0 {
			t.Fatalf("List = %v %v, want the primary's (empty) list", list, err)
		}
	})
}

func TestMirrorSessionStore_BindsAtNew(t *testing.T) {
	mem := NewMemorySessionStore()
	a, err := New(WithPlugins(scriptSignIn{}), WithSessionStore(MirrorSessionStore(SQLSessionStore(), mem)), WithSessionArchive())
	if err != nil {
		t.Fatalf("a mirror with the SQL store takes the archive: %v", err)
	}
	m, ok := a.SessionStore().(mirrorSessionStore)
	if !ok {
		t.Fatalf("SessionStore = %T, want the mirror", a.SessionStore())
	}
	if p, ok := m.primary.(sqlSessionStore); !ok || p.a != a || !p.archive {
		t.Fatalf("primary = %#v, want the SQL store bound to this Auth with the archive", m.primary)
	}
	if m.logger != a.logger || a.finder != nil {
		t.Fatal("the mirror must log through the Auth and offer no single-query lookup")
	}
	alone, err := New(WithPlugins(scriptSignIn{}), WithSessionStore(SQLSessionStore()))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := alone.SessionStore().(sqlSessionStore); !ok || alone.finder == nil {
		t.Fatalf("SQLSessionStore alone = %T, want the default store with its single-query lookup", alone.SessionStore())
	}
	for name, opts := range map[string][]Option{
		"a mirror missing a side":          {WithSessionStore(MirrorSessionStore(mem, nil))},
		"a mirror missing the primary":     {WithSessionStore(MirrorSessionStore(nil, mem))},
		"the SQL store on both sides":      {WithSessionStore(MirrorSessionStore(SQLSessionStore(), MirrorSessionStore(NewMemorySessionStore(), SQLSessionStore())))},
		"the archive with no SQL store":    {WithSessionStore(MirrorSessionStore(mem, NewMemorySessionStore())), WithSessionArchive()},
		"a broken mirror as the primary":   {WithSessionStore(MirrorSessionStore(MirrorSessionStore(mem, nil), mem))},
		"a broken mirror as the secondary": {WithSessionStore(MirrorSessionStore(mem, MirrorSessionStore(nil, mem)))},
	} {
		if _, err := New(append(opts, WithPlugins(scriptSignIn{}))...); !errors.Is(err, ErrBadOperation) {
			t.Errorf("%s: %v, want ErrBadOperation", name, err)
		}
	}
}

func TestSQLSessionStore_RefusesEveryCallUntilBound(t *testing.T) {
	ctx := context.Background()
	p := SQLSessionStore()
	_, findErr := p.Find(ctx, nil, r14Now)
	_, touchErr := p.Touch(ctx, "", r14Now, r14Now)
	_, listErr := p.List(ctx, "", r14Now)
	_, sweepErr := p.Sweep(ctx, r14Now)
	for name, err := range map[string]error{
		"Insert": p.Insert(ctx, Session{}, nil), "Find": findErr, "Touch": touchErr, "List": listErr,
		"Delete": p.Delete(ctx, "", ""), "DeleteUser": p.DeleteUser(ctx, "", ""), "Sweep": sweepErr, "SetData": p.SetData(ctx, "", nil),
	} {
		if !errors.Is(err, ErrUnboundSessionStore) {
			t.Errorf("%s = %v, want ErrUnboundSessionStore", name, err)
		}
	}
}

func TestNew_SessionExtrasOptionsRefuseWhereTheyWouldDoNothing(t *testing.T) {
	extras := WithSessionExtras(func(context.Context, *Call) (any, error) { return nil, nil })
	for name, opts := range map[string][]Option{
		"refresh without read and no stateless": {WithStatelessRefreshWithoutRead(0)},
		"revocations and a store":               {WithSessionRevocations(NewMemorySessionRevocations())},
		"device extras and no multi-session":    {WithDeviceSessionExtras(), extras},
		"device extras and no extras function":  {WithDeviceSessionExtras(), WithMultiSession(0)},
	} {
		if _, err := New(append(opts, WithPlugins(scriptSignIn{}))...); !errors.Is(err, ErrBadOperation) {
			t.Errorf("%s: %v, want ErrBadOperation", name, err)
		}
	}
	a, err := New(WithPlugins(scriptSignIn{}), WithStatelessSessions(sessKey), WithStatelessRefreshWithoutRead(time.Hour),
		WithSessionRevocations(NewMemorySessionRevocations()), WithMultiSession(0), WithDeviceSessionExtras(), extras)
	if err != nil {
		t.Fatal(err)
	}
	if a.stateless.readEvery != MaxStatelessReadInterval || a.revocations == nil || !a.deviceExtras {
		t.Fatalf("readEvery=%v revocations=%v deviceExtras=%v", a.stateless.readEvery, a.revocations, a.deviceExtras)
	}
}

func TestStatelessReadInterval_BoundsAndUse(t *testing.T) {
	for in, want := range map[time.Duration]time.Duration{0: DefaultStatelessReadInterval, -time.Minute: DefaultStatelessReadInterval, time.Hour: MaxStatelessReadInterval, 2 * time.Minute: 2 * time.Minute} {
		if got := clampReadInterval(in); got != want {
			t.Errorf("clampReadInterval(%v) = %v, want %v", in, got, want)
		}
	}
	st := &statelessSessions{readEvery: 5 * time.Minute}
	read := &statelessRead{At: r14Now}
	for name, tc := range map[string]struct {
		st   *statelessSessions
		r    *statelessRead
		at   time.Time
		want bool
	}{
		"within the interval":    {st, read, r14Now.Add(4 * time.Minute), true},
		"at the interval":        {st, read, r14Now.Add(5 * time.Minute), false},
		"no copy":                {st, nil, r14Now, false},
		"a copy from the future": {st, read, r14Now.Add(-time.Second), false},
		"the option off":         {&statelessSessions{}, read, r14Now, false},
	} {
		if got := tc.st.usableRead(tc.r, tc.at); got != tc.want {
			t.Errorf("%s: usableRead = %v, want %v", name, got, tc.want)
		}
	}
}

func TestStateless_SealWithCarriesTheReadUser(t *testing.T) {
	ring, _ := NewKeyRing(sessKey)
	st := &statelessSessions{ring: ring}
	read := &statelessRead{User: User{ID: "u", Name: "Ada"}, At: r14Now}
	tok, err := st.sealWith(Session{ID: "s", UserID: "u"}, read)
	if err != nil {
		t.Fatal(err)
	}
	s, got, err := st.openWith(tok)
	if err != nil || s.ID != "s" || got == nil || got.User.Name != "Ada" || !got.At.Equal(r14Now) {
		t.Fatalf("openWith = %+v %+v %v", s, got, err)
	}
	plain, _ := st.seal(Session{ID: "s"})
	if _, got, _ := st.openWith(plain); got != nil {
		t.Fatal("a token sealed without a read must carry none")
	}
}

// failingRevocations fails both calls.
type failingRevocations struct{}

func (failingRevocations) Revoke(context.Context, string, time.Time) error { return errFailingStore }
func (failingRevocations) Revoked(context.Context, string, time.Time) (bool, error) {
	return false, errFailingStore
}

func TestRevokeStateless_ListsUntilTheLatestValidInstant(t *testing.T) {
	ctx := context.Background()
	a := &Auth{}
	if err := a.revokeStateless(ctx, Session{ID: "s"}); err != nil {
		t.Fatalf("no list: %v, want nothing done", err)
	}
	if err := a.checkRevoked(ctx, "s", r14Now); err != nil {
		t.Fatalf("no list: %v", err)
	}
	r := NewMemorySessionRevocations()
	a.revocations = r
	hard := r14Now.Add(30 * 24 * time.Hour)
	if err := a.revokeStateless(ctx, Session{ID: "slides", ExpiresAt: r14Now.Add(time.Hour), MaxExpiresAt: &hard}); err != nil {
		t.Fatal(err)
	}
	if err := a.revokeStateless(ctx, Session{ID: "fixed", ExpiresAt: r14Now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	// A token of the sliding session can be refreshed up to its hard stop,
	// so the entry lasts that long; the fixed one only to its expiry.
	if err := a.checkRevoked(ctx, "slides", hard.Add(-time.Minute)); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("sliding session before its hard stop: %v, want refused", err)
	}
	if err := a.checkRevoked(ctx, "fixed", r14Now.Add(2*time.Hour)); err != nil {
		t.Fatalf("fixed session after its expiry: %v, want the entry gone", err)
	}
	a.revocations = failingRevocations{}
	if err := a.revokeStateless(ctx, Session{ID: "s"}); !errors.Is(err, errFailingStore) {
		t.Fatalf("revoke failure: %v", err)
	}
	if err := a.checkRevoked(ctx, "s", r14Now); !errors.Is(err, errFailingStore) || errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("a list that cannot be read must fail the request, not sign out: %v", err)
	}
}

func TestDeviceExtras_OffWithoutTheOption(t *testing.T) {
	a := &Auth{sessionExtras: func(context.Context, *Call) (any, error) { return "x", nil }}
	if got, err := a.deviceExtrasFor(context.Background(), &Call{}, Session{}, User{}); got != nil || err != nil {
		t.Fatalf("deviceExtrasFor = %v %v, want nothing without WithDeviceSessionExtras", got, err)
	}
}

func TestStatelessCacheHit_AListThatCannotBeReadFailsTheRequest(t *testing.T) {
	cache := NewMemorySessionCache(4)
	a, err := New(WithPlugins(scriptSignIn{}), WithStatelessSessions(sessKey), WithSessionRevocations(failingRevocations{}), WithSessionCache(cache, 0))
	if err != nil {
		t.Fatal(err)
	}
	tok := Token("cached-token")
	if _, err := cache.Put(context.Background(), CacheKey{TokenHash: HashToken(tok)}, Session{ID: "s", UserID: "u"}, User{ID: "u"}, a.now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	ctx := a.WithRequest(context.Background(), Request{Transport: TransportHTTP, Credential: CredentialCookie, Token: tok})
	if err := a.Resolve(ctx); !errors.Is(err, errFailingStore) {
		t.Fatalf("Resolve = %v, want the list's failure, never a cached sign-in", err)
	}
	if _, ok := CurrentUser(ctx); ok {
		t.Fatal("a cache hit signed in while the list could not be read")
	}
}
