package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/organization/orgtest"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
)

// The failure paths the 2026-10-08 additions left without a test: rate
// stores that fail under the credential-stuffing guard, database faults in
// the user-locale read, the profile-field write and RequireOwnerRow, message
// data that cannot be queued or restored, and the organization helpers.

// f1SQLite is an env on a fresh SQLite database, for the tests whose subject
// does not depend on the engine.
func f1SQLite(t *testing.T) *env {
	db, d := openSQLite(t)
	return newEnv(t, auth.EngineSQLite, db, d)
}

// errF1Store is the failure of f1Store's armed calls.
var errF1Store = errors.New("f1: rate store down")

// f1PluginKey is the key RateHit and RatePeek hand the store for a plugin's
// own key: "plugin|" and the first 32 hex characters of its SHA-256, the
// layout TestRateHitAndPeek pins.
func f1PluginKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return "plugin|" + hex.EncodeToString(sum[:])[:32]
}

// f1StuffingGlobal is the store key of the guard's global failure counter.
var f1StuffingGlobal = f1PluginKey("password.stuffing.global")

// f1Store is a memory rate store that fails the one kind of call it is armed
// for: a Hit or a Peek, on the guard's global key or on any other plugin key
// (the per-password counter). The core's own limits never fail.
type f1Store struct {
	auth.RateStore
	failPeek, failHit bool
	global            bool
}

// armed reports whether key is the counter this store fails.
func (s *f1Store) armed(key string) bool {
	return strings.HasPrefix(key, "plugin|") && (key == f1StuffingGlobal) == s.global
}

func (s *f1Store) Hit(ctx context.Context, key string, window time.Duration) (int, error) {
	if s.failHit && s.armed(key) {
		return 0, errF1Store
	}
	return s.RateStore.Hit(ctx, key, window)
}

func (s *f1Store) Peek(ctx context.Context, key string, window time.Duration) (int, error) {
	if s.failPeek && s.armed(key) {
		return 0, errF1Store
	}
	peeker, ok := s.RateStore.(auth.RatePeeker)
	if !ok {
		return 0, auth.ErrRatePeekUnsupported
	}
	return peeker.Peek(ctx, key, window)
}

// TestF1_StuffingStoreFailures: a rate store that cannot read a counter fails
// the sign-in, since the guard cannot tell whether the password is refused;
// one that cannot count a failure leaves the answer ErrInvalidCredentials and
// logs the failure. Both counters, the password's and the global one.
func TestF1_StuffingStoreFailures(t *testing.T) {
	e := f1SQLite(t)
	for _, tc := range []struct {
		name            string
		peek, hit, glob bool
	}{
		{"peek password", true, false, false},
		{"peek global", true, false, true},
		{"hit password", false, true, false},
		{"hit global", false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := &bytes.Buffer{}
			store := &f1Store{RateStore: auth.NewMemoryRateStore(e.clock.Now), global: tc.glob}
			pw := e.passwordPlugin(password.GuardCredentialStuffing(password.StuffingPolicy{GlobalFailures: 5, Window: time.Minute}))
			a := e.newAuth(t, []auth.Option{stuffingSecret, auth.WithRateStore(store), auth.WithLogger(slog.New(slog.NewTextHandler(logs, nil)))}, e.emailPlugin(), pw)
			who := "f1-" + strings.ReplaceAll(tc.name, " ", "-") + "@example.com"
			if _, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: who, Password: secret}); err != nil {
				t.Fatal(err)
			}
			store.failPeek, store.failHit = tc.peek, tc.hit
			err := stuffingSignIn(a, pw, who, "not-the-password")
			if tc.peek {
				if !errors.Is(err, errF1Store) {
					t.Fatalf("a failed read: %v, want the store's error", err)
				}
				return
			}
			if !errors.Is(err, password.ErrInvalidCredentials) || !strings.Contains(logs.String(), "password: count a failed sign-in") {
				t.Fatalf("a failed count: %v, logs %s", err, logs)
			}
		})
	}
}

// TestF1_DBRatePeekFaults: a database failure of the database store's read
// fails RatePeek.
func TestF1_DBRatePeekFaults(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		// Built by hand: the harness passes a memory rate store, and the two
		// cannot be combined.
		a, err := auth.New(e.withDB(), auth.WithBaseURL(testBaseURL), auth.WithClock(e.clock.Now), auth.WithDBRateStore(), auth.WithPlugins(e.emailPlugin(), e.passwordPlugin()))
		tokensMust(t, err)
		_, err = a.Migrate(context.Background())
		tokensMust(t, err)
		return func(ctx context.Context) error {
			_, err := a.RatePeek(ctx, "f1|peek", time.Minute)
			return err
		}
	})
}

// TestF1_UserLocaleReadFails: when the stored locale cannot be read, the
// client's locale is used and the failure is logged, never answered.
func TestF1_UserLocaleReadFails(t *testing.T) {
	for k := 1; k <= authtest.MaxFaultSteps; k++ {
		e := newFaultEnv(t)
		logs := &bytes.Buffer{}
		a := coreAuth(t, e.env, nil, auth.WithUserColumns(auth.ColumnExtension{Name: "f1_locale", Type: auth.ColumnText, Nullable: true}),
			auth.WithUserLocale("f1_locale"), auth.WithLogger(slog.New(slog.NewTextHandler(logs, nil))))
		ctx := context.Background()
		u := must[auth.User](t)(a.CreateUser(ctx, auth.NewUser{Name: "Ada"}))
		_, tok, err := a.CreateSession(ctx, u.ID, auth.Client{})
		tokensMust(t, err)
		tokensMust(t, auth.SetUserColumn(ctx, a, auth.AppName, u.ID, sqlb.Col[string](auth.TableUser, "f1_locale"), "de"))
		c := a.WithRequest(ctx, auth.Request{Transport: auth.TransportHTTP, Client: auth.Client{Locale: "en"}, Credential: auth.CredentialBearer, Token: tok})
		e.f.Arm(k)
		got := ""
		if err := a.Resolve(c); err == nil {
			got = a.Locale(c)
		}
		if !e.f.Disarm() {
			t.Fatalf("no fault at step %d reached the locale read", k)
		}
		if strings.Contains(logs.String(), "auth: user locale") {
			if got != "en" {
				t.Fatalf("a failed locale read answered %q, want the client's", got)
			}
			return
		}
	}
	t.Fatal("no step faulted the locale read")
}

// TestF1_ProfileFieldsFaults: every database failure of a profile update
// with app fields fails it, the field write's included.
func TestF1_ProfileFieldsFaults(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		a := coreAuth(t, e.env, nil, auth.WithUserColumns(auth.ColumnExtension{Name: "f1_bio", Type: auth.ColumnText, Nullable: true}), auth.WithProfileFields("f1_bio"))
		ctx := context.Background()
		u := must[auth.User](t)(a.CreateUser(ctx, auth.NewUser{Name: "Ada"}))
		_, tok, err := a.CreateSession(ctx, u.ID, auth.Client{})
		tokensMust(t, err)
		return func(ctx context.Context) error {
			signed := a.WithRequest(ctx, auth.Request{Transport: auth.TransportHTTP, Credential: auth.CredentialBearer, Token: tok})
			_, err := a.UpdateProfile(signed, auth.ProfileRequest{Fields: auth.Fields{"f1_bio": json.RawMessage(`"maths"`)}})
			return err
		}
	})
}

// TestF1_RequireOwnerRowFaults: a database failure of RequireOwnerRow's read
// fails the operation rather than answering not-found.
func TestF1_RequireOwnerRowFaults(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		op := newRowOwnerPlugin()
		h := authtest.New(t, authtest.WithDB(e.db, e.d), authtest.WithOptions(auth.WithTablePrefix(tablePrefix())), authtest.WithPlugins(func(env *authtest.Env) []auth.Plugin {
			return append(harnessPlugins(env), op)
		}))
		ada := h.CreateUser("Ada")
		mine := h.SignIn(ada.ID)
		return func(ctx context.Context) error {
			_, err := op.read.Call(mine.Context(ctx), ownerIn{ID: mine.Session.ID})
			return err
		}
	})
}

// errF1Decode is f1Mail's refusal to restore message data.
var errF1Decode = errors.New("f1: data cannot be restored")

// f1Purpose is the purpose whose data f1Mail decodes.
const f1Purpose auth.Purpose = "f1.notice"

// f1Mail is the email plugin with a decoder for f1Purpose that refuses while
// fail is set, and a deliverer that records what it sends.
type f1Mail struct {
	*email.Plugin
	fail bool
	got  []auth.Message
}

func (m *f1Mail) Deliver(ctx context.Context, _ auth.Identity, msg auth.Message) error {
	// A dead context is the crashed process: nothing is delivered, so the
	// outbox row is what carries the message.
	if err := ctx.Err(); err != nil {
		return err
	}
	m.got = append(m.got, msg)
	return nil
}

func (m *f1Mail) DecodeMessageData(p auth.Purpose, raw json.RawMessage) (any, error) {
	if p != f1Purpose {
		return nil, nil
	}
	if m.fail {
		return nil, errF1Decode
	}
	var v string
	return v, json.Unmarshal(raw, &v)
}

// TestF1_MessageDataFailures: data that does not encode, or that its
// decoder refuses, fails Deliver before anything is queued; a stored row
// whose data the decoder refuses by the time the outbox sends it is counted
// as a failed send and never delivered.
func TestF1_MessageDataFailures(t *testing.T) {
	e := f1SQLite(t)
	dead, kill := context.WithCancel(context.Background())
	kill()
	crash := auth.WithBackground(func(_ context.Context, task func(context.Context)) { task(dead) })
	mail := &f1Mail{Plugin: email.New(email.Login(), email.Recover(), email.WithMailer(email.MailerFunc(func(context.Context, email.Mail) error { return nil })))}
	a := e.newAuth(t, []auth.Option{auth.WithDeliveryOutbox(sessKey), crash}, mail, e.passwordPlugin())
	ctx := context.Background()
	to := auth.Identity{Kind: email.KindEmail, Value: "ada@example.com"}
	deliver := func(data any) error {
		return a.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
			return a.Deliver(ctx, to, auth.Message{Purpose: f1Purpose, Data: data})
		})
	}
	if err := deliver(make(chan int)); !errors.Is(err, auth.ErrMessageDataUndecodable) {
		t.Fatalf("data that does not encode: %v", err)
	}
	mail.fail = true
	if err := deliver("hello"); !errors.Is(err, auth.ErrMessageDataUndecodable) || !errors.Is(err, errF1Decode) {
		t.Fatalf("data the decoder refuses: %v", err)
	}
	mail.fail = false
	tokensMust(t, deliver("hello"))
	mail.fail = true
	e.clock.Advance(time.Hour)
	n, err := a.SendOutbox(ctx)
	if err != nil || n.Sent != 0 || n.Failed != 1 || len(mail.got) != 0 {
		t.Fatalf("a stored row whose data no longer decodes: %+v %v, %d sent", n, err, len(mail.got))
	}
}

// TestF1_InvitationInviterAddress: an inviter created with an unverified
// address asked to be primary is named in the invitation by their verified
// one, which the email plugin promotes to primary as the first verified
// address; an unverified address never reaches an invitation.
func TestF1_InvitationInviterAddress(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		seen := &p3r2Seen{}
		org := organization.New()
		a := e.newAuth(t, nil, e.emailPlugin(email.Multiple(), email.Templates(seen.template)), e.passwordPlugin(), org)
		ctx := context.Background()
		u := must[auth.User](t)(a.CreateUser(ctx, auth.NewUser{Name: "Ada"}))
		must[auth.Identity](t)(a.CreateIdentity(ctx, auth.NewIdentity{UserID: u.ID, Kind: email.KindEmail, Raw: "ada@old.example", Primary: true}))
		must[auth.Identity](t)(a.CreateIdentity(ctx, auth.NewIdentity{UserID: u.ID, Kind: email.KindEmail, Raw: "ada@new.example", Verified: true}))
		_, tok, err := a.CreateSession(ctx, u.ID, auth.Client{})
		tokensMust(t, err)
		o := must[organization.Org](t)(org.CreateFor(ctx, u.ID, organization.CreateRequest{Name: "Acme", Slug: "acme"}))
		if err := org.Invite(request(a, tok), organization.InviteRequest{OrgID: o.ID, Email: "bob@example.com", Role: organization.RoleMember}); err != nil {
			t.Fatal(err)
		}
		if d := seen.last(t, a); d.InviterEmail != "ada@new.example" {
			t.Fatalf("inviter address %q, want the verified one", d.InviterEmail)
		}
	})
}

// TestF1_OrgFactoryIDFailure: NewOrganization fails the test when the app's
// id generator fails, rather than building a fixture with a broken slug.
func TestF1_OrgFactoryIDFailure(t *testing.T) {
	e := f1SQLite(t)
	ids := func(prefix string) (string, error) {
		if prefix == "" {
			return "", errors.New("f1: no ids")
		}
		return prefix + strings.ToLower(strings.TrimRight(auth.NewToken().Reveal(), "=")[:20]), nil
	}
	env := authtest.New(t, authtest.WithDB(e.db, e.d), authtest.WithOptions(auth.WithTablePrefix(tablePrefix()), auth.WithIDs(ids)),
		authtest.WithPlugins(func(env *authtest.Env) []auth.Plugin {
			return []auth.Plugin{email.New(email.Login(), email.Recover(), email.WithMailer(env.Mail)), e.passwordPlugin(), organization.New()}
		}))
	f := orgtest.New(env)
	rec := &p3r2TB{TB: t}
	env.T = rec
	func() {
		defer func() { _ = recover() }()
		f.NewOrganization("usr_x", "")
	}()
	if !strings.Contains(rec.msg, "orgtest: slug") {
		t.Fatalf("a failing id generator did not fail the test: %q", rec.msg)
	}
}
