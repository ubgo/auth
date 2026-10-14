package integration

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/phone"
	"github.com/ubgo/auth/plugin/username"
	"github.com/ubgo/sqlb"
)

func TestEmail_ChangeAndUndo(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)

		const next = "alice@new.example"
		if err := em.Change(ctx, next); err != nil {
			t.Fatalf("change: %v", err)
		}
		if _, err := em.ConfirmChange(anon(a), e.mail.LastToken(t, a, next)); err != nil {
			t.Fatalf("confirm: %v", err)
		}
		list := must[[]email.Address](t)(em.List(request(a, up.Token)))
		if len(list) != 1 || list[0].Email != next || !list[0].Primary {
			t.Fatalf("after change: %+v, want only %s as primary", list, next)
		}

		// The old address got an undo link; using it restores the address and
		// ends every session, the thief's included.
		undo := e.mail.LastToken(t, a, alice)
		if err := em.UndoChange(anon(a), undo); err != nil {
			t.Fatalf("undo: %v", err)
		}
		if _, _, _, err := a.ResolveSession(context.Background(), up.Token); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("session after undo: %v, want signed out", err)
		}
		in := must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}))
		list = must[[]email.Address](t)(em.List(request(a, in.Token)))
		if len(list) != 1 || list[0].Email != alice || !list[0].Primary {
			t.Fatalf("after undo: %+v, want only %s as primary", list, alice)
		}
	})
}

func TestEmail_MultipleAddressesAndLastSignInMethod(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(email.Multiple()), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		up := signUpVerified(t, e, a, pw, em)
		fresh := func() context.Context { return request(a, up.Token) }

		const work = "alice@work.example"
		if err := em.Add(fresh(), work); err != nil {
			t.Fatal(err)
		}
		if err := em.MakePrimary(fresh(), work); !errors.Is(err, auth.ErrNotVerified) {
			t.Fatalf("make an unverified address primary: %v, want ErrNotVerified", err)
		}
		if _, err := em.Verify(anon(a), e.mail.LastToken(t, a, work)); err != nil {
			t.Fatal(err)
		}
		if err := em.MakePrimary(fresh(), work); err != nil {
			t.Fatal(err)
		}
		if err := em.Remove(fresh(), alice); err != nil {
			t.Fatalf("remove a second address: %v", err)
		}
		if err := em.Remove(fresh(), work); !errors.Is(err, auth.ErrLastSignInMethod) {
			t.Fatalf("remove the last sign-in address: %v, want ErrLastSignInMethod", err)
		}
	})
}

func TestEmail_VerifiedAddressCannotBeVerifiedTwice(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(email.Multiple()), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		signUpVerified(t, e, a, pw, em)
		bob := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: "bob@example.com", Password: secret}))
		before := len(e.mail.To(a, alice))
		if err := em.Add(request(a, bob.Token), alice); err != nil {
			t.Fatal(err)
		}
		// No verify link reaches alice's inbox, only the duplicate sign-up
		// notice: a link to an address her account already verified could
		// only ever answer auth.identity_taken.
		got := e.mail.To(a, alice)
		if len(got) != before+1 || !strings.HasPrefix(got[len(got)-1].Subject, "Someone tried to sign up") {
			t.Fatalf("mail to alice after bob added her address: %+v", got[before:])
		}
		// Should the address be verified for bob anyway (a link issued before
		// alice verified it), the unique index refuses a second verified row.
		ids, err := a.Identities(context.Background(), bob.User.ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, idn := range ids {
			if idn.Value != alice {
				continue
			}
			if _, err := a.VerifyIdentity(context.Background(), idn.ID); !errors.Is(err, auth.ErrIdentityTaken) {
				t.Fatalf("verify a value verified elsewhere: %v, want ErrIdentityTaken", err)
			}
		}
	})
}

func TestPhone_SignInWithCodeCreatesThenFindsTheUser(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ph := e.phonePlugin(phone.Login(), phone.SignInWithCode())
		a := e.newAuth(t, nil, ph)
		const number = "+1 (555) 010-0100"
		const e164 = "+15550100100"
		if err := ph.SendCode(anon(a), number); err != nil {
			t.Fatal(err)
		}
		first := must[phone.SignInResult](t)(ph.SignIn(anon(a), number, e.sms.LastCode(t, a, e164)))
		if !first.Created || first.Token == "" {
			t.Fatalf("first code sign-in = %+v, want a created user and a session", first)
		}
		if err := ph.SendCode(anon(a), e164); err != nil {
			t.Fatal(err)
		}
		second := must[phone.SignInResult](t)(ph.SignIn(anon(a), e164, e.sms.LastCode(t, a, e164)))
		if second.Created || second.User.ID != first.User.ID {
			t.Fatalf("second sign-in = %+v, want the same user %s", second, first.User.ID)
		}
	})
}

func TestPhone_CodeIsSingleUseAndAttemptsAreCapped(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ph := e.phonePlugin(phone.Login(), phone.SignInWithCode(), phone.WithMaxAttempts(2))
		a := e.newAuth(t, nil, ph)
		const n = "+15550100100"
		if err := ph.SendCode(anon(a), n); err != nil {
			t.Fatal(err)
		}
		code := e.sms.LastCode(t, a, n)
		wrong := "000000"
		if code == wrong {
			wrong = "111111"
		}
		for range 2 {
			if _, err := ph.SignIn(anon(a), n, wrong); !errors.Is(err, phone.ErrCodeInvalid) {
				t.Fatalf("wrong code: %v", err)
			}
		}
		// Two wrong guesses spent the code, although each failed call rolled
		// its transaction back: the count is written after the rollback.
		if _, err := ph.SignIn(anon(a), n, code); !errors.Is(err, phone.ErrCodeInvalid) {
			t.Fatalf("right code after the cap: %v, want ErrCodeInvalid", err)
		}
		if err := ph.SendCode(anon(a), n); err != nil {
			t.Fatal(err)
		}
		code = e.sms.LastCode(t, a, n)
		if _, err := ph.SignIn(anon(a), n, code); err != nil {
			t.Fatalf("fresh code: %v", err)
		}
		if _, err := ph.SignIn(anon(a), n, code); !errors.Is(err, phone.ErrCodeInvalid) {
			t.Fatalf("reused code: %v, want ErrCodeInvalid", err)
		}
	})
}

func TestUsername_SetAvailableReserved(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, un := e.emailPlugin(), e.passwordPlugin(), username.New(username.Login())
		a := e.newAuth(t, nil, em, un, pw)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)

		if ok := must[bool](t)(un.Available(anon(a), "Alice_1")); !ok {
			t.Fatal("a free handle must be available")
		}
		if _, err := un.Set(ctx, "Alice_1"); err != nil {
			t.Fatal(err)
		}
		if ok := must[bool](t)(un.Available(anon(a), "alice_1")); ok {
			t.Fatal("a taken handle must not be available, whatever its case")
		}
		if _, err := un.Set(ctx, "admin"); !errors.Is(err, username.ErrReserved) {
			t.Fatalf("reserved handle: %v", err)
		}
		// A handle signs in with the same password.
		in, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: "ALICE_1", Password: secret})
		if err != nil || in.User.ID != up.User.ID {
			t.Fatalf("sign in by handle: %v %v", in.User.ID, err)
		}
		// Renaming frees the old handle.
		if _, err := un.Set(ctx, "alice_2"); err != nil {
			t.Fatal(err)
		}
		if ok := must[bool](t)(un.Available(anon(a), "alice_1")); !ok {
			t.Fatal("the old handle must be free after a rename")
		}
	})
}

// TestComposite_OneStatementFillsFlatAndNestedFields loads a user whose
// columns come from auth_user (flat: core and the email plugin's column) and
// from two joins of auth_identity (nested: phone and handle).
func TestComposite_OneStatementFillsFlatAndNestedFields(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, un := e.emailPlugin(), e.passwordPlugin(), username.New(username.Login())
		ph := e.phonePlugin(phone.Login())
		a := e.newAuth(t, nil, em, ph, un, pw)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)
		must[username.Result](t)(un.Set(ctx, "Alice"))
		if err := ph.Add(ctx, "+15550100100"); err != nil {
			t.Fatal(err)
		}
		if err := ph.Verify(ctx, "+15550100100", e.sms.LastCode(t, a, "+15550100100")); err != nil {
			t.Fatal(err)
		}

		var u appUser
		if err := a.LoadUser(context.Background(), up.User.ID, &u); err != nil {
			t.Fatal(err)
		}
		switch {
		case u.ID != up.User.ID || u.Name != "Alice":
			t.Errorf("core fields = %+v", u.User)
		case u.PrimaryEmail == nil || *u.PrimaryEmail != alice:
			t.Errorf("flat plugin column PrimaryEmail = %v", u.PrimaryEmail)
		case u.Phone.Number != "+15550100100" || !u.Phone.Verified():
			t.Errorf("nested phone = %+v", u.Phone)
		case u.Handle.Handle != "alice" || u.Handle.Display != "Alice":
			t.Errorf("nested handle = %+v", u.Handle)
		}

		// A user with no phone and no handle: the LEFT joins miss and the
		// nested structs are zero, not an error.
		bob := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: "bob@example.com", Password: secret}))
		var b appUser
		if err := a.LoadUser(context.Background(), bob.User.ID, &b); err != nil {
			t.Fatal(err)
		}
		if b.Phone.Exists() || b.Handle.Exists() || b.PrimaryEmail != nil {
			t.Errorf("bob = %+v, want empty nested data and no primary (unverified)", b)
		}
	})
}

// appUser is an application's composite user: flat where the column is on
// auth_user, nested where it is joined (ADR-0001).
type appUser struct {
	auth.User
	email.EmailColumns
	Phone  phone.Data
	Handle username.Data
}

func (u *appUser) Bindings() []sqlb.Binding {
	return sqlb.Bindings(auth.UserBindings(&u.User), email.Bindings(&u.EmailColumns), phone.UserBindings(&u.Phone), username.UserBindings(&u.Handle))
}

func (u *appUser) Joins() []sqlb.Join { return []sqlb.Join{phone.UserJoin(), username.UserJoin()} }

// TestTx_AppAndAuthWritesCommitTogether: an app row and a library row in one
// transaction; a failure rolls back both, and no mail goes out for the
// rolled-back row.
func TestTx_AppAndAuthWritesCommitTogether(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		ctx := context.Background()
		if _, err := e.db.Exec("CREATE TABLE app_note (id " + auth.TypesFor(e.engine).Key + " NOT NULL PRIMARY KEY, user_id " + auth.TypesFor(e.engine).Key + " NOT NULL)"); err != nil {
			t.Fatal(err)
		}
		insertNote := func(tx *sql.Tx, id, userID string) error {
			q := "INSERT INTO app_note (id, user_id) VALUES (?, ?)"
			if e.engine == auth.EnginePostgres {
				q = "INSERT INTO app_note (id, user_id) VALUES ($1, $2)"
			}
			_, err := tx.ExecContext(ctx, q, id, userID)
			return err
		}
		errBoom := errors.New("boom")
		err := a.Tx(ctx, func(ctx context.Context, tx *sql.Tx) error {
			u, err := a.CreateUser(ctx, auth.NewUser{Name: "Rolled back"})
			if err != nil {
				return err
			}
			if _, err := a.CreateIdentity(ctx, auth.NewIdentity{UserID: u.ID, Kind: email.KindEmail, Raw: "ghost@example.com"}); err != nil {
				return err
			}
			if err := insertNote(tx, "note_1", u.ID); err != nil {
				return err
			}
			return errBoom
		})
		if !errors.Is(err, errBoom) {
			t.Fatalf("tx = %v", err)
		}
		var users, notes int
		_ = e.db.QueryRow("SELECT COUNT(*) FROM " + tbl(auth.TableNameUser)).Scan(&users)
		_ = e.db.QueryRow("SELECT COUNT(*) FROM app_note").Scan(&notes)
		if users != 0 || notes != 0 {
			t.Fatalf("after rollback: %d users, %d notes", users, notes)
		}
		if got := e.mail.To(a, "ghost@example.com"); len(got) != 0 {
			t.Fatalf("mail sent for a rolled-back row: %+v", got)
		}

		err = a.Tx(ctx, func(ctx context.Context, tx *sql.Tx) error {
			u, err := a.CreateUser(ctx, auth.NewUser{Name: "Kept"})
			if err != nil {
				return err
			}
			if _, err := a.CreateIdentity(ctx, auth.NewIdentity{UserID: u.ID, Kind: email.KindEmail, Raw: "kept@example.com"}); err != nil {
				return err
			}
			return insertNote(tx, "note_2", u.ID)
		})
		if err != nil {
			t.Fatal(err)
		}
		if got := e.mail.To(a, "kept@example.com"); len(got) != 1 {
			t.Fatalf("committed row: %d mails, want 1 verify link", len(got))
		}
	})
}

func TestScope_UniquePerTenant(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(email.ScopedByTenant()), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		acme := auth.WithScope(anon(a), "acme")
		globex := auth.WithScope(anon(a), "globex")
		one := must[password.SignInResult](t)(pw.SignUp(acme, password.SignUpRequest{Identifier: alice, Password: secret}))
		two := must[password.SignInResult](t)(pw.SignUp(globex, password.SignUpRequest{Identifier: alice, Password: "other passphrase"}))
		// Verify both: one address, verified in two tenants, is allowed.
		for _, m := range e.mail.To(a, alice) {
			if mm := tokenInLink.FindStringSubmatch(m.Text); mm != nil {
				if _, err := em.Verify(anon(a), auth.Token(mm[1])); err != nil {
					t.Fatalf("verify in its tenant: %v", err)
				}
			}
		}
		in := must[password.SignInResult](t)(pw.SignIn(globex, password.SignInRequest{Identifier: alice, Password: "other passphrase"}))
		if in.User.ID != two.User.ID || in.User.ID == one.User.ID {
			t.Fatalf("globex sign-in reached %s, want %s", in.User.ID, two.User.ID)
		}
		if _, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}); !errors.Is(err, auth.ErrNoScope) {
			t.Fatalf("sign-in without a tenant: %v, want ErrNoScope", err)
		}
	})
}
