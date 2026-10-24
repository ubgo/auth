package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/ldap"
	"github.com/ubgo/sqlb"
)

const (
	adaUser = "ada"
	adaPass = "correct horse battery staple"
	adaMail = "ada@example.com"
)

// newWorld wires the example's plugins over dir with extra options, on an
// in-memory database, and opens a browser on it.
func newWorld(t *testing.T, dir ldap.Directory, extra ...ldap.Option) (*authtest.Env, *authtest.Browser) {
	t.Helper()
	e := authtest.New(t, authtest.WithPlugins(func(*authtest.Env) []auth.Plugin { return plugins(dir, extra...) }))
	return e, e.Browser(newHandler(e.Auth))
}

func signIn(b *authtest.Browser, user, pass string) *authtest.Response {
	return b.Post("/auth/ldap/sign-in", map[string]string{"username": user, "password": pass})
}

// TestLDAP_FirstSignInCreatesThenSignsIn: the first sign-in creates the user
// from the entry (name, verified email); the next signs in to the same user.
//
//ds:def id=ldap-example-test-signin-2p8x4m6k
func TestLDAP_FirstSignInCreatesThenSignsIn(t *testing.T) {
	e, b := newWorld(t, demoDirectory())
	var first ldap.SignInResult
	signIn(b, adaUser, adaPass).Expect(http.StatusOK).Decode(&first)
	if !first.Created || first.User.Name != "Ada Lovelace" {
		t.Fatalf("first sign-in = %+v", first)
	}
	var who meResponse
	b.Get("/me").Expect(http.StatusOK).Decode(&who)
	if who.ID != first.User.ID {
		t.Fatalf("/me = %+v", who)
	}
	owner, err := e.Auth.FindIdentity(t.Context(), email.KindEmail, adaMail, true)
	if err != nil || owner.UserID != first.User.ID {
		t.Fatalf("the directory's address must be the new user's, verified: %+v %v", owner, err)
	}
	var again ldap.SignInResult
	signIn(b, adaUser, adaPass).Expect(http.StatusOK).Decode(&again)
	if again.Created || again.User.ID != first.User.ID {
		t.Fatalf("second sign-in = %+v", again)
	}
}

// TestLDAP_UnknownUserLooksLikeWrongPassword: an unknown username and a
// wrong password get byte-identical answers, so the endpoint does not tell
// a stranger who has an account.
func TestLDAP_UnknownUserLooksLikeWrongPassword(t *testing.T) {
	_, b := newWorld(t, demoDirectory())
	wrong := signIn(b, adaUser, "nope").Expect(http.StatusUnauthorized)
	unknown := signIn(b, "grace", "nope").Expect(http.StatusUnauthorized)
	if !bytes.Equal(wrong.Body, unknown.Body) || wrong.ErrorCode() != ldap.ErrCredentialsInvalid.Code {
		t.Fatalf("wrong password %s, unknown user %s", wrong.Body, unknown.Body)
	}
	if code := signIn(b, adaUser, "").Expect(http.StatusUnauthorized).ErrorCode(); code != ldap.ErrCredentialsInvalid.Code {
		t.Fatalf("an empty password: %s", code)
	}
}

// TestLDAP_LinksByVerifiedEmail: a person who already has a user with the
// directory's address, verified, gets that user on their first directory
// sign-in, not a second account.
func TestLDAP_LinksByVerifiedEmail(t *testing.T) {
	e, b := newWorld(t, demoDirectory())
	existing := e.CreateUser("Ada", authtest.Identity{Kind: email.KindEmail, Value: adaMail})
	var out ldap.SignInResult
	signIn(b, adaUser, adaPass).Expect(http.StatusOK).Decode(&out)
	if out.User.ID != existing.ID || !out.Linked || out.Created {
		t.Fatalf("sign-in = %+v, want the existing user %s linked", out, existing.ID)
	}
}

// TestLDAP_UntrustedEmailNeverLinks: with UntrustedEmail the same situation
// is refused, since linking would hand the user to whoever controls the
// directory entry.
func TestLDAP_UntrustedEmailNeverLinks(t *testing.T) {
	e, b := newWorld(t, demoDirectory(), ldap.UntrustedEmail())
	e.CreateUser("Ada", authtest.Identity{Kind: email.KindEmail, Value: adaMail})
	if code := signIn(b, adaUser, adaPass).Expect(http.StatusConflict).ErrorCode(); code != ldap.ErrAccountExists.Code {
		t.Fatalf("answered %s", code)
	}
}

// TestLDAP_UnverifiedAddressNeverLinks: a user who holds the directory's
// address but never proved it is not that address's owner, so the directory
// sign-in must not hand them the entry's session (or the entry theirs): it
// creates a user of its own.
func TestLDAP_UnverifiedAddressNeverLinks(t *testing.T) {
	e, b := newWorld(t, demoDirectory())
	u, err := e.Auth.CreateUser(t.Context(), auth.NewUser{Name: "Squatter"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Auth.CreateIdentity(t.Context(), auth.NewIdentity{UserID: u.ID, Kind: email.KindEmail, Raw: adaMail, Verified: false}); err != nil {
		t.Fatal(err)
	}
	var out ldap.SignInResult
	signIn(b, adaUser, adaPass).Expect(http.StatusOK).Decode(&out)
	if out.User.ID == u.ID || out.Linked || !out.Created {
		t.Fatalf("sign-in = %+v, must not link to the unverified holder %s", out, u.ID)
	}
}

// TestLDAP_UntrustedEmailIsStoredUnverified: under UntrustedEmail a new
// user's directory address is kept unverified, so it cannot later be used
// to recover or take over an account.
func TestLDAP_UntrustedEmailIsStoredUnverified(t *testing.T) {
	e, b := newWorld(t, demoDirectory(), ldap.UntrustedEmail())
	var out ldap.SignInResult
	signIn(b, adaUser, adaPass).Expect(http.StatusOK).Decode(&out)
	if _, err := e.Auth.FindIdentity(t.Context(), email.KindEmail, adaMail, true); !errors.Is(err, auth.ErrIdentityNotFound) {
		t.Fatalf("a verified identity for the directory address exists: %v", err)
	}
	got, err := e.Auth.FindIdentity(t.Context(), email.KindEmail, adaMail, false)
	if err != nil || got.UserID != out.User.ID {
		t.Fatalf("unverified identity = %+v, %v", got, err)
	}
}

// TestLDAP_NoSignUp: with NoSignUp a directory account with no user to link
// to is refused, and one whose address matches signs in.
func TestLDAP_NoSignUp(t *testing.T) {
	e, b := newWorld(t, demoDirectory(), ldap.NoSignUp())
	if code := signIn(b, adaUser, adaPass).Expect(http.StatusForbidden).ErrorCode(); code != ldap.ErrSignUpDisabled.Code {
		t.Fatalf("answered %s", code)
	}
	e.CreateUser("Ada", authtest.Identity{Kind: email.KindEmail, Value: adaMail})
	signIn(b, adaUser, adaPass).Expect(http.StatusOK)
}

// TestLDAP_RenamedEntryKeepsItsUser: the subject is entryUUID, so a renamed
// entry with a new address still signs in to the same user.
func TestLDAP_RenamedEntryKeepsItsUser(t *testing.T) {
	dir := demoDirectory()
	_, b := newWorld(t, dir)
	var first ldap.SignInResult
	signIn(b, adaUser, adaPass).Expect(http.StatusOK).Decode(&first)
	u := dir.users[adaUser]
	u.entry = ldap.Entry{DN: "uid=ada.king,ou=staff,dc=example,dc=com", Attributes: map[string][]string{
		"cn": {"Ada King"}, "mail": {"ada.king@example.com"}, "entryUUID": u.entry.Attributes["entryUUID"],
	}}
	dir.users[adaUser] = u
	var again ldap.SignInResult
	signIn(b, adaUser, adaPass).Expect(http.StatusOK).Decode(&again)
	if again.User.ID != first.User.ID || again.Created {
		t.Fatalf("after the rename = %+v, want user %s", again, first.User.ID)
	}
}

// TestLDAP_MapProfileRefuses: MapProfile is the place for an allow rule; an
// error from it refuses the sign-in after the password was proven.
func TestLDAP_MapProfileRefuses(t *testing.T) {
	staffOnly := ldap.MapProfile(func(e ldap.Entry) (ldap.Profile, error) {
		return ldap.Profile{}, errors.New("not in the staff group")
	})
	_, b := newWorld(t, demoDirectory(), staffOnly)
	if code := signIn(b, adaUser, adaPass).Expect(http.StatusForbidden).ErrorCode(); code != ldap.ErrProfileRefused.Code {
		t.Fatalf("answered %s", code)
	}
}

// TestLDAP_DirectoryDown: an unreachable directory is a 503, never "wrong
// password", so an outage does not send people to reset passwords.
func TestLDAP_DirectoryDown(t *testing.T) {
	dir := demoDirectory()
	dir.down = true
	_, b := newWorld(t, dir)
	if code := signIn(b, adaUser, adaPass).Expect(http.StatusServiceUnavailable).ErrorCode(); code != ldap.ErrDirectoryUnavailable.Code {
		t.Fatalf("answered %s", code)
	}
}

// TestLDAP_RateLimitsPerUsername: guesses at one username stop at the
// per-username limit, before the directory's own lockout would lock the
// person out everywhere.
func TestLDAP_RateLimitsPerUsername(t *testing.T) {
	_, b := newWorld(t, demoDirectory())
	limited := false
	for range 10 {
		if signIn(b, adaUser, "guess").Status == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("ten guesses at one username were never limited")
	}
}

// sweepWorld is a fresh Env with a counter on its database and the ldap
// plugin built the way the app builds it.
func sweepWorld(t *testing.T, dir ldap.Directory, extra ...ldap.Option) (*authtest.Env, *ldap.Plugin) {
	t.Helper()
	var lp *ldap.Plugin
	e := authtest.New(t, authtest.WithFaults(authtest.NewFaults()), authtest.WithPlugins(func(*authtest.Env) []auth.Plugin {
		ps := plugins(dir, extra...)
		lp = ps[len(ps)-1].(*ldap.Plugin)
		return ps
	}))
	return e, lp
}

// TestLDAP_EveryDatabaseFailureReachesTheCaller: the directory sign-in is
// run once per database call it makes, each time with that call failing;
// every run must return the failure, so a first sign-in that could not store
// its link, or a sign-in that could not look the link up, never reports
// success. It covers the three paths: a new user, a link to the user who
// holds the address, and a returning user.
func TestLDAP_EveryDatabaseFailureReachesTheCaller(t *testing.T) {
	signIn := func(e *authtest.Env, lp *ldap.Plugin) error {
		_, err := lp.SignIn(e.Anonymous(context.Background()), adaUser, adaPass)
		return err
	}
	for name, setup := range map[string]func(e *authtest.Env, lp *ldap.Plugin){
		"a new user": func(*authtest.Env, *ldap.Plugin) {},
		"link to the holder of the address": func(e *authtest.Env, _ *ldap.Plugin) {
			e.CreateUser("Ada", authtest.Identity{Kind: email.KindEmail, Value: adaMail})
		},
		"a returning user": func(e *authtest.Env, lp *ldap.Plugin) {
			if err := signIn(e, lp); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			authtest.SweepFaults(t,
				func() (*sweepEnv, *authtest.Faults) {
					e, lp := sweepWorld(t, demoDirectory())
					return &sweepEnv{e, lp}, e.Faults
				},
				func(s *sweepEnv) func(context.Context) error {
					setup(s.Env, s.lp)
					return func(context.Context) error { return signIn(s.Env, s.lp) }
				})
		})
	}
}

// sweepEnv is an Env with the plugin the sweep drives.
type sweepEnv struct {
	*authtest.Env
	lp *ldap.Plugin
}

// TestLDAP_ProfileMappingAndAnEntryWithoutASubject: the attribute map reads
// the image; a binary subject (objectGUID) is hex-encoded so it can be stored
// and compared; an entry with no subject at all is refused rather than linked
// under an empty key every such entry would share.
func TestLDAP_ProfileMappingAndAnEntryWithoutASubject(t *testing.T) {
	dir := &memoryDirectory{users: map[string]memoryUser{}}
	dir.add("grace", "pass", ldap.Entry{DN: "uid=grace,dc=example,dc=com", Attributes: map[string][]string{
		"cn": {"Grace"}, "mail": {"grace@example.com"}, "objectGUID": {"\x01\x02\xff"}, "thumbnailURL": {"https://img.example/grace.png"},
	}})
	dir.add("nobody", "pass", ldap.Entry{DN: "", Attributes: map[string][]string{"cn": {"No Subject"}}})
	e, b := newWorld(t, dir, ldap.MapAttributes(ldap.AttributeMap{Subject: "objectGUID", Image: "thumbnailURL"}))
	var out ldap.SignInResult
	signIn(b, "grace", "pass").Expect(http.StatusOK).Decode(&out)
	if out.User.Image != "https://img.example/grace.png" || !out.Created {
		t.Fatalf("grace = %+v, want her image from thumbnailURL", out)
	}
	var again ldap.SignInResult
	signIn(b, "grace", "pass").Expect(http.StatusOK).Decode(&again)
	if again.Created || again.User.ID != out.User.ID {
		t.Fatalf("a binary subject must find the same user again: %+v", again)
	}
	var stored string
	if err := e.Auth.One(t.Context(), e.Auth.Select().Columns(sqlb.Bind(ldap.AccountSubject, &stored)).From(ldap.TableAccount).Where(sqlb.Eq(ldap.AccountUserID, out.User.ID))); err != nil {
		t.Fatal(err)
	}
	if stored != "0102ff" {
		t.Fatalf("stored subject = %q, want the hex of the binary value", stored)
	}
	if code := signIn(b, "nobody", "pass").Expect(http.StatusForbidden).ErrorCode(); code != ldap.ErrProfileRefused.Code {
		t.Fatalf("an entry with no subject answered %s", code)
	}
}

// TestLDAP_AddressTheEmailPluginRefusesIsDropped: a directory holding an
// address the email plugin would not accept still signs its user in, without
// the address, instead of locking them out of the app.
func TestLDAP_AddressTheEmailPluginRefusesIsDropped(t *testing.T) {
	dir := &memoryDirectory{users: map[string]memoryUser{}}
	dir.add("odd", "pass", ldap.Entry{DN: "uid=odd,dc=example,dc=com", Attributes: map[string][]string{"cn": {"Odd"}, "mail": {"not an address"}, "entryUUID": {"odd-1"}}})
	_, b := newWorld(t, dir)
	var out ldap.SignInResult
	signIn(b, "odd", "pass").Expect(http.StatusOK).Decode(&out)
	if !out.Created {
		t.Fatalf("sign-in = %+v", out)
	}
}

// TestLDAP_DirectoryFuncAdaptsAFunction: DirectoryFunc is a Directory.
func TestLDAP_DirectoryFuncAdaptsAFunction(t *testing.T) {
	dir := ldap.DirectoryFunc(func(_ context.Context, user, _ string) (ldap.Entry, error) {
		return ldap.Entry{DN: "uid=" + user, Attributes: map[string][]string{"cn": {"Fn"}, "entryUUID": {"fn-1"}}}, nil
	})
	_, b := newWorld(t, dir)
	signIn(b, "any", "pass").Expect(http.StatusOK)
}

// TestLDAP_MapAttributesReadsEmailAndName: the attribute map names where the
// address and the display name live, for a directory that does not use mail
// and cn.
func TestLDAP_MapAttributesReadsEmailAndName(t *testing.T) {
	dir := &memoryDirectory{users: map[string]memoryUser{}}
	dir.add("kim", "pass", ldap.Entry{DN: "uid=kim,dc=example,dc=com", Attributes: map[string][]string{
		"displayName": {"Kim Doe"}, "userPrincipalName": {"kim@example.com"}, "entryUUID": {"kim-1"},
	}})
	e, b := newWorld(t, dir, ldap.MapAttributes(ldap.AttributeMap{Email: "userPrincipalName", Name: "displayName"}))
	var out ldap.SignInResult
	signIn(b, "kim", "pass").Expect(http.StatusOK).Decode(&out)
	if out.User.Name != "Kim Doe" {
		t.Fatalf("name = %q, want displayName", out.User.Name)
	}
	if owner, err := e.Auth.FindIdentity(t.Context(), email.KindEmail, "kim@example.com", true); err != nil || owner.UserID != out.User.ID {
		t.Fatalf("address from userPrincipalName: %+v, %v", owner, err)
	}
}

// TestLDAP_MapProfileErrorsKeepTheirCode: a MapProfile error that is already
// an *auth.Error is the answer as it is (an app's own refusal with its own
// status and code); any other error is the generic ldap.profile_refused.
func TestLDAP_MapProfileErrorsKeepTheirCode(t *testing.T) {
	notStaff := auth.NewError("app.not_staff", http.StatusForbidden, "Staff only.")
	_, b := newWorld(t, demoDirectory(), ldap.MapProfile(func(ldap.Entry) (ldap.Profile, error) { return ldap.Profile{}, notStaff }))
	if code := signIn(b, adaUser, adaPass).Expect(http.StatusForbidden).ErrorCode(); code != notStaff.Code {
		t.Fatalf("answered %s, want the app's own %s", code, notStaff.Code)
	}
}

// TestLDAP_AFailedIDLeavesNoHalfLinkedUser: when the link row cannot get an
// id the sign-in fails as a whole, and nothing of the new user is kept.
func TestLDAP_AFailedIDLeavesNoHalfLinkedUser(t *testing.T) {
	ids := auth.WithIDs(func(prefix string) (string, error) {
		if prefix == "lda" {
			return "", errors.New("ids down")
		}
		return auth.NewID(prefix)
	})
	e := authtest.New(t, authtest.WithOptions(ids), authtest.WithPlugins(func(*authtest.Env) []auth.Plugin { return plugins(demoDirectory()) }))
	b := e.Browser(newHandler(e.Auth))
	signIn(b, adaUser, adaPass).Expect(http.StatusInternalServerError)
	if _, err := e.Auth.FindIdentity(t.Context(), email.KindEmail, adaMail, false); !errors.Is(err, auth.ErrIdentityNotFound) {
		t.Fatalf("the failed sign-in left an identity behind: %v", err)
	}
}

// TestLDAP_RacingFirstSignInsAreTold: two first sign-ins of one entry race;
// the loser's link row hits the unique subject and gets ldap.sign_in_conflict
// to retry, not a second user. The race is staged by a hook that inserts the
// winner's row between the loser's lookup and its own insert.
func TestLDAP_RacingFirstSignInsAreTold(t *testing.T) {
	winner := auth.WithDataHooks(auth.DataHooks{User: auth.TableHooks[auth.User]{AfterCreate: func(ctx context.Context, tx sqlb.DBTX, u *auth.User) error {
		_, err := tx.ExecContext(ctx, "INSERT INTO auth_ldap_account (id, user_id, subject, dn, created_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?)",
			"lda_winner", "usr_winner", "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d", "uid=ada", time.Now(), time.Now())
		return err
	}}})
	e := authtest.New(t, authtest.WithOptions(winner), authtest.WithPlugins(func(*authtest.Env) []auth.Plugin { return plugins(demoDirectory()) }))
	b := e.Browser(newHandler(e.Auth))
	if code := signIn(b, adaUser, adaPass).Expect(http.StatusConflict).ErrorCode(); code != ldap.ErrSignInConflict.Code {
		t.Fatalf("the loser answered %s, want %s", code, ldap.ErrSignInConflict.Code)
	}
}

// TestLDAP_SignInCredentialsCountsLinkedAccounts: the core's last-way-in
// check counts a user's directory accounts, leaving out the one being
// removed, so removing the only way in is refused.
func TestLDAP_SignInCredentialsCountsLinkedAccounts(t *testing.T) {
	e, lp := sweepWorld(t, demoDirectory())
	out, err := lp.SignIn(e.Anonymous(t.Context()), adaUser, adaPass)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := lp.SignInCredentials(t.Context(), out.User.ID, ""); err != nil || n != 1 {
		t.Fatalf("credentials = %d, %v; want 1", n, err)
	}
	var accountID string
	if err := e.Auth.One(t.Context(), e.Auth.Select().Columns(sqlb.Bind(ldap.AccountID, &accountID)).From(ldap.TableAccount).Where(sqlb.Eq(ldap.AccountUserID, out.User.ID))); err != nil {
		t.Fatal(err)
	}
	if n, err := lp.SignInCredentials(t.Context(), out.User.ID, accountID); err != nil || n != 0 {
		t.Fatalf("credentials without the account being removed = %d, %v; want 0", n, err)
	}
}
