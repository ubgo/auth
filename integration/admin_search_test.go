package integration

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/audit"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/phone"
)

// searchPeople are users whose addresses and names carry every character a
// LIKE or GLOB pattern treats as syntax, so a search that forgot to escape
// matches more than one of them.
var searchPeople = []struct{ name, address string }{
	{"Ada Lovelace", "ada_lovelace@example.com"},
	{"ada byron", "adaxlovelace@example.com"},
	{"Half 50%", "half50%off@example.com"},
	{"Half 500", "half500ff@example.com"},
	{"Bang!", "bang!x@example.com"},
	{"Star*Lord", "star@galaxy.io"},
	{"Star?Lord", "starq@galaxy.io"},
	{"[x] marks", "marks@galaxy.io"},
	{"Émile Zola", "ÉMILE@zola.fr"},
}

// seedSearch creates searchPeople from Go, each with a verified address, and
// returns their ids by name.
func seedSearch(t *testing.T, w *adminWorld) map[string]string {
	t.Helper()
	ids := map[string]string{}
	for _, p := range searchPeople {
		u := must[auth.User](t)(w.a.CreateUser(context.Background(), auth.NewUser{Name: p.name}))
		if err := w.em.SetFor(context.Background(), u.ID, p.address, true); err != nil {
			t.Fatal(err)
		}
		ids[p.name] = u.ID
	}
	return ids
}

// names returns the sorted display names of a page.
func names(r admin.UsersResult) []string {
	out := []string{}
	for _, u := range r.Users {
		out = append(out, u.Name)
	}
	slices.Sort(out)
	return out
}

// TestAdmin_SearchUsersMatchesFragmentsAsText: email search ignores case
// because both sides are folded in Go, name search keeps case, and every
// pattern character in the value matches only itself, on every engine.
func TestAdmin_SearchUsersMatchesFragmentsAsText(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newAdminWorld(t, e, nil)
		seedSearch(t, w)
		search := func(in admin.SearchUsersRequest) admin.UsersResult {
			t.Helper()
			return must[admin.UsersResult](t)(w.ad.SearchUsers(w.bossCtx(), in))
		}
		for _, c := range []struct {
			in   admin.SearchUsersRequest
			want []string
		}{
			// Email is the default field and contains the default operator.
			{admin.SearchUsersRequest{Value: "LOVELACE"}, []string{"Ada Lovelace", "ada byron"}},
			{admin.SearchUsersRequest{Value: "ada_"}, []string{"Ada Lovelace"}},
			{admin.SearchUsersRequest{Value: "50%"}, []string{"Half 50%"}},
			{admin.SearchUsersRequest{Value: "g!x"}, []string{"Bang!"}},
			{admin.SearchUsersRequest{Value: " Émi ", Field: admin.SearchEmail}, []string{"Émile Zola"}},
			{admin.SearchUsersRequest{Value: "star", Operator: admin.SearchStartsWith}, []string{"Star*Lord", "Star?Lord"}},
			{admin.SearchUsersRequest{Value: "@GALAXY.IO", Operator: admin.SearchEndsWith}, []string{"Star*Lord", "Star?Lord", "[x] marks"}},
			{admin.SearchUsersRequest{Value: "galaxy", Operator: admin.SearchEndsWith}, nil},
			{admin.SearchUsersRequest{Value: "lovelace", Operator: admin.SearchStartsWith}, nil},
			// Name keeps case: "ada" is not "Ada", on SQLite too.
			{admin.SearchUsersRequest{Value: "Ada", Field: admin.SearchName}, []string{"Ada Lovelace"}},
			{admin.SearchUsersRequest{Value: "ada", Field: admin.SearchName}, []string{"ada byron"}},
			{admin.SearchUsersRequest{Value: "émile", Field: admin.SearchName}, nil},
			{admin.SearchUsersRequest{Value: "*", Field: admin.SearchName}, []string{"Star*Lord"}},
			{admin.SearchUsersRequest{Value: "?", Field: admin.SearchName}, []string{"Star?Lord"}},
			{admin.SearchUsersRequest{Value: "[x]", Field: admin.SearchName, Operator: admin.SearchStartsWith}, []string{"[x] marks"}},
			{admin.SearchUsersRequest{Value: "%", Field: admin.SearchName, Operator: admin.SearchEndsWith}, []string{"Half 50%"}},
			{admin.SearchUsersRequest{Value: "_", Field: admin.SearchName}, nil},
			{admin.SearchUsersRequest{Value: "!", Field: admin.SearchName, Operator: admin.SearchEndsWith}, []string{"Bang!"}},
			{admin.SearchUsersRequest{Value: "Lord", Field: admin.SearchName, Operator: admin.SearchEndsWith}, []string{"Star*Lord", "Star?Lord"}},
		} {
			got := search(c.in)
			want := c.want
			if want == nil {
				want = []string{}
			}
			if !slices.Equal(names(got), want) || got.Total != int64(len(want)) {
				t.Errorf("%+v = %v (total %d), want %v", c.in, names(got), got.Total, want)
			}
		}

		// It pages, sorts and filters like the list.
		pg := search(admin.SearchUsersRequest{Value: "@", Limit: 2, Page: 2, Sort: admin.UserSortNameAsc})
		if pg.Total != int64(len(searchPeople)+2) || len(pg.Users) != 2 || pg.Page != 2 || pg.Limit != 2 || pg.Offset != 2 {
			t.Fatalf("page = %+v", pg)
		}
		if adm := search(admin.SearchUsersRequest{Value: "@", Admin: admin.FlagTrue}); adm.Total != 1 || adm.Users[0].ID != w.boss.User.ID {
			t.Fatalf("admins only = %+v", adm)
		}
	})
}

// TestAdmin_SearchUsersRefusals: the caller is checked before the input, and
// every input outside the closed sets or the length bound is refused.
func TestAdmin_SearchUsersRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newAdminWorld(t, e, nil)
		if _, err := w.ad.SearchUsers(request(w.a, w.bob.Token), admin.SearchUsersRequest{Field: "nope"}); !errors.Is(err, admin.ErrForbidden) {
			t.Fatalf("non-admin: %v", err)
		}
		for in, want := range map[*admin.SearchUsersRequest]error{
			{Value: "  "}: admin.ErrSearchValue,
			{Value: strings.Repeat("é", admin.MaxSearchLength+1)}:                               admin.ErrSearchValue,
			{Value: "x", Field: "phone"}:                                                        admin.ErrBadSearchField,
			{Value: "x", Operator: "like"}:                                                      admin.ErrBadSearchOperator,
			{Value: "x", Field: admin.SearchName, Operator: "like"}:                             admin.ErrBadSearchOperator,
			{Value: "x", Sort: "id"}:                                                            admin.ErrBadSort,
			{Value: "x", Banned: "maybe"}:                                                       admin.ErrBadFilter,
			{Value: strings.Repeat("é", admin.MaxSearchLength), Field: admin.SearchName}:        nil,
			{Value: strings.Repeat("é", admin.MaxSearchLength), Operator: admin.SearchEndsWith}: nil,
		} {
			if _, err := w.ad.SearchUsers(w.bossCtx(), *in); !errors.Is(err, want) || (want == nil && err != nil) {
				t.Errorf("%+v: %v, want %v", *in, err, want)
			}
		}
	})
}

// TestAdmin_SearchUsersWithoutEmailPlugin: an email search with no email
// plugin says so instead of answering an empty page; a name search works.
func TestAdmin_SearchUsersWithoutEmailPlugin(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ph, ad := e.phonePlugin(phone.Login(), phone.SignInWithCode()), admin.New()
		a := e.newAuth(t, nil, ph, ad)
		const number = "+14155550123"
		if err := ph.SendCode(anon(a), number); err != nil {
			t.Fatal(err)
		}
		in := must[phone.SignInResult](t)(ph.SignIn(anon(a), number, e.sms.LastCode(t, a, number)))
		if err := ad.Grant(context.Background(), in.User.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := a.CreateUser(context.Background(), auth.NewUser{Name: "Root"}); err != nil {
			t.Fatal(err)
		}
		tok := in.Token
		if _, err := ad.SearchUsers(request(a, tok), admin.SearchUsersRequest{Value: "x"}); !errors.Is(err, admin.ErrNoEmailPlugin) {
			t.Fatalf("email search without the plugin: %v", err)
		}
		if r := must[admin.UsersResult](t)(ad.SearchUsers(request(a, tok), admin.SearchUsersRequest{Value: "oo", Field: admin.SearchName})); r.Total != 1 {
			t.Fatalf("name search = %+v", r)
		}
	})
}

// TestAdmin_SearchUsersHasItsOwnRateRule: search-users is limited per IP by
// SearchRate, and the plain list is not counted against it.
func TestAdmin_SearchUsersHasItsOwnRateRule(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newAdminWorld(t, e, []admin.Option{admin.SearchRate(2, time.Minute)})
		for range 2 {
			if _, err := w.ad.SearchUsers(w.bossCtx(), admin.SearchUsersRequest{Value: "bob"}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := w.ad.Users(w.bossCtx(), admin.UsersRequest{}); err != nil {
			t.Fatalf("the list shares no budget with the search: %v", err)
		}
		if _, err := w.ad.SearchUsers(w.bossCtx(), admin.SearchUsersRequest{Value: "bob"}); !errors.Is(err, auth.ErrRateLimited) {
			t.Fatalf("third search: %v", err)
		}
		e.clock.Advance(time.Minute)
		if _, err := w.ad.SearchUsers(w.bossCtx(), admin.SearchUsersRequest{Value: "bob"}); err != nil {
			t.Fatalf("next window: %v", err)
		}
	})
}

// TestAdmin_ImpersonatingAdminsIsOptIn: by default an admin target is
// refused; with AllowImpersonatingAdmins it is allowed, with a fresh sign-in,
// the audit record, no admin operation from the impersonation session, and
// the way back; impersonating oneself is refused either way.
func TestAdmin_ImpersonatingAdminsIsOptIn(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		def := newAdminWorld(t, e, nil)
		if err := def.ad.SetAdmin(def.bossCtx(), def.bob.User.ID, true); err != nil {
			t.Fatal(err)
		}
		for _, target := range []string{def.bob.User.ID, def.boss.User.ID} {
			if _, err := def.ad.Impersonate(def.bossCtx(), admin.ImpersonateRequest{UserID: target}); !errors.Is(err, admin.ErrAdminTarget) {
				t.Fatalf("default, target %s: %v", target, err)
			}
		}
	})
	eachEngine(t, func(t *testing.T, e *env) {
		w := &adminWorld{em: e.emailPlugin(), pw: e.passwordPlugin(), ad: admin.New(admin.AllowImpersonatingAdmins())}
		au := audit.New()
		w.a = e.newAuth(t, nil, w.em, w.pw, w.ad, au)
		w.boss = signUpVerified(t, e, w.a, w.pw, w.em)
		w.bossMail = alice
		if err := w.ad.Grant(context.Background(), w.boss.User.ID); err != nil {
			t.Fatal(err)
		}
		w.bob = must[password.SignInResult](t)(w.pw.SignUp(anon(w.a), password.SignUpRequest{Identifier: "bob@example.com", Password: secret, Name: "Bob"}))
		w.bossCtx = func() context.Context { return request(w.a, w.boss.Token) }
		if err := w.ad.SetAdmin(w.bossCtx(), w.bob.User.ID, true); err != nil {
			t.Fatal(err)
		}
		if _, err := w.ad.Impersonate(w.bossCtx(), admin.ImpersonateRequest{UserID: w.boss.User.ID}); !errors.Is(err, admin.ErrSelfTarget) {
			t.Fatalf("self: %v", err)
		}
		// A fresh sign-in is still required.
		e.clock.Advance(auth.DefaultFreshWindow + time.Minute)
		if _, err := w.ad.Impersonate(w.bossCtx(), admin.ImpersonateRequest{UserID: w.bob.User.ID}); !errors.Is(err, auth.ErrFreshSessionRequired) {
			t.Fatalf("stale session: %v", err)
		}
		w.boss.Token = mustSignIn(t, w)
		as := must[admin.ImpersonateResult](t)(w.ad.Impersonate(w.bossCtx(), admin.ImpersonateRequest{UserID: w.bob.User.ID, Minutes: 600}))
		if got := as.ExpiresAt.Sub(e.clock.Now()); got > auth.MaxImpersonationTTL || as.User.ID != w.bob.User.ID {
			t.Fatalf("impersonation = %+v, lasts %v", as, got)
		}
		ev := must[audit.Page](t)(au.Events(context.Background(), audit.Query{Op: admin.EndpointImpersonate}))
		if len(ev.Events) == 0 || !ev.Events[0].OK || ev.Events[0].ActorID != w.boss.User.ID || ev.Events[0].SubjectID != w.bob.User.ID {
			t.Fatalf("audit = %+v", ev.Events)
		}
		// Acting as an admin grants none of the admin operations.
		acting := func() context.Context { return request(w.a, as.Token) }
		if _, err := w.ad.Users(acting(), admin.UsersRequest{}); !errors.Is(err, auth.ErrImpersonationRefused) {
			t.Fatalf("list while acting as an admin: %v", err)
		}
		if _, err := w.ad.SearchUsers(acting(), admin.SearchUsersRequest{Value: "x"}); !errors.Is(err, auth.ErrImpersonationRefused) {
			t.Fatalf("search while acting as an admin: %v", err)
		}
		if _, err := w.ad.Impersonate(acting(), admin.ImpersonateRequest{UserID: w.boss.User.ID}); !errors.Is(err, auth.ErrImpersonationRefused) {
			t.Fatalf("chained impersonation: %v", err)
		}
		r := must[admin.StopResult](t)(w.ad.StopImpersonating(withFlow(w.a, as.Token, as.AdminToken)))
		if !r.Restored {
			t.Fatalf("stop = %+v", r)
		}
		if _, err := w.ad.Users(request(w.a, as.AdminToken), admin.UsersRequest{}); err != nil {
			t.Fatalf("the restored admin session: %v", err)
		}
	})
}

// TestAdmin_SearchUsersEveryDatabaseFailureSurfaces: each database call of a
// search, by email and by name, fails the search when it fails.
func TestAdmin_SearchUsersEveryDatabaseFailureSurfaces(t *testing.T) {
	for _, field := range admin.SearchFieldValues {
		t.Run(string(field), func(t *testing.T) {
			sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
				w := newAdminWorld(t, e.env, nil)
				return func(context.Context) error {
					_, err := w.ad.SearchUsers(w.bossCtx(), admin.SearchUsersRequest{Value: "b", Field: field})
					return err
				}
			})
		})
	}
}
