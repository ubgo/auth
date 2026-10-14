package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/access/accessadmin"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
)

// p3 app columns: a plan and a seat count the app owns, for update-user's
// data.
var (
	p3Plan  = sqlb.Col[string](auth.TableUser, "p3_plan")
	p3Seats = sqlb.Col[int64](auth.TableUser, "p3_seats")
)

// errP3Plan is the app's own refusal of a plan, from an Editable check.
var errP3Plan = auth.NewError("app.bad_plan", http.StatusBadRequest, "No such plan.")

// p3AdminWorld is newAdminWorld with Go-level options for the Auth, which
// update-user's app columns and the session store need.
func p3AdminWorld(t *testing.T, e *env, opts []auth.Option, adminOpts ...admin.Option) *adminWorld {
	t.Helper()
	w := &adminWorld{em: e.emailPlugin(), pw: e.passwordPlugin(), ad: admin.New(adminOpts...)}
	w.a = e.newAuth(t, opts, w.em, w.pw, w.ad)
	w.boss = signUpVerified(t, e, w.a, w.pw, w.em)
	w.bossMail = alice
	if err := w.ad.Grant(context.Background(), w.boss.User.ID); err != nil {
		t.Fatal(err)
	}
	w.bob = must[password.SignInResult](t)(w.pw.SignUp(anon(w.a), password.SignUpRequest{Identifier: "bob@example.com", Password: secret, Name: "Bob"}))
	if _, err := w.em.Verify(anon(w.a), e.mail.LastToken(t, w.a, "bob@example.com")); err != nil {
		t.Fatal(err)
	}
	w.bossCtx = func() context.Context { return request(w.a, w.boss.Token) }
	return w
}

func p3Str(s string) *string { return &s }

// TestP3Admin_FilterEveryField: every filter field with its operators, on
// every engine: addresses ignore case, names keep it, roles follow RolesOf,
// times compare as times, and the negations include users the positive form
// misses.
func TestP3Admin_FilterEveryField(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newAdminWorld(t, e, nil)
		e.clock.Advance(time.Hour)
		cut := e.clock.Now()
		e.clock.Advance(time.Hour)
		ids := seedSearch(t, w)
		// A user with no address at all, for emailVerified false and ne.
		bare := must[auth.User](t)(w.a.CreateUser(context.Background(), auth.NewUser{Name: "No Mail"}))
		if err := w.ad.BanFor(context.Background(), w.bob.User.ID, "spam ring", e.clock.Now().Add(48*time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := w.ad.BanFor(context.Background(), ids["Bang!"], "forever", time.Time{}); err != nil {
			t.Fatal(err)
		}
		everyone := []string{"Ada Lovelace", "Bang!", "Bob", "Half 50%", "Half 500", "No Mail", "Star*Lord", "Star?Lord", "[x] marks", "ada byron", "Émile Zola", w.boss.User.Name}
		slices.Sort(everyone)
		without := func(drop ...string) []string {
			return slices.DeleteFunc(slices.Clone(everyone), func(n string) bool { return slices.Contains(drop, n) })
		}
		list := func(in admin.UsersRequest) admin.UsersResult {
			t.Helper()
			in.Limit = admin.MaxPageSize
			return must[admin.UsersResult](t)(w.ad.Users(w.bossCtx(), in))
		}
		f := func(field admin.FilterField, op admin.FilterOperator, v string) admin.UsersRequest {
			return admin.UsersRequest{FilterField: field, FilterOperator: op, FilterValue: p3Str(v)}
		}
		later := e.clock.Now().Add(time.Hour).Format(time.RFC3339Nano)
		for _, c := range []struct {
			in   admin.UsersRequest
			want []string
		}{
			// Email is the default field and eq the default operator.
			{admin.UsersRequest{FilterValue: p3Str("ADA_LOVELACE@EXAMPLE.COM")}, []string{"Ada Lovelace"}},
			{f(admin.FilterEmail, admin.FilterNe, "bob@example.com"), without("Bob")},
			{f(admin.FilterEmail, admin.FilterIn, "bob@example.com, STAR@galaxy.io"), []string{"Bob", "Star*Lord"}},
			{f(admin.FilterEmail, admin.FilterNotIn, "bob@example.com,star@galaxy.io"), without("Bob", "Star*Lord")},
			{f(admin.FilterEmail, admin.FilterContains, "50%"), []string{"Half 50%"}},
			{f(admin.FilterEmail, admin.FilterStartsWith, "star"), []string{"Star*Lord", "Star?Lord"}},
			{f(admin.FilterEmail, admin.FilterEndsWith, "@galaxy.io"), []string{"Star*Lord", "Star?Lord", "[x] marks"}},
			{f(admin.FilterEmailVerified, admin.FilterEq, "false"), []string{"No Mail"}},
			{f(admin.FilterEmailVerified, admin.FilterNe, "false"), without("No Mail")},
			{f(admin.FilterID, admin.FilterEq, bare.ID), []string{"No Mail"}},
			{f(admin.FilterID, admin.FilterIn, bare.ID+","+w.bob.User.ID), []string{"Bob", "No Mail"}},
			{f(admin.FilterName, admin.FilterEq, "Ada Lovelace"), []string{"Ada Lovelace"}},
			{f(admin.FilterName, admin.FilterEq, "ada lovelace"), nil},
			{f(admin.FilterName, admin.FilterContains, "ada"), []string{"ada byron"}},
			{f(admin.FilterName, admin.FilterStartsWith, "Star*"), []string{"Star*Lord"}},
			{f(admin.FilterName, admin.FilterNotIn, "Bob,No Mail"), without("Bob", "No Mail")},
			{f(admin.FilterRole, admin.FilterEq, admin.RoleAdmin), []string{w.boss.User.Name}},
			{f(admin.FilterRole, admin.FilterNe, admin.RoleUser), []string{w.boss.User.Name}},
			{f(admin.FilterRole, admin.FilterIn, "admin,user"), everyone},
			{f(admin.FilterBanned, admin.FilterEq, "true"), []string{"Bang!", "Bob"}},
			{f(admin.FilterBanned, admin.FilterNe, "true"), without("Bang!", "Bob")},
			{f(admin.FilterBanReason, admin.FilterContains, "spam"), []string{"Bob"}},
			// A permanent ban has no end, so no time comparison matches it.
			{f(admin.FilterBanExpires, admin.FilterGt, e.clock.Now().Format(time.RFC3339Nano)), []string{"Bob"}},
			{f(admin.FilterBanExpires, admin.FilterLt, later), nil},
			{f(admin.FilterCreatedAt, admin.FilterLt, cut.Format(time.RFC3339Nano)), []string{w.boss.User.Name, "Bob"}},
			{f(admin.FilterCreatedAt, admin.FilterGte, cut.Format(time.RFC3339Nano)), without("Bob", w.boss.User.Name)},
			{f(admin.FilterUpdatedAt, admin.FilterGt, later), nil},
		} {
			got := list(c.in)
			want := c.want
			if want == nil {
				want = []string{}
			}
			if !slices.Equal(names(got), want) || got.Total != int64(len(want)) {
				t.Errorf("%s %s %v = %v (total %d), want %v", c.in.FilterField, c.in.FilterOperator, *c.in.FilterValue, names(got), got.Total, want)
			}
		}

		// The filter combines with the flags and with search-users.
		if got := list(admin.UsersRequest{Banned: admin.FlagTrue, FilterField: admin.FilterName, FilterValue: p3Str("Bob")}); got.Total != 1 {
			t.Fatalf("flag and filter = %+v", got)
		}
		s := must[admin.UsersResult](t)(w.ad.SearchUsers(w.bossCtx(), admin.SearchUsersRequest{Value: "galaxy", FilterField: admin.FilterName, FilterOperator: admin.FilterEndsWith, FilterValue: p3Str("Lord")}))
		if !slices.Equal(names(s), []string{"Star*Lord", "Star?Lord"}) {
			t.Fatalf("search with a filter = %v", names(s))
		}

		for _, c := range []struct {
			in   admin.UsersRequest
			want error
		}{
			{admin.UsersRequest{FilterField: "password"}, admin.ErrBadFilterField},
			{admin.UsersRequest{FilterField: admin.FilterEmail, FilterOperator: admin.FilterLt}, admin.ErrBadFilterOperator},
			{admin.UsersRequest{FilterOperator: "like"}, admin.ErrBadFilterOperator},
			{f(admin.FilterBanned, admin.FilterEq, "maybe"), admin.ErrBadFilterValue},
			{f(admin.FilterEmailVerified, admin.FilterEq, "yes"), admin.ErrBadFilterValue},
			{f(admin.FilterCreatedAt, admin.FilterGt, "yesterday"), admin.ErrBadFilterValue},
			{f(admin.FilterBanExpires, admin.FilterGt, "soon"), admin.ErrBadFilterValue},
			{f(admin.FilterID, admin.FilterIn, "a,,b"), admin.ErrBadFilterValue},
			{f(admin.FilterName, admin.FilterEq, " "), admin.ErrBadFilterValue},
		} {
			if _, err := w.ad.Users(w.bossCtx(), c.in); !errors.Is(err, c.want) {
				t.Errorf("%+v = %v, want %v", c.in, err, c.want)
			}
		}
		// A non-admin is refused before the filter is read.
		if _, err := w.ad.Users(request(w.a, w.bob.Token), admin.UsersRequest{FilterField: "password"}); err == nil || errors.Is(err, admin.ErrBadFilterField) {
			t.Fatalf("non-admin with a bad filter = %v", err)
		}
	})
}

// TestP3Admin_RoleFilterFollowsRolesOf: a stored role list, the flag's admin
// role for a user granted without one, AdminIDs, and the default role only
// for a user with neither.
func TestP3Admin_RoleFilterFollowsRolesOf(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		roles := accessadmin.DefaultRoles()
		roles["support"] = roles[admin.RoleUser]
		roles["support_x"] = roles[admin.RoleUser]
		w := newAdminWorld(t, e, []admin.Option{admin.WithAuthorizer(accessadmin.MustNew(accessadmin.DefaultAccessControl, roles))})
		carol := must[auth.User](t)(w.a.CreateUser(context.Background(), auth.NewUser{Name: "Carol"}))
		if err := w.ad.SetRoleFor(context.Background(), w.bob.User.ID, "support", admin.RoleUser); err != nil {
			t.Fatal(err)
		}
		if err := w.ad.SetRoleFor(context.Background(), carol.ID, "support_x"); err != nil {
			t.Fatal(err)
		}
		role := func(op admin.FilterOperator, v string) []string {
			t.Helper()
			return names(must[admin.UsersResult](t)(w.ad.Users(w.bossCtx(), admin.UsersRequest{FilterField: admin.FilterRole, FilterOperator: op, FilterValue: p3Str(v)})))
		}
		// "support" is a whole element, so support_x does not hold it; _ is
		// text, not a LIKE wildcard.
		if got := role(admin.FilterEq, "support"); !slices.Equal(got, []string{"Bob"}) {
			t.Fatalf("support = %v", got)
		}
		if got := role(admin.FilterEq, admin.RoleUser); !slices.Equal(got, []string{"Bob"}) {
			t.Fatalf("user = %v (carol holds only support_x, boss only admin)", got)
		}
		if got := role(admin.FilterNotIn, "support,support_x"); !slices.Equal(got, []string{w.boss.User.Name}) {
			t.Fatalf("not_in = %v", got)
		}
	})
}

// TestP3Admin_SortByEveryField: sortBy with each direction, ascending by
// default, alongside the older sort values; mixing the two is refused.
func TestP3Admin_SortByEveryField(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newAdminWorld(t, e, nil)
		e.clock.Advance(time.Minute)
		carol := must[auth.User](t)(w.a.CreateUser(context.Background(), auth.NewUser{Name: "Carol"}))
		order := func(in admin.UsersRequest) []string {
			t.Helper()
			var out []string
			for _, u := range must[admin.UsersResult](t)(w.ad.Users(w.bossCtx(), in)).Users {
				out = append(out, u.ID)
			}
			return out
		}
		boss, bob := w.boss.User.ID, w.bob.User.ID
		byID := []string{boss, bob, carol.ID}
		slices.Sort(byID)
		for _, c := range []struct {
			in   admin.UsersRequest
			want []string
		}{
			{admin.UsersRequest{SortBy: admin.SortByName}, []string{boss, bob, carol.ID}},
			{admin.UsersRequest{SortBy: admin.SortByName, SortDirection: admin.SortDesc}, []string{carol.ID, bob, boss}},
			{admin.UsersRequest{SortBy: admin.SortByCreatedAt, SortDirection: admin.SortDesc}, []string{carol.ID, bob, boss}[:1]},
			{admin.UsersRequest{SortBy: admin.SortByID}, byID},
			{admin.UsersRequest{SortBy: admin.SortByID, SortDirection: admin.SortDesc}, []string{byID[2], byID[1], byID[0]}},
		} {
			got := order(c.in)
			if !slices.Equal(got[:len(c.want)], c.want) {
				t.Errorf("%+v = %v, want %v", c.in, got, c.want)
			}
		}
		// Updating a user moves it to the end of updatedAt ascending.
		e.clock.Advance(time.Minute)
		if err := w.ad.UpdateUser(w.bossCtx(), admin.UpdateUserRequest{UserID: bob, Name: p3Str("Bobby")}); err != nil {
			t.Fatal(err)
		}
		if got := order(admin.UsersRequest{SortBy: admin.SortByUpdatedAt}); got[len(got)-1] != bob {
			t.Fatalf("updatedAt asc = %v, want bob last", got)
		}
		for _, in := range []admin.UsersRequest{
			{SortBy: admin.SortByName, Sort: admin.UserSortNameAsc},
			{SortDirection: admin.SortDesc},
			{SortBy: admin.SortByName, SortDirection: "sideways"},
			{SortBy: "email"},
		} {
			if _, err := w.ad.Users(w.bossCtx(), in); !errors.Is(err, admin.ErrBadSort) {
				t.Errorf("%+v = %v, want ErrBadSort", in, err)
			}
		}
	})
}

// TestP3Admin_UpdateUserData: data sets the profile fields and the declared
// app columns, typed and checked; every key is checked before the first
// write, and a write that fails rolls the whole edit back.
func TestP3Admin_UpdateUserData(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		cols := auth.WithUserColumns(
			auth.ColumnExtension{Name: p3Plan.Name(), Type: auth.ColumnText, Default: "'free'"},
			auth.ColumnExtension{Name: p3Seats.Name(), Type: auth.ColumnInt, Default: "1"},
		)
		checkPlan := func(v string) error {
			if v != "free" && v != "pro" {
				return errP3Plan
			}
			return nil
		}
		w := p3AdminWorld(t, e, []auth.Option{cols}, admin.EditableColumns(
			admin.Editable(p3Plan, checkPlan), admin.Editable(p3Seats, nil),
			// A plugin's column declared by mistake: SetUserColumn refuses it
			// at the write, and the edit rolls back.
			admin.Editable(admin.BanReason, nil),
		))
		bob := w.bob.User.ID
		update := func(data string) error {
			var m map[string]json.RawMessage
			if err := json.Unmarshal([]byte(data), &m); err != nil {
				t.Fatal(err)
			}
			return w.ad.UpdateUser(w.bossCtx(), admin.UpdateUserRequest{UserID: bob, Data: m})
		}
		read := func() (string, string, int64) {
			t.Helper()
			var name, plan string
			var seats int64
			if err := w.a.LoadUserColumns(context.Background(), bob, sqlb.Bind(auth.UserName, &name), sqlb.Bind(p3Plan, &plan), sqlb.Bind(p3Seats, &seats)); err != nil {
				t.Fatal(err)
			}
			return name, plan, seats
		}
		if err := update(`{"name":"Robert","p3_plan":"pro","p3_seats":5}`); err != nil {
			t.Fatal(err)
		}
		if n, p, s := read(); n != "Robert" || p != "pro" || s != 5 {
			t.Fatalf("after update = %q %q %d", n, p, s)
		}
		for data, want := range map[string]error{
			`{}`:                                 admin.ErrNoUserData,
			`{"name":"X","password":"hunter2"}`:  admin.ErrFieldNotEditable,
			`{"name":"X","role":"admin"}`:        admin.ErrFieldNotEditable,
			`{"name":"X","email":"x@y.z"}`:       admin.ErrFieldNotEditable,
			`{"name":"X","p3_plan":"gold"}`:      errP3Plan,
			`{"name":"X","p3_plan":7}`:           admin.ErrBadUserData,
			`{"name":"X","p3_seats":"many"}`:     admin.ErrBadUserData,
			`{"name":7}`:                         admin.ErrBadUserData,
			`{"name":"X","admin_ban_reason":""}`: auth.ErrNotColumnOwner,
		} {
			if err := update(data); !errors.Is(err, want) {
				t.Errorf("%s = %v, want %v", data, err, want)
			}
			if n, p, s := read(); n != "Robert" || p != "pro" || s != 5 {
				t.Fatalf("%s changed the user: %q %q %d", data, n, p, s)
			}
		}
		// Without data the fields work as before.
		if err := w.ad.UpdateUser(w.bossCtx(), admin.UpdateUserRequest{UserID: bob, Name: p3Str("Bob")}); err != nil {
			t.Fatal(err)
		}
		// A non-admin is refused before the data is read.
		if err := w.ad.UpdateUser(request(w.a, w.bob.Token), admin.UpdateUserRequest{UserID: bob, Data: map[string]json.RawMessage{}}); !errors.Is(err, admin.ErrForbidden) {
			t.Fatalf("non-admin = %v", err)
		}
	})
}

// TestP3Admin_AllSessionsAndLastActive: the fleet list pages every live
// session, narrows to one user, and leaves out ended ones; a user's last
// activity comes from their sessions; a store with no table is refused.
func TestP3Admin_AllSessionsAndLastActive(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newAdminWorld(t, e, nil)
		e.clock.Advance(time.Minute)
		must[password.SignInResult](t)(w.pw.SignIn(anon(w.a), password.SignInRequest{Identifier: "bob@example.com", Password: secret}))
		sessionsOf := func(a *auth.Auth, userID string) []auth.Session {
			t.Helper()
			return must[[]auth.Session](t)(a.Sessions(context.Background(), userID))
		}
		// Newest first: the second sign-in's session.
		second := sessionsOf(w.a, w.bob.User.ID)[0]
		carol := must[auth.User](t)(w.a.CreateUser(context.Background(), auth.NewUser{Name: "Carol"}))

		all := must[admin.AllSessionsResult](t)(w.ad.AllSessions(w.bossCtx(), admin.AllSessionsRequest{}))
		if all.Total != 3 || len(all.Sessions) != 3 || !slices.ContainsFunc(all.Sessions, func(s admin.FleetSession) bool {
			return s.ID == second.ID && s.UserID == w.bob.User.ID && s.ExpiresAt.Equal(second.ExpiresAt)
		}) {
			t.Fatalf("all = %+v", all)
		}
		pg := must[admin.AllSessionsResult](t)(w.ad.AllSessions(w.bossCtx(), admin.AllSessionsRequest{Limit: 1, Page: 2}))
		if pg.Total != 3 || len(pg.Sessions) != 1 || pg.Offset != 1 || pg.Page != 2 {
			t.Fatalf("page 2 = %+v", pg)
		}
		bobs := must[admin.AllSessionsResult](t)(w.ad.AllSessions(w.bossCtx(), admin.AllSessionsRequest{UserID: w.bob.User.ID}))
		if bobs.Total != 2 {
			t.Fatalf("bob's = %+v", bobs)
		}
		if err := w.ad.RevokeSession(w.bossCtx(), w.bob.User.ID, second.ID); err != nil {
			t.Fatal(err)
		}
		if got := must[admin.AllSessionsResult](t)(w.ad.AllSessions(w.bossCtx(), admin.AllSessionsRequest{})); got.Total != 2 {
			t.Fatalf("after revoke = %+v", got)
		}
		if _, err := w.ad.AllSessions(request(w.a, w.bob.Token), admin.AllSessionsRequest{}); !errors.Is(err, admin.ErrForbidden) {
			t.Fatalf("non-admin = %v", err)
		}

		// Last activity: bob's newest session was revoked, but its row is
		// gone, so the older one answers; carol never signed in.
		users := must[admin.UsersResult](t)(w.ad.Users(w.bossCtx(), admin.UsersRequest{}))
		byID := map[string]admin.UserSummary{}
		for _, u := range users.Users {
			byID[u.ID] = u
		}
		first := sessionsOf(w.a, w.bob.User.ID)[0]
		if la := byID[w.bob.User.ID].LastActiveAt; la == nil || !la.Equal(first.LastSeenAt) {
			t.Fatalf("bob last active = %v, want %v", la, first.LastSeenAt)
		}
		if byID[carol.ID].LastActiveAt != nil {
			t.Fatalf("carol last active = %v", byID[carol.ID].LastActiveAt)
		}
		d := must[admin.UserDetail](t)(w.ad.User(w.bossCtx(), w.boss.User.ID))
		if d.User.LastActiveAt == nil || !d.User.LastActiveAt.Equal(sessionsOf(w.a, w.boss.User.ID)[0].LastSeenAt) {
			t.Fatalf("boss detail last active = %v", d.User.LastActiveAt)
		}

	})
}

// TestP3Admin_SessionsInMemory: with sessions out of the database the fleet
// list is refused rather than shown empty, and last activity still answers
// from each user's live sessions.
func TestP3Admin_SessionsInMemory(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		sessionsOf := func(a *auth.Auth, userID string) []auth.Session {
			t.Helper()
			return must[[]auth.Session](t)(a.Sessions(context.Background(), userID))
		}
		mw := p3AdminWorld(t, e, []auth.Option{auth.WithSessionStore(auth.NewMemorySessionStore())})
		if _, err := mw.ad.AllSessions(mw.bossCtx(), admin.AllSessionsRequest{}); !errors.Is(err, admin.ErrSessionsNotListable) {
			t.Fatalf("memory store = %v", err)
		}
		mu := must[admin.UsersResult](t)(mw.ad.Users(mw.bossCtx(), admin.UsersRequest{FilterField: admin.FilterID, FilterValue: p3Str(mw.bob.User.ID)}))
		if len(mu.Users) != 1 || mu.Users[0].LastActiveAt == nil || !mu.Users[0].LastActiveAt.Equal(sessionsOf(mw.a, mw.bob.User.ID)[0].LastSeenAt) {
			t.Fatalf("memory last active = %+v", mu)
		}
	})
}

// TestP3Admin_HTTP: the query-string names are better-auth's, and the new
// route answers over HTTP for an admin only.
func TestP3Admin_HTTP(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newAdminWorld(t, e, nil, email.SignInWithCode())
		web := newApp(t, w.a)
		get := func(tok auth.Token, path string, out any) int {
			t.Helper()
			req, _ := http.NewRequest(http.MethodGet, web.srv.URL+path, nil)
			req.Header.Set("Authorization", "Bearer "+string(tok))
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			if out != nil && res.StatusCode == http.StatusOK {
				if err := json.NewDecoder(res.Body).Decode(out); err != nil {
					t.Fatal(err)
				}
			}
			return res.StatusCode
		}
		q := url.Values{"filterField": {"name"}, "filterOperator": {"in"}, "filterValue": {"Bob,Nobody"}, "sortBy": {"name"}, "sortDirection": {"desc"}}
		var users admin.UsersResult
		if code := get(w.boss.Token, "/auth/admin/users?"+q.Encode(), &users); code != http.StatusOK || users.Total != 1 || users.Users[0].ID != w.bob.User.ID || users.Users[0].LastActiveAt == nil {
			t.Fatalf("users = %d %+v", code, users)
		}
		if code := get(w.boss.Token, "/auth/admin/users?filterField=password&filterValue=x", nil); code != http.StatusBadRequest {
			t.Fatalf("bad field = %d", code)
		}
		var all admin.AllSessionsResult
		if code := get(w.boss.Token, "/auth/admin/all-sessions?limit=1", &all); code != http.StatusOK || all.Total != 2 || len(all.Sessions) != 1 {
			t.Fatalf("all-sessions = %d %+v", code, all)
		}
		if code := get(w.bob.Token, "/auth/admin/all-sessions", nil); code != http.StatusForbidden {
			t.Fatalf("all-sessions as bob = %d", code)
		}
		if code := get("", "/auth/admin/all-sessions", nil); code != http.StatusUnauthorized {
			t.Fatalf("all-sessions anonymous = %d", code)
		}
	})
}

// TestP3Admin_FilterTimeAndTextOperators: the remaining operators of the
// time and text fields, each on every engine.
func TestP3Admin_FilterTimeAndTextOperators(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newAdminWorld(t, e, nil)
		bob := must[auth.User](t)(w.a.User(context.Background(), w.bob.User.ID))
		end := e.clock.Now().Add(time.Hour)
		if err := w.ad.BanFor(context.Background(), bob.ID, "", end); err != nil {
			t.Fatal(err)
		}
		at := func(tm time.Time) string { return tm.Format(time.RFC3339Nano) }
		list := func(field admin.FilterField, op admin.FilterOperator, v string) []string {
			t.Helper()
			return names(must[admin.UsersResult](t)(w.ad.Users(w.bossCtx(), admin.UsersRequest{FilterField: field, FilterOperator: op, FilterValue: p3Str(v)})))
		}
		for _, c := range []struct {
			field admin.FilterField
			op    admin.FilterOperator
			v     string
			want  []string
		}{
			{admin.FilterName, admin.FilterNe, "Bob", []string{"Alice"}},
			{admin.FilterCreatedAt, admin.FilterEq, at(bob.CreatedAt), []string{"Alice", "Bob"}},
			{admin.FilterCreatedAt, admin.FilterNe, at(bob.CreatedAt), []string{}},
			{admin.FilterCreatedAt, admin.FilterLte, at(bob.CreatedAt), []string{"Alice", "Bob"}},
			{admin.FilterBanExpires, admin.FilterEq, at(end), []string{"Bob"}},
			{admin.FilterBanExpires, admin.FilterNe, at(end), []string{}},
			{admin.FilterBanExpires, admin.FilterLte, at(end), []string{"Bob"}},
			{admin.FilterBanExpires, admin.FilterGte, at(end.Add(time.Second)), []string{}},
		} {
			if got := list(c.field, c.op, c.v); !slices.Equal(got, c.want) {
				t.Errorf("%s %s %s = %v, want %v", c.field, c.op, c.v, got, c.want)
			}
		}
	})
}

// TestP3Admin_RoleFilterCountsAdminIDs: a user made an admin by AdminIDs,
// with no grant and no stored role, holds the admin role and not the default.
func TestP3Admin_RoleFilterCountsAdminIDs(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newAdminWorld(t, e, nil)
		carol := must[auth.User](t)(w.a.CreateUser(context.Background(), auth.NewUser{Name: "Carol"}))
		ad := admin.New(admin.AdminIDs(carol.ID))
		a2 := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), ad)
		role := func(v string) []string {
			t.Helper()
			return names(must[admin.UsersResult](t)(ad.Users(request(a2, w.boss.Token), admin.UsersRequest{FilterField: admin.FilterRole, FilterValue: p3Str(v)})))
		}
		if got := role(admin.RoleAdmin); !slices.Equal(got, []string{"Alice", "Carol"}) {
			t.Fatalf("admins = %v", got)
		}
		if got := role(admin.RoleUser); !slices.Equal(got, []string{"Bob"}) {
			t.Fatalf("users = %v", got)
		}
	})
}

// TestP3Admin_AllSessionsEveryDatabaseFailureSurfaces: each statement of
// all-sessions failing comes back as an error, never as a short page.
func TestP3Admin_AllSessionsEveryDatabaseFailureSurfaces(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		w := newAdminWorld(t, e.env, nil)
		return func(context.Context) error {
			_, err := w.ad.AllSessions(w.bossCtx(), admin.AllSessionsRequest{})
			return err
		}
	})
}

// p3FailingList is a memory session store whose List fails while fail is
// set, for last activity's store-error path.
type p3FailingList struct {
	auth.SessionStore
	fail *bool
}

var errP3List = errors.New("p3: list failed")

func (s p3FailingList) List(ctx context.Context, userID string, now time.Time) ([]auth.Session, error) {
	if *s.fail {
		return nil, errP3List
	}
	return s.SessionStore.List(ctx, userID, now)
}

// TestP3Admin_LastActiveOutsideSQL: a store error reaches the caller, and in
// stateless mode the caller's own row answers while the others stay nil.
func TestP3Admin_LastActiveOutsideSQL(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		fail := false
		w := p3AdminWorld(t, e, []auth.Option{auth.WithSessionStore(p3FailingList{SessionStore: auth.NewMemorySessionStore(), fail: &fail})})
		fail = true
		if _, err := w.ad.Users(w.bossCtx(), admin.UsersRequest{}); !errors.Is(err, errP3List) {
			t.Fatalf("store failure = %v", err)
		}
	})
	eachEngine(t, func(t *testing.T, e *env) {
		w := p3AdminWorld(t, e, []auth.Option{auth.WithStatelessSessions(sessKey)})
		got := must[admin.UsersResult](t)(w.ad.Users(w.bossCtx(), admin.UsersRequest{}))
		for _, u := range got.Users {
			if (u.ID == w.boss.User.ID) != (u.LastActiveAt != nil) {
				t.Fatalf("stateless %s last active = %v", u.Name, u.LastActiveAt)
			}
		}
		if _, err := w.ad.AllSessions(w.bossCtx(), admin.AllSessionsRequest{}); !errors.Is(err, admin.ErrSessionsNotListable) {
			t.Fatalf("stateless all-sessions = %v", err)
		}
	})
}
