package scim

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
)

// signInStub satisfies the core's "at least one sign-in method" rule.
type signInStub struct{}

func (signInStub) Name() string  { return "signin" }
func (signInStub) SignsIn() bool { return true }

func noMail() email.Option {
	return email.WithMailer(email.MailerFunc(func(context.Context, email.Mail) error { return nil }))
}

// wire builds the plugin into an Auth with no database.
func wire(t *testing.T, opts ...Option) *Plugin {
	t.Helper()
	p := New(opts...)
	if _, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(signInStub{}, email.New(noMail()), p)); err != nil {
		t.Fatal(err)
	}
	return p
}

var acme = Connections(Connection{ID: "acme", Credentials: []Credential{{ID: "c1", Token: "secret-1"}}})

// TestValidate_RefusesUnusableConnections: each bad configuration is named.
func TestValidate_RefusesUnusableConnections(t *testing.T) {
	cfg := func(p *Plugin) error {
		_, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(signInStub{}, email.New(noMail()), p))
		return err
	}
	if err := cfg(New()); !errors.Is(err, ErrNoConnections) {
		t.Fatalf("none: %v", err)
	}
	bad := []Connection{
		{ID: ""}, {ID: " x"}, {ID: strings.Repeat("x", maxIDLength+1)},
		{ID: "a", Credentials: []Credential{{ID: "c", Token: "has space"}}},
		{ID: "a", Credentials: []Credential{{ID: "c", Token: "t", Scopes: []Scope{"scim.all"}}}},
		{ID: "a", Credentials: []Credential{{ID: "c", Token: "t"}, {ID: "c", Token: "u"}}},
	}
	for _, c := range bad {
		if err := cfg(New(Connections(c))); !errors.Is(err, ErrBadConnection) {
			t.Fatalf("%+v: %v", c, err)
		}
	}
	if err := cfg(New(Connections(Connection{ID: "a"}, Connection{ID: "a"}))); !errors.Is(err, ErrBadConnection) {
		t.Fatalf("duplicate id: %v", err)
	}
	two := Connections(Connection{ID: "a", Credentials: []Credential{{ID: "c", Token: "t"}}}, Connection{ID: "b", Credentials: []Credential{{ID: "c", Token: "t"}}})
	if err := cfg(New(two)); !errors.Is(err, ErrDuplicateToken) {
		t.Fatalf("shared token: %v", err)
	}
	if _, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(signInStub{}, New(acme))); err == nil {
		t.Fatal("scim without the email plugin must be refused")
	}
	if err := cfg(New(VerifyBearerToken(func(context.Context, BearerRequest) (Principal, error) { return Principal{}, nil }))); err != nil {
		t.Fatalf("verifier only: %v", err)
	}
}

// TestPlugin_DeclaresItsSurface: tables, user tables, the column, the
// session predicate, migrations on every engine without foreign keys.
func TestPlugin_DeclaresItsSurface(t *testing.T) {
	p := wire(t, acme)
	if p.Name() != PluginName || len(p.Tables()) != 8 || len(p.UserTables()) != 4 || p.Columns()[0].Name != ColDeactivatedAt ||
		len(p.SessionPredicates()) != 1 || p.Requires()[0] != email.PluginName {
		t.Fatal("surface")
	}
	for _, eng := range []string{auth.EnginePostgres, auth.EngineMySQL, auth.EngineSQLite} {
		m, err := p.TypedMigrations(eng, auth.TypesFor(eng))
		if err != nil || len(m[0].Statements) != 8 || strings.Contains(strings.ToUpper(strings.Join(m[0].Statements, ";")), "REFERENCES") {
			t.Fatalf("%s: %v %v", eng, m, err)
		}
	}
	if _, err := p.TypedMigrations("oracle", auth.TypesFor("oracle")); !errors.Is(err, auth.ErrEngineNotSupported) {
		t.Fatalf("oracle: %v", err)
	}
}

// request builds a SCIM request through the handler.
func serveReq(p *Plugin, method, path, token, ctype, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if ctype != "" {
		r.Header.Set("Content-Type", ctype)
	}
	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, r)
	return w
}

// TestHandler_AuthenticationAndErrors: discovery is public; tokens,
// expiry, scopes, media types and bodies are checked before the database.
func TestHandler_AuthenticationAndErrors(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	p := wire(t, Connections(Connection{ID: "acme", Credentials: []Credential{
		{ID: "full", Token: "full"}, {ID: "old", Token: "old", ExpiresAt: &past},
		{ID: "ro", Token: "ro", Scopes: []Scope{ScopeUsersRead}},
	}}), VerifyBearerToken(func(_ context.Context, r BearerRequest) (Principal, error) {
		switch r.Token {
		case "dyn":
			return Principal{ConnectionID: "dyn", Scopes: []Scope{ScopeGroupsRead}}, nil
		case "broken":
			return Principal{}, errors.New("store down")
		case "badconn":
			return Principal{ConnectionID: " "}, nil
		case "taken":
			// A dynamic principal naming a configured connection.
			return Principal{ConnectionID: "acme"}, nil
		}
		return Principal{}, ErrUnauthorized
	}))
	cases := []struct {
		method, path, token, ctype, body string
		status                           int
		scimType                         ErrorType
	}{
		{http.MethodGet, "/ServiceProviderConfig", "", "", "", 200, ""},
		{http.MethodGet, "/ResourceTypes/User", "", "", "", 200, ""},
		{http.MethodGet, "/ResourceTypes/Nope", "", "", "", 404, ""},
		{http.MethodPost, "/Schemas", "", "", "", 405, ""},
		{http.MethodGet, "/Users", "", "", "", 401, ""},
		{http.MethodGet, "/Users", "nope", "", "", 401, ""},
		{http.MethodGet, "/Users", "old", "", "", 401, ""},
		{http.MethodGet, "/Users", "badconn", "", "", 401, ""},
		{http.MethodGet, "/Users", "taken", "", "", 401, ""},
		{http.MethodGet, "/Users", "broken", "", "", 500, ""},
		{http.MethodPost, "/Users", "ro", MediaType, "{}", 403, ""},
		{http.MethodGet, "/Users", "dyn", "", "", 403, ""},
	}
	for _, c := range cases {
		w := serveReq(p, c.method, c.path, c.token, c.ctype, c.body)
		var body errorBody
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if w.Code != c.status || body.ScimType != c.scimType || w.Header().Get("Content-Type") != MediaType {
			t.Errorf("%s %s (%s) = %d %+v, want %d %s", c.method, c.path, c.token, w.Code, body, c.status, c.scimType)
		}
		if c.status == 401 && w.Header().Get("WWW-Authenticate") != `Bearer realm="SCIM"` {
			t.Errorf("%s: no WWW-Authenticate", c.path)
		}
	}
	// Past authentication and scope, the connection binding needs the
	// database (the integration suite covers every answer after it); here
	// its absence surfaces as a 500 with no detail.
	w := serveReq(p, http.MethodGet, "/Users", "full", "", "")
	if w.Code != 500 || !strings.Contains(w.Body.String(), "Internal error") {
		t.Fatalf("no database = %d %s", w.Code, w.Body)
	}
	if pr, ok := PrincipalFrom(context.Background()); ok || pr.ConnectionID != "" {
		t.Fatal("no principal outside a request")
	}
}

// TestRequiredScope: method and collection choose the scope.
func TestRequiredScope(t *testing.T) {
	for _, c := range []struct {
		m, p string
		want Scope
	}{{"GET", "/Users", ScopeUsersRead}, {"HEAD", "/Users/1", ScopeUsersRead}, {"PATCH", "/Users/1", ScopeUsersWrite},
		{"GET", "/Groups", ScopeGroupsRead}, {"DELETE", "/Groups/1", ScopeGroupsWrite}} {
		if got := requiredScope(c.m, c.p); got != c.want {
			t.Errorf("%s %s = %s", c.m, c.p, got)
		}
	}
}

// TestParseFilter: the supported subset parses; everything else is
// invalidFilter.
func TestParseFilter(t *testing.T) {
	users := []string{"id", "username", "externalid", "emails.value", "emails[type].value"}
	ts, err := parseFilter(`urn:ietf:params:scim:schemas:core:2.0:User:userName EQ "a\"b" AND emails[type eq "work"].value eq "x@y.z"`, users...)
	if err != nil || len(ts) != 2 || ts[0] != (term{Attr: "username", Value: `a"b`}) || ts[1] != (term{Attr: "emails.value", Type: "work", Value: "x@y.z"}) {
		t.Fatalf("%+v %v", ts, err)
	}
	for _, bad := range []string{`userName`, `userName sw "a"`, `userName eq`, `userName eq "a" or id eq "b"`, `title eq "x"`,
		`emails[type eq "work".value eq "x"`, `phoneNumbers[type eq "x"].value eq "1"`, `userName eq "unclosed`,
		`emails[type co "w"].value eq "x"`, `emails[type eq "w" and x eq "y"].value eq "x"`, `userName eq "\q"`,
		strings.Repeat(`id eq "1" and `, 10) + `id eq "1"`} {
		if _, err := parseFilter(bad, users...); err == nil {
			t.Errorf("%s parsed", bad)
		} else if se := (*Error)(nil); !errors.As(err, &se) || se.Type != InvalidFilter {
			t.Errorf("%s: %v", bad, err)
		}
	}
	if ts, err := parseFilter(`active eq true`, "active"); err != nil || ts[0].Value != "true" {
		t.Fatalf("bare value: %+v %v", ts, err)
	}
}

// TestParsePath: attributes, sub-attributes, value filters and the
// enterprise URN.
func TestParsePath(t *testing.T) {
	for in, want := range map[string]path{
		"userName":                           {attr: "userName"},
		"name.givenName":                     {attr: "name", sub: "givenName"},
		`emails[type eq "work"].value`:       {attr: "emails", filter: &term{Attr: "type", Value: "work"}, sub: "value"},
		SchemaEnterpriseUser + ":department": {ext: true, attr: "department"},
		SchemaEnterpriseUser:                 {ext: true},
		SchemaUser + ":active":               {attr: "active"},
	} {
		got, err := parsePath(in)
		if err != nil || got.attr != want.attr || got.sub != want.sub || got.ext != want.ext || (got.filter == nil) != (want.filter == nil) {
			t.Errorf("%s = %+v %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "a b", `emails[type eq "w"`, `emails[type eq "w"]x`, `emails[type]`, "a.b.c"} {
		if _, err := parsePath(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

// patchDoc applies ops (a JSON list) to a fresh user document.
func patchDoc(t *testing.T, ops string) (map[string]any, error) {
	t.Helper()
	doc := map[string]any{
		"schemas": []any{SchemaUser}, "userName": "ada",
		"emails":  []any{map[string]any{"value": "a@x.io", "type": "work", "primary": true}},
		"members": []any{map[string]any{"value": "m1"}, map[string]any{"value": "m2"}},
		"name":    map[string]any{"givenName": "Ada"},
	}
	var list []PatchOp
	if err := json.Unmarshal([]byte(ops), &list); err != nil {
		t.Fatal(err)
	}
	return doc, applyPatch(doc, list, "userName")
}

// TestApplyPatch covers each operation shape.
func TestApplyPatch(t *testing.T) {
	doc, err := patchDoc(t, `[
		{"op":"Replace","value":{"displayName":"A","name.familyName":"L","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"R"}}},
		{"op":"add","path":"members","value":[{"value":"m2"},{"value":"m3"}]},
		{"op":"add","path":"name","value":{"middleName":"B"}},
		{"op":"replace","path":"emails.value","value":"b@x.io"},
		{"op":"add","path":"phoneNumbers[type eq \"mobile\"]","value":{"value":"1","primary":true}},
		{"op":"remove","path":"members","value":[{"value":"m1"}]},
		{"path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.value","value":"boss"},
		{"op":"add","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User","value":{"division":"D"}},
		{"op":"remove","path":"name.givenName"}
	]`)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(doc)
	for _, want := range []string{`"displayName":"A"`, `"familyName":"L"`, `"middleName":"B"`, `"value":"b@x.io"`, `"department":"R"`,
		`"division":"D"`, `"manager":{"value":"boss"}`, `"members":[{"value":"m2"},{"value":"m3"}]`, `"phoneNumbers":[{"type":"mobile","value":"1"}]`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %s in %s", want, b)
		}
	}
	if strings.Contains(string(b), "givenName") {
		t.Errorf("givenName not removed: %s", b)
	}
	errs := map[string]ErrorType{
		`[{"op":"move","path":"a"}]`:                                          InvalidValue,
		`[{"op":"remove"}]`:                                                   NoTarget,
		`[{"op":"add","value":"x"}]`:                                          InvalidValue,
		`[{"op":"replace","path":"meta","value":{}}]`:                         Mutability,
		`[{"op":"remove","path":"userName"}]`:                                 Mutability,
		`[{"op":"replace","path":"emails[value eq \"z\"].type","value":"w"}]`: NoTarget,
		`[{"op":"replace","path":"a b","value":1}]`:                           InvalidPath,
		`[{"op":"add","value":{"a b":1}}]`:                                    InvalidPath,
		`[{"op":"replace","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.displayName","value":"x"}]`: Mutability,
		`[{"op":"replace","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User","value":"x"}]`:                     InvalidValue,
		`[{"op":"replace","value":{"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":"x"}}]`:                          InvalidValue,
		`[{"op":"replace","path":"emails[type eq \"work\"]","value":"x"}]`:                                                       InvalidValue,
		`[{"op":"remove","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department"}]`:                       NoTarget,
	}
	for ops, want := range errs {
		_, err := patchDoc(t, ops)
		var se *Error
		if !errors.As(err, &se) || se.Type != want {
			t.Errorf("%s: %v, want %s", ops, err, want)
		}
	}
	// Filtered removes and replaces, and a remove of the whole extension.
	doc, err = patchDoc(t, `[
		{"op":"replace","path":"emails[primary eq true]","value":{"display":"Work"}},
		{"op":"remove","path":"emails[type eq \"work\"].display"},
		{"op":"add","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department","value":"R"},
		{"op":"remove","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"},
		{"op":"remove","path":"members[value eq \"m1\"]"},
		{"op":"remove","path":"title"},
		{"op":"remove","path":"name"}
	]`)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = json.Marshal(doc)
	if strings.Contains(string(b), "Work") || strings.Contains(string(b), "m1") || strings.Contains(string(b), "enterprise") || strings.Contains(string(b), "name\"") {
		t.Fatalf("after removes: %s", b)
	}
}

// TestDecodeUser: validation bounds and Entra's string booleans.
func TestDecodeUser(t *testing.T) {
	ok := func(extra string) map[string]any {
		var m map[string]any
		_ = json.Unmarshal([]byte(`{"schemas":["`+SchemaUser+`"],"userName":"ada@x.io"`+extra+`}`), &m)
		return m
	}
	if m, err := decodeUser(ok(`,"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"manager":"m-1"}`)); err != nil || m.Enterprise.Manager.Value != "m-1" {
		t.Fatalf("bare manager = %+v %v", m, err)
	}
	u, err := decodeUser(ok(`,"active":"False","emails":[{"value":"w@x.io","type":"work","primary":"TRUE"}],"id":"x","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{}`))
	if err != nil || u.IsActive() || !u.Emails[0].Primary || u.ID != "" || u.Enterprise != nil {
		t.Fatalf("%+v %v", u, err)
	}
	bad := []string{
		`,"schemas":["` + SchemaUser + `","` + SchemaUser + `"]`,
		`,"schemas":["urn:x"]`,
		`,"userName":" "`,
		`,"userName":"` + strings.Repeat("a", maxUserName+1) + `"`,
		`,"title":"` + strings.Repeat("a", maxLongString+1) + `"`,
		`,"locale":"` + strings.Repeat("a", maxShortString+1) + `"`,
		`,"emails":[` + strings.Repeat(`{"value":"a@x.io"},`, maxEmails) + `{"value":"b@x.io"}]`,
		`,"roles":[` + strings.Repeat(`{"value":"r"},`, maxMultiValues) + `{"value":"s"}]`,
		`,"emails":[{"value":"not an email"}]`,
		`,"emails":[{"value":"a@x.io","primary":true},{"value":"b@x.io","primary":true}]`,
		`,"emails":[{"value":"a@x.io","type":"work"},{"value":"b@x.io","type":"Work"}]`,
		`,"emails":[{"value":"a@x.io"},{"value":"A@x.io"}]`,
		`,"addresses":[{"type":"home"},{"type":"home","locality":"x"}]`,
		`,"active":"maybe"`,
		`,"userName":"no-email"`,
	}
	for _, extra := range bad {
		if _, err := decodeUser(ok(extra)); err == nil {
			t.Errorf("accepted %.80s", extra)
		}
	}
}

// TestPrimaryEmail: primary, then work, then first, then userName.
func TestPrimaryEmail(t *testing.T) {
	for want, u := range map[string]User{
		"p@x.io": {Emails: []MultiValue{{Value: "w@x.io", Type: "work"}, {Value: "p@x.io", Primary: true}}},
		"w@x.io": {Emails: []MultiValue{{Value: "h@x.io", Type: "home"}, {Value: "w@x.io", Type: "WORK"}}},
		"h@x.io": {Emails: []MultiValue{{Value: "h@x.io", Type: "home"}}},
		"u@x.io": {UserName: "u@x.io"},
		"":       {UserName: "u"},
	} {
		if got := u.PrimaryEmail(); got != want {
			t.Errorf("%+v = %q, want %q", u, got, want)
		}
	}
	if got := (User{Name: &Name{GivenName: "A", FamilyName: "L"}}).displayName(); got != "A L" {
		t.Fatalf("displayName = %q", got)
	}
	if got := (User{Name: &Name{Formatted: "F"}}).displayName(); got != "F" {
		t.Fatalf("formatted = %q", got)
	}
	if got := (User{}).displayName(); got != "" {
		t.Fatalf("empty = %q", got)
	}
}

// TestDecodeGroup: required name, member type, duplicates, the member bound.
func TestDecodeGroup(t *testing.T) {
	doc := func(s string) map[string]any {
		var m map[string]any
		_ = json.Unmarshal([]byte(s), &m)
		return m
	}
	g, err := decodeGroup(doc(`{"schemas":["` + SchemaGroup + `"],"displayName":" Eng ","members":[{"value":"a","type":"user"},{"value":"a"}]}`))
	if err != nil || g.DisplayName != "Eng" || len(g.Members) != 1 {
		t.Fatalf("%+v %v", g, err)
	}
	many := `{"schemas":["` + SchemaGroup + `"],"displayName":"X","members":[`
	for i := range MaxGroupMembers + 1 {
		if i > 0 {
			many += ","
		}
		many += `{"value":"m` + strconv.Itoa(i) + `"}`
	}
	for _, bad := range []string{`{"schemas":["x"],"displayName":"X"}`, `{"schemas":["` + SchemaGroup + `"]}`,
		`{"schemas":["` + SchemaGroup + `"],"displayName":"X","members":[{"value":"a","type":"Group"}]}`,
		`{"schemas":["` + SchemaGroup + `"],"displayName":"X","members":[{"value":""}]}`,
		`{"schemas":["` + SchemaGroup + `"],"displayName":1}`, many + `]}`} {
		if _, err := decodeGroup(doc(bad)); err == nil {
			t.Errorf("accepted %.60s", bad)
		}
	}
}

// TestProjection: include keeps id and schemas; exclude drops attributes
// and sub-attributes.
func TestProjection(t *testing.T) {
	doc := func() map[string]any {
		return map[string]any{"id": "1", "schemas": []any{}, "userName": "a", "name": map[string]any{"givenName": "A", "familyName": "L"}, "emails": []any{},
			SchemaEnterpriseUser: map[string]any{"department": "R", "division": "D"}}
	}
	pr, _ := parseProjection(url.Values{"attributes": {"userName, name.givenName," + SchemaEnterpriseUser + ":department"}})
	d := doc()
	pr.apply(d)
	b, _ := json.Marshal(d)
	if string(b) != `{"id":"1","name":{"givenName":"A"},"schemas":[],"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"R"},"userName":"a"}` {
		t.Fatalf("include = %s", b)
	}
	pr, _ = parseProjection(url.Values{"excludedAttributes": {"emails,name.familyName,id"}})
	d = doc()
	pr.apply(d)
	b, _ = json.Marshal(d)
	if strings.Contains(string(b), "emails") || strings.Contains(string(b), "familyName") || !strings.Contains(string(b), `"id"`) {
		t.Fatalf("exclude = %s", b)
	}
	if pr, err := parseProjection(url.Values{}); pr != nil || err != nil {
		t.Fatal("no projection")
	}
	pr, _ = parseProjection(url.Values{"attributes": {"name,name.givenName"}})
	d = doc()
	pr.apply(d)
	if len(d["name"].(map[string]any)) != 2 {
		t.Fatalf("whole attribute wins: %v", d)
	}
}

// TestPaging: defaults, bounds, slices.
func TestPaging(t *testing.T) {
	s, c, err := page(url.Values{"startIndex": {"0"}, "count": {"500"}})
	if err != nil || s != 1 || c != MaxPageSize {
		t.Fatalf("%d %d %v", s, c, err)
	}
	if _, _, err := page(url.Values{"startIndex": {"x"}}); err == nil {
		t.Fatal("bad startIndex")
	}
	docs := []map[string]any{{"a": 1}, {"b": 2}, {"c": 3}}
	if got := pageOf(docs, 2, 5); got.TotalResults != 3 || got.ItemsPerPage != 2 {
		t.Fatalf("%+v", got)
	}
	if got := pageOf(docs, 9, 5); got.ItemsPerPage != 0 || got.Resources == nil {
		t.Fatalf("%+v", got)
	}
}

// TestHelpers covers the small functions.
func TestHelpers(t *testing.T) {
	if optKey("") != nil || optString("") != nil || *optString("a") != "a" || len(*optKey("a")) != 64 || keyOfValue("a") == keyOfValue("A") {
		t.Fatal("keys")
	}
	if got := truncateName(strings.Repeat("é", auth.MaxNameLength+5)); len([]rune(got)) != auth.MaxNameLength {
		t.Fatalf("truncate = %d", len([]rune(got)))
	}
	r := httptest.NewRequest(http.MethodGet, "/scim/v2/Users?x=1", nil)
	if got := location(r, "https://app.example.com/api", pathUsers, "u1"); got != "https://app.example.com/scim/v2/Users/u1" {
		t.Fatalf("location = %s", got)
	}
	if (&Error{Status: 400, Type: InvalidValue, Detail: "d"}).Error() != "scim: 400 invalidValue: d" {
		t.Fatal("Error()")
	}
	w := httptest.NewRecorder()
	writeError(w, auth.ErrIdentityTaken)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "uniqueness") {
		t.Fatalf("taken = %d %s", w.Code, w.Body)
	}
	w = httptest.NewRecorder()
	writeError(w, auth.ErrIdentifierInvalid)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid = %d", w.Code)
	}
	w = httptest.NewRecorder()
	writeError(w, auth.ErrUserNotFound)
	if w.Code != http.StatusNotFound {
		t.Fatalf("coded = %d", w.Code)
	}
	if !matchesEmails(`{"emails":[{"value":"A@x.io","type":"work"}]}`, []term{{Attr: "emails.value", Type: "WORK", Value: "a@x.io"}}) ||
		matchesEmails(`{"emails":[{"value":"a@x.io","type":"home"}]}`, []term{{Attr: "emails.value", Type: "work", Value: "a@x.io"}}) ||
		matchesEmails(`not json`, []term{{Attr: "emails.value", Value: "a"}}) {
		t.Fatal("matchesEmails")
	}
	if len(schemas()) != 3 || len(resourceTypes()) != 2 || spConfig()["patch"] != (supported{true}) {
		t.Fatal("discovery")
	}
}

// TestDropEntraMarker: one marker is dropped; two, or attributes under it,
// are refused.
func TestDropEntraMarker(t *testing.T) {
	doc := map[string]any{"schemas": []any{SchemaGroup, EntraLegacyGroupSchema}}
	if err := dropEntraMarker(doc); err != nil || len(doc["schemas"].([]any)) != 1 {
		t.Fatalf("%v %v", doc, err)
	}
	if err := dropEntraMarker(map[string]any{"schemas": []any{EntraLegacyGroupSchema, EntraLegacyGroupSchema}}); err == nil {
		t.Fatal("repeated marker accepted")
	}
	if err := dropEntraMarker(map[string]any{EntraLegacyGroupSchema: map[string]any{}}); err == nil {
		t.Fatal("attributes under the marker accepted")
	}
}

// TestManaged_ConfigurationAndHelpers: managed settings are checked, the
// API refuses when the option is off, and the helpers round-trip.
func TestManaged_ConfigurationAndHelpers(t *testing.T) {
	build := func(opts ...Option) error {
		_, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(signInStub{}, email.New(noMail()), New(opts...)))
		return err
	}
	for _, m := range []Option{ManagedConnections(), ManagedConnections(CredentialHashSecret([]byte("short"))),
		ManagedConnections(CredentialHashSecret([]byte(strings.Repeat("k", 32))), MaxActiveCredentials(0)),
		ManagedConnections(CredentialHashSecret([]byte(strings.Repeat("k", 32))), LastUsedWriteInterval(-1))} {
		if err := build(m); !errors.Is(err, ErrBadManaged) {
			t.Fatalf("bad managed config: %v", err)
		}
	}
	if err := build(ManagedConnections(CredentialHashSecret([]byte(strings.Repeat("k", 32))))); err != nil {
		t.Fatalf("managed only: %v", err)
	}
	if err := build(Connections(Connection{ID: managedConnPrefix + "_x"})); !errors.Is(err, ErrBadConnection) {
		t.Fatalf("static id with the managed prefix: %v", err)
	}
	p := wire(t, acme)
	ctx := context.Background()
	if _, err := p.CreateManagedConnection(ctx, CreateManagedRequest{}); !errors.Is(err, ErrManagedDisabled) {
		t.Fatalf("create without the option: %v", err)
	}
	if _, err := p.ManagedConnections(ctx, "d"); !errors.Is(err, ErrManagedDisabled) {
		t.Fatalf("list without the option: %v", err)
	}
	if _, err := p.ManagedConnection(ctx, "c", "d"); !errors.Is(err, ErrManagedDisabled) {
		t.Fatalf("get without the option: %v", err)
	}
	m := wire(t, ManagedConnections(CredentialHashSecret([]byte(strings.Repeat("k", 32)))))
	if _, err := m.CreateManagedConnection(ctx, CreateManagedRequest{CreationRequestID: "short"}); !errors.Is(err, auth.ErrBadRequest) {
		t.Fatalf("short request id: %v", err)
	}
	if _, err := m.RotateCredential(ctx, "c", "d", "a", []Scope{"bad"}, nil); !errors.Is(err, auth.ErrBadRequest) {
		t.Fatalf("bad scope: %v", err)
	}
	if string(m.digest("a")) != string(m.digest("a")) || string(m.digest("a")) == string(m.digest("b")) {
		t.Fatal("digest")
	}
	if joinScopes([]Scope{ScopeUsersRead, ScopeGroupsRead}) != "scim.users.read scim.groups.read" || len(parseScopes("")) != 4 || parseScopes("scim.users.read")[0] != ScopeUsersRead {
		t.Fatal("scopes")
	}
	if _, err := m.managedAuth(ctx, ManagedTokenPrefix+"nodot"); !errors.Is(err, errInvalidToken) {
		t.Fatalf("malformed managed token: %v", err)
	}
}

// TestReconcileProjection_NeedsAMapper: without WithGroupMapper there is
// nothing to replay into.
func TestReconcileProjection_NeedsAMapper(t *testing.T) {
	if _, err := wire(t, acme).ReconcileProjection(context.Background(), "acme"); !errors.Is(err, ErrNoGroupMapper) {
		t.Fatalf("no mapper: %v", err)
	}
}

// TestFenceAndGate: If-Match parsing, the stale answers, the version
// spelling, the gate's refusal outside Handler and its default rules.
func TestFenceAndGate(t *testing.T) {
	row := userRow{revision: 4}
	for h, want := range map[string]fence{"": {revision: 4}, "*": {revision: 4}, `W/"7"`: {revision: 7, strict: true}, `"8"`: {revision: 8, strict: true}} {
		r := httptest.NewRequest(http.MethodPatch, "/Users/x", nil)
		r.Header.Set("If-Match", h)
		if got, err := fenceOf(r, row); err != nil || got != want {
			t.Errorf("%q = %+v %v", h, got, err)
		}
	}
	r := httptest.NewRequest(http.MethodPatch, "/Users/x", nil)
	r.Header.Set("If-Match", "nope")
	if _, err := fenceOf(r, row); !errors.Is(err, errPrecondition) {
		t.Fatalf("malformed: %v", err)
	}
	if (fence{strict: true}).stale() != errPrecondition || (fence{}).stale() != errConcurrent || version(3) != `W/"3"` {
		t.Fatal("stale/version")
	}
	p := wire(t, acme)
	if _, err := p.doGate(context.Background(), nil, gateRequest{}); !errors.Is(err, auth.ErrUnknownOperation) {
		t.Fatalf("gate over a transport: %v", err)
	}
	if rl := p.RateLimits(); len(rl) != 2 || rl[0].Limit != DefaultRequestLimit || (gateRequest{Connection: "c"}).RateIdentifier() != "c" || len(p.Operations()) != 1 {
		t.Fatal("rules")
	}
}

// TestApplyPatch_EdgeShapes pins the shapes TestApplyPatch leaves out: a
// value that is not JSON, a path-less enterprise object naming a
// sub-attribute, a read-only key in a path-less object, a sub-attribute
// patch on an empty list or a list with no primary, a single object added to
// a list, a filter on a non-string value and a path in another case.
func TestApplyPatch_EdgeShapes(t *testing.T) {
	doc := map[string]any{"userName": "ada"}
	if err := applyPatch(doc, []PatchOp{{Op: "add", Path: "title", Value: json.RawMessage(`{`)}}); !errors.Is(err, errSyntax) {
		t.Fatalf("value that is not JSON: %v", err)
	}
	// A path-less enterprise object reads "manager.value" as the path form
	// does, so it lands inside manager, and manager.displayName is refused.
	doc, err := patchDoc(t, `[{"op":"replace","value":{"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"manager.value":"boss"}}}]`)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(doc); !strings.Contains(string(b), `"manager":{"value":"boss"}`) {
		t.Fatalf("path-less manager.value = %s", b)
	}
	var se *Error
	if _, err := patchDoc(t, `[{"op":"replace","value":{"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"manager.displayName":"x"}}}]`); !errors.As(err, &se) || se.Type != Mutability {
		t.Fatalf("path-less manager.displayName: %v", err)
	}
	if _, err := patchDoc(t, `[{"op":"replace","value":{"meta":{}}}]`); !errors.As(err, &se) || se.Type != Mutability {
		t.Fatalf("path-less read-only key: %v", err)
	}
	doc, err = patchDoc(t, `[
		{"op":"replace","path":"phoneNumbers","value":[]},
		{"op":"replace","path":"phoneNumbers.value","value":"1"},
		{"op":"replace","path":"addresses","value":["junk",{"formatted":"a"},{"formatted":"b"}]},
		{"op":"replace","path":"addresses.formatted","value":"c"},
		{"op":"add","path":"members","value":{"value":"m9"}},
		{"op":"add","path":"members","value":[{"value":7}]},
		{"op":"replace","path":"NAME.givenName","value":"Augusta"}
	]`)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(doc)
	for _, want := range []string{`"phoneNumbers":[{"primary":true,"value":"1"}]`, `"addresses":["junk",{"formatted":"c"},{"formatted":"b"}]`,
		`{"value":"m9"},{"value":7}`, `"name":{"givenName":"Augusta"}`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %s in %s", want, b)
		}
	}
	// A value filter matches only strings and booleans: the numeric member
	// value is no match.
	if _, err := patchDoc(t, `[{"op":"add","path":"members","value":[{"value":7}]},{"op":"remove","path":"members[value eq \"7\"]"}]`); !errors.As(err, &se) || se.Type != NoTarget {
		t.Fatalf("filter on a number: %v", err)
	}
}

// TestParseProjection_SkipsEmptyNames: "attributes=,userName" names one
// attribute, not an empty one.
func TestParseProjection_SkipsEmptyNames(t *testing.T) {
	pr, err := parseProjection(url.Values{"attributes": {" ,userName,"}})
	if err != nil || len(pr.paths) != 1 || pr.paths[0] != [2]string{"userName", ""} {
		t.Fatalf("%+v %v", pr, err)
	}
}

// TestLocation_MemberRefFromAGroupRequest: a link to /Users built while
// serving a /Groups request names /Users under the mount, never
// /Groups/Users; the mount is found with and without a prefix strip.
func TestLocation_MemberRefFromAGroupRequest(t *testing.T) {
	const base = "https://app.example.com"
	for _, target := range []string{"/scim/v2/Groups/grp_1", "/scim/v2/Groups", "/scim/v2/Groups?filter=x", "/scim/v2/Users/scu_9"} {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		if got := location(r, base, pathUsers, "scu_1"); got != base+"/scim/v2/Users/scu_1" {
			t.Errorf("%s: member $ref = %s", target, got)
		}
		if got := location(r, base, pathGroups, "grp_1"); got != base+"/scim/v2/Groups/grp_1" {
			t.Errorf("%s: group location = %s", target, got)
		}
		// Behind http.StripPrefix the handler sees only its own path.
		stripped := httptest.NewRequest(http.MethodGet, target, nil)
		stripped.URL.Path = strings.TrimPrefix(stripped.URL.Path, "/scim/v2")
		stripped.URL.RawPath = ""
		if got := location(stripped, base, pathUsers, "scu_1"); got != base+"/scim/v2/Users/scu_1" {
			t.Errorf("%s stripped: member $ref = %s", target, got)
		}
	}
	// A mount whose own path holds a Users segment keeps it.
	r := httptest.NewRequest(http.MethodGet, "/tenants/Users/scim/Groups/grp_1", nil)
	r.URL.Path = "/Groups/grp_1"
	if got := location(r, base, pathUsers, "scu_1"); got != base+"/tenants/Users/scim/Users/scu_1" {
		t.Errorf("mount with a Users segment: %s", got)
	}
}

// TestGate_NotOffered: EndpointRequest is registered, so rate rules and
// hooks can name it, but no transport serves it and no generated surface
// (the TypeScript client, its method list, the OpenAPI document) lists it,
// because every caller but Handler gets auth.unknown_operation.
func TestGate_NotOffered(t *testing.T) {
	a, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(signInStub{}, email.New(noMail()), New(acme)))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Operation(EndpointRequest); !ok {
		t.Fatal("the gate must stay registered")
	}
	for _, op := range a.Operations() {
		if op.Info().ID == EndpointRequest {
			t.Fatal("Auth.Operations lists the gate, so every transport mounts it")
		}
	}
	files, err := authhttp.TypeScriptClient(a)
	if err != nil {
		t.Fatal(err)
	}
	methods, err := authhttp.TypeScriptMethods(a)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range methods {
		if m.ID == EndpointRequest {
			t.Fatalf("TypeScriptMethods lists %+v", m)
		}
	}
	id := `"` + string(EndpointRequest) + `"`
	if strings.Contains(string(files[authhttp.TSFileClient]), id) {
		t.Fatal("client.ts lists the gate")
	}
	if strings.Contains(string(authhttp.OpenAPIDocument(a, authhttp.OpenAPIInfo{Title: "t", Version: "1"})), id) {
		t.Fatal("the OpenAPI document lists the gate")
	}
}
