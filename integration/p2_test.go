package integration

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/audit"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/sqlb"
)

// Partial rows of the better-auth comparison (core and OAuth concepts),
// finished: the email switches of social sign-in.

// p2Users counts the user rows.
func p2Users(t *testing.T, e *env) int {
	t.Helper()
	var n int
	if err := e.db.QueryRow("SELECT COUNT(*) FROM " + tbl(auth.TableNameUser)).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// RequireEmail refuses a profile with no address (better-auth's
// email_not_found) before anything is written, and admits an unverified one.
func TestOAuth_RequireEmail(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1"}}
		a := e.newAuth(t, nil, e.emailPlugin(), oauth.New(oauth.WithProviders(alpha), oauth.RequireEmail()))
		b := &tokensBrowser{a: a}
		tokensMust(t, b.start("alpha", oauth.StartRequest{}))
		if _, err := b.finish("alpha"); !errors.Is(err, oauth.ErrEmailNotFound) {
			t.Fatalf("no provider email: %v", err)
		}
		if n := p2Users(t, e); n != 0 {
			t.Fatalf("users after the refusal = %d", n)
		}
		alpha.profile = oauth.Profile{Subject: "a-1", Email: "ann@example.com"}
		if _, res := tokensSignIn(t, a, "alpha"); !res.Created || res.Token == "" {
			t.Fatalf("an unverified address under RequireEmail: %+v", res)
		}
	})
}

// VerifyEmailBeforeSignIn creates the user but issues no session until the
// address is verified, lands on the error page with the code, holds the
// id-token route the same way, and signs in once the address is verified.
func TestOAuth_VerifyEmailBeforeSignIn(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		alpha := newTokensNative("alpha", "a-1")
		alpha.profile.Email = "ann@example.com"
		a := e.newAuth(t, []auth.Option{auth.WithErrorURL("/signin-error")}, e.emailPlugin(), oauth.New(oauth.WithProviders(alpha), oauth.VerifyEmailBeforeSignIn()))

		b := &tokensBrowser{a: a}
		tokensMust(t, b.start("alpha", oauth.StartRequest{ReturnTo: "/home"}))
		res, err := b.finish("alpha")
		if err != nil || !res.Created || !res.EmailVerificationRequired || res.Token != "" || b.session != "" {
			t.Fatalf("held sign-in: %+v %v", res, err)
		}
		if res.RedirectTo != "/signin-error?error="+oauth.ErrEmailNotVerified.Code {
			t.Fatalf("landing %q", res.RedirectTo)
		}
		if n := p2Users(t, e); n != 1 {
			t.Fatalf("the held user must be kept: %d users", n)
		}
		// The request's own error page wins over the configured one.
		tokensMust(t, b.start("alpha", oauth.StartRequest{ErrorTo: "/oops?from=x"}))
		if res, err := b.finish("alpha"); err != nil || res.Created || !strings.HasPrefix(res.RedirectTo, "/oops?") || !strings.Contains(res.RedirectTo, "error=oauth.email_not_verified") || !strings.Contains(res.RedirectTo, "from=x") {
			t.Fatalf("held again: %+v %v", res, err)
		}
		// The native route is held too, with no redirect.
		nb := &tokensBrowser{a: a}
		if res, err := nb.idToken("alpha", oauth.IDTokenRequest{IDToken: alpha.mint()}); err != nil || !res.EmailVerificationRequired || res.Token != "" || res.RedirectTo != "" {
			t.Fatalf("held id-token sign-in: %+v %v", res, err)
		}

		// Once the address is verified, the next sign-in issues a session.
		id, err := a.FindIdentity(context.Background(), email.KindEmail, "ann@example.com", false)
		tokensMust(t, err)
		_, err = a.VerifyIdentity(context.Background(), id.ID)
		tokensMust(t, err)
		if _, res := tokensSignIn(t, a, "alpha"); res.EmailVerificationRequired || res.Token == "" {
			t.Fatalf("after verification: %+v", res)
		}

		// A provider that verified the address signs in at once.
		beta := &tokensProvider{name: "beta", profile: oauth.Profile{Subject: "b-1", Email: "bo@example.com", EmailVerified: true}}
		a2 := e.newAuth(t, nil, e.emailPlugin(), oauth.New(oauth.WithProviders(beta), oauth.VerifyEmailBeforeSignIn()))
		if _, res := tokensSignIn(t, a2, "beta"); res.EmailVerificationRequired || res.Token == "" {
			t.Fatalf("a verified provider address: %+v", res)
		}
		// A provider-initiated sign-in is held too, landing on the site root.
		corp := newTokensInitiated("corp", oauth.Profile{Subject: "c-1", Email: "cy@example.com"})
		a3 := e.newAuth(t, nil, e.emailPlugin(), oauth.New(oauth.WithProviders(corp), oauth.AllowProviderInitiated("corp"), oauth.VerifyEmailBeforeSignIn()))
		if res, err := (&tokensBrowser{a: a3}).initiated("corp", "dashboard-code"); err != nil || !res.EmailVerificationRequired || res.Token != "" || res.RedirectTo != "/?error="+oauth.ErrEmailNotVerified.Code {
			t.Fatalf("held provider-initiated sign-in: %+v %v", res, err)
		}
		// No address at all is refused before anything is written.
		beta.profile = oauth.Profile{Subject: "b-2"}
		before := p2Users(t, e)
		b2 := &tokensBrowser{a: a2}
		tokensMust(t, b2.start("beta", oauth.StartRequest{}))
		if _, err := b2.finish("beta"); !errors.Is(err, oauth.ErrEmailNotFound) || p2Users(t, e) != before {
			t.Fatalf("no address: %v", err)
		}
	})
}

// An id-token sign-in stores the SDK's access token when the ID token's
// at_hash binds it, and refuses one it does not bind before writing
// anything.
func TestOAuth_IDTokenAccessToken(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		const at = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y"
		alpha := newTokensNative("alpha", "a-1")
		// The fake verifier accepts this exact string; its header names the
		// algorithm the at_hash is computed with.
		alpha.goodToken = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`)) + ".e30.sig"
		alpha.profile.Email, alpha.profile.EmailVerified = "ann@example.com", true
		alpha.profile.Claims = map[string]json.RawMessage{"at_hash": json.RawMessage(`"77QmUPtjPfzWtF2AnpK9RQ"`)}
		oa := oauth.New(oauth.WithProviders(alpha), oauth.StoreTokens(tokensKey))
		a := e.newAuth(t, nil, e.emailPlugin(), oa)

		b := &tokensBrowser{a: a}
		if _, err := b.idToken("alpha", oauth.IDTokenRequest{IDToken: alpha.mint(), AccessToken: "not-the-bound-token"}); !errors.Is(err, oauth.ErrIDTokenInvalid) || p2Users(t, e) != 0 {
			t.Fatalf("an unbound access token: %v", err)
		}
		res, err := b.idToken("alpha", oauth.IDTokenRequest{IDToken: alpha.mint(), AccessToken: at})
		if err != nil || res.Token == "" {
			t.Fatalf("a bound access token: %+v %v", res, err)
		}
		ts, err := oa.Tokens(context.Background(), res.User.ID, "alpha")
		if err != nil || ts.AccessToken.Reveal() != at {
			t.Fatalf("stored tokens: %v", err)
		}
	})
}

// rowOwnerPlugin reads a session row the caller owns with RequireOwnerRow.
type rowOwnerPlugin struct {
	read *auth.Op[ownerIn, p2SessionRow]
	// last is what the columns held after the last call, success or not.
	last p2SessionRow
}

type p2SessionRow struct {
	UserAgent string `json:"userAgent"`
}

func newRowOwnerPlugin() *rowOwnerPlugin {
	p := &rowOwnerPlugin{}
	p.read = auth.Define(auth.OpInfo{ID: "rowownerp.read", Kind: auth.Query, Require: auth.SignedIn, Path: "/read"},
		func(ctx context.Context, c *auth.Call, in ownerIn) (p2SessionRow, error) {
			o := auth.Ownership{
				Table: auth.TableSession,
				ID:    sqlb.Col[string](auth.TableSession, auth.ColSessionID),
				Owner: sqlb.Col[string](auth.TableSession, auth.ColSessionUserID),
			}
			if in.Forbidden {
				o.Forbidden = errOwnerForbidden
			}
			var row p2SessionRow
			err := c.RequireOwnerRow(ctx, o, in.ID, sqlb.Bind(sqlb.Col[string](auth.TableSession, auth.ColSessionUserAgent), &row.UserAgent))
			p.last = row
			return row, err
		})
	return p
}

func (p *rowOwnerPlugin) Name() string                 { return "rowownerp" }
func (p *rowOwnerPlugin) Operations() []auth.Operation { return []auth.Operation{p.read} }

// RequireOwnerRow hands back the caller's own row, gives the same answers as
// RequireOwner otherwise, and never fills the columns with another user's
// values.
func TestRequireOwnerRow_EveryEngine(t *testing.T) {
	eachEngine(t, func(t *testing.T, env *env) {
		op := newRowOwnerPlugin()
		h := authtest.New(t, authtest.WithDB(env.db, env.d), authtest.WithOptions(auth.WithTablePrefix(tablePrefix())), authtest.WithPlugins(func(e *authtest.Env) []auth.Plugin {
			return append(harnessPlugins(e), op)
		}))
		ada, bob := h.CreateUser("Ada"), h.CreateUser("Bob")
		mine, theirs := h.SignIn(ada.ID), h.SignIn(bob.ID)
		ctx := mine.Context(context.Background())
		got, err := op.read.Call(ctx, ownerIn{ID: mine.Session.ID})
		if err != nil || got.UserAgent != mine.Session.UserAgent {
			t.Fatalf("own row: %+v %v (want user agent %q)", got, err, mine.Session.UserAgent)
		}
		for _, tc := range []struct {
			in   ownerIn
			want error
		}{
			{ownerIn{ID: theirs.Session.ID}, auth.ErrResourceNotFound},
			{ownerIn{ID: "ses_missing"}, auth.ErrResourceNotFound},
			{ownerIn{ID: theirs.Session.ID, Forbidden: true}, errOwnerForbidden},
			{ownerIn{}, auth.ErrBadRequest},
		} {
			op.last = p2SessionRow{UserAgent: "untouched"}
			if _, err := op.read.Call(ctx, tc.in); !errors.Is(err, tc.want) {
				t.Errorf("%+v: err = %v, want %v", tc.in, err, tc.want)
			}
			if op.last.UserAgent != "" {
				t.Errorf("%+v: columns filled with %q", tc.in, op.last.UserAgent)
			}
		}
		if _, err := op.read.Call(context.Background(), ownerIn{ID: mine.Session.ID}); !errors.Is(err, auth.ErrSignedOut) {
			t.Errorf("signed out: %v", err)
		}
	})
}

// Unlinking the only sign-in method is refused by default and allowed under
// AllowUnlinkingAll.
func TestOAuth_AllowUnlinkingAll(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		for _, all := range []bool{false, true} {
			alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1"}}
			opts := []oauth.Option{oauth.WithProviders(alpha)}
			if all {
				opts = append(opts, oauth.AllowUnlinkingAll())
			}
			oa := oauth.New(opts...)
			a := e.newAuth(t, nil, oa)
			b, res := tokensSignIn(t, a, "alpha")
			_, err := tokensInvoke[auth.Done](b.ctx(), a, oauth.EndpointUnlink, oauth.UnlinkRequest{Provider: "alpha"})
			left, lerr := oa.Accounts(context.Background(), res.User.ID)
			tokensMust(t, lerr)
			switch {
			case !all && (!errors.Is(err, auth.ErrLastSignInMethod) || len(left) != 1):
				t.Fatalf("default: %v, %d accounts left", err, len(left))
			case all && (err != nil || len(left) != 0):
				t.Fatalf("AllowUnlinkingAll: %v, %d accounts left", err, len(left))
			}
		}
	})
}

// p2Tracer records every span's info.
type p2Tracer struct{ spans []auth.SpanInfo }

func (r *p2Tracer) Start(ctx context.Context, s auth.SpanInfo) (context.Context, auth.Span) {
	r.spans = append(r.spans, s)
	return ctx, p2Span{}
}

type p2Span struct{}

func (p2Span) End(error) {}

// Database and data-hook spans (better-auth's "db {operation} {model}"):
// every statement of a user creation is a span with its verb and real table,
// and the data hook is a span of its own; no span carries SQL.
func TestTracer_DatabaseSpans(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		tr := &p2Tracer{}
		hooks := auth.DataHooks{User: auth.TableHooks[auth.User]{BeforeCreate: func(context.Context, sqlb.DBTX, *auth.User) error { return nil }}}
		a := e.newAuth(t, []auth.Option{auth.WithTracer(tr), auth.WithDataHooks(hooks)}, e.emailPlugin(), e.passwordPlugin())
		tr.spans = nil
		if _, err := a.CreateUser(context.Background(), auth.NewUser{Name: "Ada"}); err != nil {
			t.Fatal(err)
		}
		var insert, hook bool
		for _, s := range tr.spans {
			switch {
			case s.Kind == auth.SpanDatabase && s.DBOperation == "insert" && s.Table == a.TableName(auth.TableUser):
				insert = s.Name == "auth.db insert "+s.Table
			case s.Kind == auth.SpanDataHook && s.DBOperation == "before_create" && s.Table == "user":
				hook = true
			}
			if strings.Contains(s.Name, "VALUES") || strings.Contains(s.Name, "$1") || strings.Contains(s.Name, "?") {
				t.Fatalf("a span name carries SQL: %q", s.Name)
			}
		}
		if !insert || !hook {
			t.Fatalf("insert span %v, hook span %v: %+v", insert, hook, tr.spans)
		}
	})
}

// LinkUnverifiedLocalEmail links a verified provider address to a local
// account holding it unverified; the default refuses that link.
func TestOAuth_LinkUnverifiedLocalEmail(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		for i, on := range []bool{false, true} {
			addr := fmt.Sprintf("ann%d@example.com", i)
			alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: fmt.Sprintf("a-%d", i), Email: addr, EmailVerified: true}}
			opts := []oauth.Option{oauth.WithProviders(alpha)}
			if on {
				opts = append(opts, oauth.LinkUnverifiedLocalEmail())
			}
			a := e.newAuth(t, nil, e.emailPlugin(), oauth.New(opts...))
			ctx := context.Background()
			local, err := a.CreateUser(ctx, auth.NewUser{Name: "Squatter"})
			tokensMust(t, err)
			_, err = a.CreateIdentity(ctx, auth.NewIdentity{UserID: local.ID, Kind: email.KindEmail, Raw: addr})
			tokensMust(t, err)
			b := &tokensBrowser{a: a}
			tokensMust(t, b.start("alpha", oauth.StartRequest{}))
			res, err := b.finish("alpha")
			switch {
			case on && (err != nil || res.User.ID != local.ID || res.Created):
				t.Fatalf("with the option: %+v %v", res, err)
			case !on && err == nil && res.User.ID == local.ID:
				t.Fatalf("default linked to an unverified local address: %+v", res)
			}
		}
	})
}

// WithProfileFields lets the user set listed app columns of their own row on
// POST /profile; an unlisted column or a wrong type refuses the whole update.
func TestUpdateProfile_Fields(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		bio := sqlb.Col[*string](auth.TableUser, "p2_bio")
		plan := sqlb.Col[*string](auth.TableUser, "p2_plan")
		a := coreAuth(t, e, nil, auth.WithUserColumns(
			auth.ColumnExtension{Name: "p2_bio", Type: auth.ColumnText, Nullable: true},
			auth.ColumnExtension{Name: "p2_plan", Type: auth.ColumnText, Nullable: true},
		), auth.WithProfileFields("p2_bio"))
		ctx := context.Background()
		u := must[auth.User](t)(a.CreateUser(ctx, auth.NewUser{Name: "Ada"}))
		_, tok, err := a.CreateSession(ctx, u.ID, auth.Client{})
		tokensMust(t, err)
		signed := a.WithRequest(ctx, auth.Request{Transport: auth.TransportHTTP, Credential: auth.CredentialBearer, Token: tok})
		read := func() (b, p *string) {
			t.Helper()
			tokensMust(t, a.LoadUserColumns(ctx, u.ID, sqlb.Bind(bio, &b), sqlb.Bind(plan, &p)))
			return
		}
		name := "Ada L."
		if _, err := a.UpdateProfile(signed, auth.ProfileRequest{Name: &name, Fields: auth.Fields{"p2_bio": json.RawMessage(`"maths"`)}}); err != nil {
			t.Fatal(err)
		}
		if b, _ := read(); b == nil || *b != "maths" {
			t.Fatalf("bio %v", b)
		}
		other := "Mallory"
		for _, f := range []auth.Fields{{"p2_plan": json.RawMessage(`"pro"`)}, {"p2_bio": json.RawMessage(`7`)}, {"name": json.RawMessage(`"x"`)}} {
			signed = a.WithRequest(ctx, auth.Request{Transport: auth.TransportHTTP, Credential: auth.CredentialBearer, Token: tok})
			if _, err := a.UpdateProfile(signed, auth.ProfileRequest{Name: &other, Fields: f}); !errors.Is(err, auth.ErrFieldInvalid) {
				t.Fatalf("%v: %v", f, err)
			}
		}
		if b, p := read(); p != nil || *b != "maths" {
			t.Fatalf("a refused update wrote: bio %v plan %v", b, p)
		}
		if got := must[auth.User](t)(a.User(ctx, u.ID)); got.Name != name {
			t.Fatalf("a refused update changed the name to %q", got.Name)
		}
	})
}

// WithUserLocale: a signed-in user's stored locale wins over the client's,
// once the session is resolved; a signed-out request, an empty or a
// malformed value keeps the client's.
func TestWithUserLocale(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a := coreAuth(t, e, nil, auth.WithUserColumns(auth.ColumnExtension{Name: "p2_locale", Type: auth.ColumnText, Nullable: true}), auth.WithUserLocale("p2_locale"))
		ctx := context.Background()
		u := must[auth.User](t)(a.CreateUser(ctx, auth.NewUser{Name: "Ada"}))
		_, tok, err := a.CreateSession(ctx, u.ID, auth.Client{})
		tokensMust(t, err)
		req := func(token auth.Token) context.Context {
			r := auth.Request{Transport: auth.TransportHTTP, Client: auth.Client{Locale: "en"}}
			if token != "" {
				r.Credential, r.Token = auth.CredentialBearer, token
			}
			c := a.WithRequest(ctx, r)
			tokensMust(t, a.Resolve(c))
			return c
		}
		if got := a.Locale(req(tok)); got != "en" {
			t.Fatalf("no stored locale: %q", got)
		}
		for value, want := range map[string]string{"de": "de", "not a tag!": "en"} {
			tokensMust(t, auth.SetUserColumn(ctx, a, auth.AppName, u.ID, sqlb.Col[string](auth.TableUser, "p2_locale"), value))
			if got := a.Locale(req(tok)); got != want {
				t.Fatalf("stored %q: %q, want %q", value, got, want)
			}
		}
		tokensMust(t, auth.SetUserColumn(ctx, a, auth.AppName, u.ID, sqlb.Col[string](auth.TableUser, "p2_locale"), "de"))
		if got := a.Locale(req("")); got != "en" {
			t.Fatalf("signed out: %q", got)
		}
	})
}

// p2StartCookie starts a flow whose flow cookie holds the sealed state, and
// returns the state the provider would send back.
func p2StartCookie(t *testing.T, b *tokensBrowser, provider string, in oauth.StartRequest) string {
	t.Helper()
	ctx := b.ctx()
	res, err := tokensInvoke[oauth.StartResult](ctx, b.a, oauth.StartEndpoint(provider), in)
	tokensMust(t, err)
	for _, ef := range auth.RequestEffects(ctx) {
		if ef.Kind == auth.EffectBindFlow {
			b.flow = ef.Token
		}
	}
	u, err := url.Parse(res.URL)
	tokensMust(t, err)
	return u.Query().Get("state")
}

// StateInCookie keeps the flow in the sealed flow cookie: the start writes no
// verification row, the callback signs in, and a forged, crossed or expired
// cookie is refused.
func TestOAuth_StateInCookie(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		secret := auth.WithSecret([]byte(strings.Repeat("s", auth.MinSecretSize)))
		alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1", Email: "ann@example.com", EmailVerified: true}}
		beta := &tokensProvider{name: "beta", profile: oauth.Profile{Subject: "b-1"}}
		a := e.newAuth(t, []auth.Option{secret}, e.emailPlugin(), oauth.New(oauth.WithProviders(alpha, beta), oauth.StateInCookie()))
		rows := func() int {
			var n int
			tokensMust(t, e.db.QueryRow("SELECT COUNT(*) FROM "+tbl(auth.TableNameVerification)).Scan(&n))
			return n
		}
		before := rows()
		b := &tokensBrowser{a: a}
		state := p2StartCookie(t, b, "alpha", oauth.StartRequest{ReturnTo: "/home"})
		if rows() != before || state == "" || b.flow.Reveal() == state {
			t.Fatalf("the start wrote a row (%d -> %d) or bound the bare state", before, rows())
		}
		res, err := b.callback("alpha", oauth.CallbackRequest{Code: "c", State: state})
		if err != nil || res.Token == "" || res.RedirectTo != "/home" {
			t.Fatalf("callback: %+v %v", res, err)
		}
		b2 := &tokensBrowser{a: a}
		state = p2StartCookie(t, b2, "alpha", oauth.StartRequest{})
		if _, err := b2.callback("beta", oauth.CallbackRequest{Code: "c", State: state}); !errors.Is(err, oauth.ErrStateInvalid) {
			t.Fatalf("alpha's cookie at beta: %v", err)
		}
		good := b2.flow
		// A different first character, never the one already there: a
		// sealed value starting with "A" would otherwise be left as it was.
		forged := "A"
		if good.Reveal()[0] == 'A' {
			forged = "B"
		}
		b2.flow = auth.Token(forged + good.Reveal()[1:])
		if _, err := b2.callback("alpha", oauth.CallbackRequest{Code: "c", State: state}); !errors.Is(err, oauth.ErrStateInvalid) {
			t.Fatalf("forged cookie: %v", err)
		}
		b2.flow = good
		if _, err := b2.callback("alpha", oauth.CallbackRequest{Code: "c", State: "not-the-state"}); !errors.Is(err, oauth.ErrStateInvalid) {
			t.Fatalf("wrong state: %v", err)
		}
		e.clock.Advance(oauth.DefaultStateTTL + time.Minute)
		if _, err := b2.callback("alpha", oauth.CallbackRequest{Code: "c", State: state}); !errors.Is(err, oauth.ErrStateInvalid) {
			t.Fatalf("expired cookie: %v", err)
		}
	})
}

// ChangeWithoutVerification replaces even a verified address at once, the
// new one unverified and mailed its verification; the default keeps the
// two-step change.
func TestEmailChangeWithoutVerification(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		for i, on := range []bool{false, true} {
			var em *email.Plugin
			if on {
				em = e.emailPlugin(email.ChangeWithoutVerification())
			} else {
				em = e.emailPlugin()
			}
			a := e.newAuth(t, nil, em, e.passwordPlugin())
			old, fresh := fmt.Sprintf("old%d@example.com", i), fmt.Sprintf("new%d@example.com", i)
			_, tok := identUser(t, a, old)
			if err := em.Change(request(a, tok), fresh); err != nil {
				t.Fatalf("on=%v: %v", on, err)
			}
			got := identAddresses(t, em, a, tok)
			switch {
			case on && (strings.Contains(got, old) || !strings.Contains(got, fresh)):
				t.Fatalf("with the option: %q", got)
			case !on && (!strings.Contains(got, old) || strings.Contains(got, fresh)):
				t.Fatalf("default: %q", got)
			}
		}
	})
}

// p2Notes is a plugin whose table comes from a TableSchema.
type p2Notes struct{ a *auth.Auth }

var p2NoteTable = sqlb.Table{Name: "p2_note"}

func (p *p2Notes) Name() string            { return "p2notes" }
func (p *p2Notes) Tables() []sqlb.Table    { return []sqlb.Table{p2NoteTable} }
func (p *p2Notes) Init(a *auth.Auth) error { p.a = a; return nil }
func (p *p2Notes) Migrations(engine string) ([]auth.Migration, error) {
	m, err := p.a.SchemaMigration(engine, "p2notes", "0001_note", auth.TableSchema{
		Table: p2NoteTable, ID: "id",
		Columns: []auth.SchemaColumn{{Name: "user_id", Type: auth.ColumnText}, {Name: "slug", Type: auth.ColumnText, Unique: true}, {Name: "pinned", Type: auth.ColumnBool, Default: "false"}, {Name: "at", Type: auth.ColumnTimestamp, Nullable: true}, {Name: "n", Type: auth.ColumnInt, Default: "0"}},
		Indexes: []auth.SchemaIndex{{Name: "by_user", Columns: []string{"user_id", "at"}}},
	})
	return []auth.Migration{m}, err
}

// A TableSchema migration applies on every engine (twice, idempotently),
// and its unique column refuses a duplicate.
func TestSchemaMigration_EveryEngine(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		notes := &p2Notes{}
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), notes)
		ctx := context.Background()
		if _, err := a.Migrate(ctx); err != nil {
			t.Fatalf("second migrate: %v", err)
		}
		ins := func(id, slug string) error {
			_, err := a.Exec(ctx, sqlb.NewInsert(a.Dialect()).Into(p2NoteTable).Row(
				sqlb.Set(sqlb.Col[string](p2NoteTable, "id"), id), sqlb.Set(sqlb.Col[string](p2NoteTable, "user_id"), "u1"), sqlb.Set(sqlb.Col[string](p2NoteTable, "slug"), slug)))
			return err
		}
		// The engines' databases outlive a run, so every value is fresh.
		run := auth.NewToken().Reveal()[:12]
		tokensMust(t, ins("n1"+run, "hello"+run))
		if err := ins("n2"+run, "hello"+run); !auth.IsUniqueViolation(err) {
			t.Fatalf("duplicate slug: %v", err)
		}
		var pinned bool
		tokensMust(t, a.One(ctx, a.Select().Columns(sqlb.Bind(sqlb.Col[bool](p2NoteTable, "pinned"), &pinned)).From(p2NoteTable).Where(sqlb.Eq(sqlb.Col[string](p2NoteTable, "id"), "n1"+run))))
		if pinned {
			t.Fatal("default false not applied")
		}
	})
}

// The audit list takes auth.WithDefaultPageSize, and a request still wins up
// to the list's own maximum.
func TestAudit_DefaultPageSize(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		au := audit.New()
		e.newAuth(t, []auth.Option{auth.WithDefaultPageSize(3)}, e.emailPlugin(), e.passwordPlugin(), au)
		ctx := context.Background()
		if pg := must[audit.Page](t)(au.Events(ctx, audit.Query{})); pg.Limit != 3 {
			t.Fatalf("default limit %d", pg.Limit)
		}
		if pg := must[audit.Page](t)(au.Events(ctx, audit.Query{Limit: 7})); pg.Limit != 7 {
			t.Fatalf("requested limit %d", pg.Limit)
		}
		if pg := must[audit.Page](t)(au.Events(ctx, audit.Query{Limit: audit.MaxPageSize + 1})); pg.Limit != audit.MaxPageSize {
			t.Fatalf("over the cap %d", pg.Limit)
		}
	})
}

// Every OAuth outcome annotates its call with oauth.AnnotationAction, which
// an After or Finally hook (the audit log) reads.
func TestOAuth_AnnotationAction(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var seen []string
		hook := auth.OperationHook{Finally: func(_ context.Context, c *auth.Call, err error) {
			if v := c.Annotation(oauth.AnnotationAction); v != "" && err == nil {
				seen = append(seen, v)
			}
		}}
		alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1", Email: "ann@example.com", EmailVerified: true}}
		beta := &tokensProvider{name: "beta", profile: oauth.Profile{Subject: "b-1", Email: "ann@example.com", EmailVerified: true}}
		gamma := &tokensProvider{name: "gamma", profile: oauth.Profile{Subject: "g-1"}}
		a := e.newAuth(t, []auth.Option{auth.WithOperationHooks(hook)}, e.emailPlugin(), oauth.New(oauth.WithProviders(alpha, beta, gamma)))
		b, _ := tokensSignIn(t, a, "alpha") // sign-up, verified ann@
		tokensSignIn(t, a, "alpha")         // sign-in
		tokensSignIn(t, a, "beta")          // link by the verified address
		tokensLink(t, b, "gamma")           // explicit link
		want := []string{string(oauth.AccountSignUp), string(oauth.AccountSignIn), string(oauth.AccountLinkedByEmail), string(oauth.AccountLinked)}
		if strings.Join(seen, ",") != strings.Join(want, ",") {
			t.Fatalf("annotations %v, want %v", seen, want)
		}
	})
}

// p2ParamRefresher records the parameters a refresh sent.
type p2ParamRefresher struct {
	*tokensRefresher
	sent url.Values
}

func (r *p2ParamRefresher) RefreshWithParams(ctx context.Context, hc *http.Client, rt auth.Token, params url.Values) (oauth.TokenSet, error) {
	r.sent = params
	return r.Refresh(ctx, hc, rt)
}

// The refresh parameters of an exchange (VK ID's device_id) are stored
// sealed with the tokens, survive a refresh that does not restate them, and
// are sent with every refresh.
func TestOAuth_RefreshParamsStored(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		past := e.clock.Now().Add(-time.Minute)
		prov := &p2ParamRefresher{tokensRefresher: &tokensRefresher{
			tokensProvider: &tokensProvider{name: "vk", profile: oauth.Profile{Subject: "v-1", Tokens: oauth.TokenSet{
				AccessToken: "at-1", RefreshToken: "rt-1", ExpiresAt: past, RefreshParams: url.Values{"device_id": {"dev-1"}},
			}}},
			fresh: oauth.TokenSet{AccessToken: "at-2", ExpiresAt: e.clock.Now().Add(time.Hour)},
		}}
		oa := oauth.New(oauth.WithProviders(prov), oauth.StoreTokens(tokensKey))
		a := e.newAuth(t, nil, oa)
		_, res := tokensSignIn(t, a, "vk")
		var raw *string
		tokensMust(t, e.db.QueryRow("SELECT "+oauth.ColAccountRefreshParams+" FROM "+tbl(oauth.TableNameAccount)+" WHERE subject = 'v-1'").Scan(&raw))
		if raw == nil || strings.Contains(*raw, "dev-1") {
			t.Fatalf("stored parameters must be sealed: %v", raw)
		}
		ts, err := oa.Refresh(context.Background(), res.User.ID, "vk")
		if err != nil || ts.AccessToken.Reveal() != "at-2" || prov.sent.Get("device_id") != "dev-1" {
			t.Fatalf("refresh: %v, sent %v", err, prov.sent)
		}
		// The fresh set restated none: the stored ones are kept for the next.
		prov.sent = nil
		if _, err := oa.Refresh(context.Background(), res.User.ID, "vk"); err != nil || prov.sent.Get("device_id") != "dev-1" {
			t.Fatalf("second refresh: %v, sent %v", err, prov.sent)
		}
	})
}

// p2Invite is a sending plugin's typed message payload.
type p2Invite struct{ Org string }

// p2Mail is the email plugin that records what it delivers and decodes the
// p2Invite payload of its purpose.
type p2Mail struct {
	*email.Plugin
	got []auth.Message
}

const p2PurposeInvite auth.Purpose = "p2.invite"

func (m *p2Mail) Deliver(ctx context.Context, _ auth.Identity, msg auth.Message) error {
	// A dead context is the crashed process: nothing is delivered, so the
	// outbox row is what carries the message.
	if err := ctx.Err(); err != nil {
		return err
	}
	m.got = append(m.got, msg)
	return nil
}

func (m *p2Mail) DecodeMessageData(p auth.Purpose, raw json.RawMessage) (any, error) {
	if p != p2PurposeInvite {
		return nil, nil
	}
	var v p2Invite
	return v, json.Unmarshal(raw, &v)
}

// Message.Data survives the delivery outbox with its type, through the
// sender's MessageDataDecoder; Data nobody decodes is refused at enqueue.
func TestMessageData_ThroughTheOutbox(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		dead, kill := context.WithCancel(context.Background())
		kill()
		crash := auth.WithBackground(func(_ context.Context, task func(context.Context)) { task(dead) })
		mail := &p2Mail{Plugin: email.New(email.Login(), email.Recover(), email.WithMailer(email.MailerFunc(func(context.Context, email.Mail) error { return nil })))}
		a := e.newAuth(t, []auth.Option{auth.WithDeliveryOutbox(sessKey), crash}, mail, e.passwordPlugin())
		ctx := context.Background()
		to := auth.Identity{Kind: email.KindEmail, Value: "ada@example.com"}
		if err := a.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
			return a.Deliver(ctx, to, auth.Message{Purpose: p2PurposeInvite, Data: p2Invite{Org: "Acme"}})
		}); err != nil {
			t.Fatal(err)
		}
		// The crashed first send leased the row; once the lease is over the
		// sweep sends it from the stored payload.
		e.clock.Advance(time.Hour)
		if _, err := a.SendOutbox(ctx); err != nil {
			t.Fatal(err)
		}
		if len(mail.got) != 1 {
			t.Fatalf("%d deliveries, want the outbox's one", len(mail.got))
		}
		if d, ok := mail.got[len(mail.got)-1].Data.(p2Invite); !ok || d.Org != "Acme" {
			t.Fatalf("data %#v", mail.got[len(mail.got)-1].Data)
		}
		err := a.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
			return a.Deliver(ctx, to, auth.Message{Purpose: auth.PurposeVerify, Data: p2Invite{Org: "Acme"}})
		})
		if !errors.Is(err, auth.ErrMessageDataUndecodable) {
			t.Fatalf("undecodable data: %v", err)
		}
	})
}

// RateHit and RatePeek on the database rate store, every engine.
func TestRateHitAndPeek_DBStore(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		// Built by hand: the harness passes a memory rate store, and the two
		// cannot be combined.
		a, err := auth.New(e.withDB(), auth.WithBaseURL(testBaseURL), auth.WithClock(e.clock.Now), auth.WithDBRateStore(), auth.WithPlugins(e.emailPlugin(), e.passwordPlugin()))
		tokensMust(t, err)
		ctx := context.Background()
		_, err = a.Migrate(ctx)
		tokensMust(t, err)
		key := "p2|" + auth.NewToken().Reveal()
		if !a.CanPeekRates() {
			t.Fatal("the database store must peek")
		}
		if n, err := a.RatePeek(ctx, key, time.Minute); err != nil || n != 0 {
			t.Fatalf("empty: %d %v", n, err)
		}
		for want := 1; want <= 2; want++ {
			if n, err := a.RateHit(ctx, key, time.Minute); err != nil || n != want {
				t.Fatalf("hit %d: %d %v", want, n, err)
			}
		}
		if n, err := a.RatePeek(ctx, key, time.Minute); err != nil || n != 2 {
			t.Fatalf("peek: %d %v", n, err)
		}
		e.clock.Advance(time.Minute)
		if n, _ := a.RatePeek(ctx, key, time.Minute); n != 0 {
			t.Fatalf("a new window: %d", n)
		}
	})
}

// p2InitProbe records CanPeekRates as its Init sees it.
type p2InitProbe struct{ canPeek *bool }

func (p2InitProbe) Name() string              { return "p2probe" }
func (p p2InitProbe) Init(a *auth.Auth) error { *p.canPeek = a.CanPeekRates(); return nil }

// CanPeekRates answers yes during Init under WithDBRateStore, before the
// limiter that holds the database store exists.
func TestCanPeekRates_DuringInitWithDBStore(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var got bool
		_, err := auth.New(e.withDB(), auth.WithBaseURL(testBaseURL), auth.WithDBRateStore(), auth.WithPlugins(e.emailPlugin(), e.passwordPlugin(), p2InitProbe{canPeek: &got}))
		tokensMust(t, err)
		if !got {
			t.Fatal("CanPeekRates during Init with the database store: false")
		}
	})
}
