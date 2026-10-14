package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/verificationtest"
	"github.com/ubgo/sqlb"
)

// Round 20 on real databases: the verification store contract on the SQL
// store, verification tokens kept outside the database end to end, the
// state-cookie escape hatch of the OAuth plugin and the CSRF escape hatch.

// The SQL store keeps the shared verification contract on every engine.
func TestVerificationStore_SQLConforms(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a := coreAuth(t, e, nil)
		verificationtest.Run(t, func(t *testing.T) auth.VerificationStore {
			q := sqlb.NewDelete(a.Dialect()).From(auth.TableVerification).
				Where(sqlb.In(auth.VerificationPurpose, verificationtest.PurposeA, verificationtest.PurposeB))
			if _, err := a.Exec(context.Background(), q); err != nil {
				t.Fatal(err)
			}
			return a.VerificationStore()
		})
	})
}

// With a memory store, tokens are issued, spent once, ended by
// ConsumeAllVerifications and by DeleteUser, and never touch the table; an
// OAuth flow keeps its state there too.
func TestVerificationStore_OutsideTheDatabase(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "r20-a"}}
		a := e.newAuth(t, []auth.Option{auth.WithVerificationStore(auth.NewMemoryVerificationStore(e.clock.Now))},
			e.emailPlugin(), oauth.New(oauth.WithProviders(alpha)))
		ctx := context.Background()
		before := r20VerificationRows(t, a)
		u, _ := coreUser(t, a)

		tok := must[auth.Token](t)(a.IssueVerification(ctx, corePurpose, u.ID, time.Hour, "m"))
		v, err := a.ConsumeVerification(ctx, corePurpose, tok)
		if err != nil || v.Identifier != u.ID || v.Meta != "m" || v.ConsumedAt == nil {
			t.Fatalf("consume = %+v %v", v, err)
		}
		if _, err := a.ConsumeVerification(ctx, corePurpose, tok); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("second consume = %v, want ErrTokenInvalid", err)
		}

		tok = must[auth.Token](t)(a.IssueVerification(ctx, corePurpose, u.ID, time.Hour, ""))
		if err := a.ConsumeAllVerifications(ctx, corePurpose, u.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := a.ConsumeVerification(ctx, corePurpose, tok); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("a token ConsumeAllVerifications ended = %v", err)
		}

		tok = must[auth.Token](t)(a.IssueVerification(ctx, corePurpose, u.ID, time.Hour, ""))
		if err := a.DeleteUser(ctx, u.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := a.ConsumeVerification(ctx, corePurpose, tok); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("a deleted user's token = %v", err)
		}

		if _, res := tokensSignIn(t, a, "alpha"); res.Token == "" {
			t.Fatal("an OAuth sign-in with its state in the memory store issued no session")
		}
		if after := r20VerificationRows(t, a); after != before {
			t.Fatalf("auth_verification went from %d to %d rows with the memory store", before, after)
		}
		got, err := a.Sweep(ctx, 0)
		if err != nil || got[auth.CorePluginName+"."+auth.TableNameVerification] != 0 {
			t.Fatalf("Sweep = %v %v; the memory store expires its own records", got, err)
		}
	})
}

func r20VerificationRows(t *testing.T, a *auth.Auth) int64 {
	t.Helper()
	var n int64
	q := a.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(auth.TableVerification)
	if err := a.One(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	return n
}

// The login CSRF that SkipStateCookieCheck opens, shown both ways: the
// attacker starts a flow, and the victim's browser, holding no flow cookie,
// completes it.
func TestOAuth_SkipStateCookieCheck(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		for _, skip := range []bool{false, true} {
			alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "r20-attacker"}}
			opts := []oauth.Option{oauth.WithProviders(alpha)}
			if skip {
				opts = append(opts, oauth.SkipStateCookieCheck())
			}
			var log bytes.Buffer
			a := e.newAuth(t, []auth.Option{auth.WithLogger(slog.New(slog.NewTextHandler(&log, nil)))}, e.emailPlugin(), oauth.New(opts...))
			if warned := strings.Contains(log.String(), oauth.WarnStateCookieCheckOff); warned != skip {
				t.Fatalf("skip=%v: warned=%v (%s)", skip, warned, log.String())
			}
			attacker := &tokensBrowser{a: a}
			tokensMust(t, attacker.start("alpha", oauth.StartRequest{}))
			victim := &tokensBrowser{a: a}
			res, err := victim.callback("alpha", oauth.CallbackRequest{Code: "c", State: attacker.flow.Reveal()})
			if !skip {
				if !errors.Is(err, oauth.ErrStateInvalid) {
					t.Fatalf("a callback without the flow cookie = %v, want ErrStateInvalid", err)
				}
				continue
			}
			if err != nil || res.Token == "" {
				t.Fatalf("with the check skipped the callback = %+v %v", res, err)
			}
			// The state itself is still single use and still checked.
			if _, err := victim.callback("alpha", oauth.CallbackRequest{Code: "c", State: attacker.flow.Reveal()}); !errors.Is(err, oauth.ErrStateInvalid) {
				t.Fatalf("a spent state replayed = %v", err)
			}
			if _, err := victim.callback("alpha", oauth.CallbackRequest{Code: "c", State: "made-up"}); !errors.Is(err, oauth.ErrStateInvalid) {
				t.Fatalf("a made-up state = %v", err)
			}
			if _, err := victim.callback("alpha", oauth.CallbackRequest{Code: "c"}); !errors.Is(err, oauth.ErrStateInvalid) {
				t.Fatalf("no state = %v", err)
			}
		}
	})
}

// WithoutCSRFCheck lets another site sign the user out with their cookie;
// without it the same request is refused.
func TestWithoutCSRFCheck_CookieMutationFromAnotherSite(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		strict := coreAuth(t, e, nil)
		open := coreAuth(t, e, nil, auth.WithoutCSRFCheck())
		_, tok := coreSignedIn(t, strict)
		req := auth.Request{Transport: auth.TransportHTTP, Credential: auth.CredentialCookie, Token: tok, Client: auth.Client{Origin: "https://evil.example"}}
		if err := strict.SignOut(strict.WithRequest(context.Background(), req)); !errors.Is(err, auth.ErrOriginNotTrusted) {
			t.Fatalf("a cross-site sign-out = %v, want ErrOriginNotTrusted", err)
		}
		if err := open.SignOut(open.WithRequest(context.Background(), req)); err != nil {
			t.Fatalf("a cross-site sign-out with the check off = %v", err)
		}
	})
}

// SetFields writes every column type and null on every engine, refuses a
// bad field without writing anything, and an empty set writes nothing.
func TestSetFields_EveryType(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		plan := sqlb.Col[*string](auth.TableUser, "r20_plan")
		seats := sqlb.Col[*int64](auth.TableUser, "r20_seats")
		beta := sqlb.Col[bool](auth.TableUser, "r20_beta")
		ends := sqlb.Col[*time.Time](auth.TableUser, "r20_ends")
		a := coreAuth(t, e, nil, auth.WithUserColumns(
			auth.ColumnExtension{Name: "r20_plan", Type: auth.ColumnText, Nullable: true},
			auth.ColumnExtension{Name: "r20_seats", Type: auth.ColumnInt, Nullable: true},
			auth.ColumnExtension{Name: "r20_beta", Type: auth.ColumnBool, Default: "false"},
			auth.ColumnExtension{Name: "r20_ends", Type: auth.ColumnTimestamp, Nullable: true},
		), auth.WithSignUpFields("r20_plan", "r20_seats", "r20_beta", "r20_ends"))
		ctx := context.Background()
		u := must[auth.User](t)(a.CreateUser(ctx, auth.NewUser{Name: "Fields"}))
		read := func() (p *string, s *int64, b bool, en *time.Time) {
			t.Helper()
			if err := a.LoadUserColumns(ctx, u.ID, sqlb.Bind(plan, &p), sqlb.Bind(seats, &s), sqlb.Bind(beta, &b), sqlb.Bind(ends, &en)); err != nil {
				t.Fatal(err)
			}
			return
		}
		when := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
		err := a.SetFields(ctx, u.ID, auth.Fields{"r20_plan": json.RawMessage(`"pro"`), "r20_seats": json.RawMessage(`7`), "r20_beta": json.RawMessage(`true`), "r20_ends": json.RawMessage(`"2026-11-01T00:00:00Z"`)})
		if err != nil {
			t.Fatal(err)
		}
		if p, s, b, en := read(); p == nil || *p != "pro" || s == nil || *s != 7 || !b || en == nil || !en.Equal(when) {
			t.Fatalf("read back %v %v %v %v", p, s, b, en)
		}
		if err := a.SetFields(ctx, u.ID, auth.Fields{"r20_plan": json.RawMessage(`null`), "r20_seats": json.RawMessage(`"x"`)}); !errors.Is(err, auth.ErrFieldInvalid) {
			t.Fatalf("a bad field = %v", err)
		}
		if p, _, _, _ := read(); p == nil {
			t.Fatal("a refused SetFields wrote its good field")
		}
		must0(t, a.SetFields(ctx, u.ID, auth.Fields{"r20_plan": json.RawMessage(`null`)}))
		must0(t, a.SetFields(ctx, u.ID, nil))
		if p, s, _, _ := read(); p != nil || s == nil {
			t.Fatalf("null and empty: plan %v seats %v", p, s)
		}
	})
}

// IssueCodeWith: a generated code is the one checked; Reuse returns the same
// code and extends it, stops at the attempt budget, and starts over after
// the secret changes.
func TestIssueCodeWith(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		secret := []byte(strings.Repeat("s", auth.MinSecretSize))
		a := coreAuth(t, e, nil, auth.WithSecret(secret))
		ctx := context.Background()
		gen := must[string](t)(a.IssueCodeWith(ctx, corePurpose, "gen", time.Minute, auth.CodeOptions{Generate: func(context.Context) (string, error) { return "424242", nil }}))
		if gen != "424242" || a.CheckCode(ctx, corePurpose, "gen", "424242", 0) != nil {
			t.Fatalf("generated code %q not the one checked", gen)
		}

		reuse := auth.CodeOptions{Reuse: true, MaxAttempts: 2}
		first := must[string](t)(a.IssueCodeWith(ctx, corePurpose, "re", 2*time.Minute, reuse))
		if len(first) != auth.DefaultCodeLength {
			t.Fatalf("reusable code %q", first)
		}
		e.clock.Advance(time.Minute + 30*time.Second)
		if again := must[string](t)(a.IssueCodeWith(ctx, corePurpose, "re", 2*time.Minute, reuse)); again != first {
			t.Fatalf("reuse gave %s then %s", first, again)
		}
		e.clock.Advance(time.Minute) // past the first expiry, inside the extended one
		if err := a.PeekCode(ctx, corePurpose, "re", first, 2); err != nil {
			t.Fatalf("extended code: %v", err)
		}
		for range 2 {
			_ = a.CheckCode(ctx, corePurpose, "re", "000000x", 2)
		}
		if fresh := must[string](t)(a.IssueCodeWith(ctx, corePurpose, "re", 2*time.Minute, reuse)); fresh == first {
			t.Fatal("a code with no attempts left was reused")
		}

		// Rotation: under a new secret the open code no longer recomputes, so
		// a resend replaces it rather than mailing a code that fails.
		open := must[string](t)(a.IssueCodeWith(ctx, corePurpose, "rot", time.Hour, reuse))
		b := coreAuth(t, e, nil, auth.WithSecret([]byte(strings.Repeat("n", auth.MinSecretSize)), secret))
		next := must[string](t)(b.IssueCodeWith(ctx, corePurpose, "rot", time.Hour, reuse))
		if err := b.CheckCode(ctx, corePurpose, "rot", next, 0); err != nil {
			t.Fatalf("code reissued after rotation (was %s, now %s) does not check: %v", open, next, err)
		}
	})
}

// IssueVerificationToken stores the caller's token, spendable once.
func TestIssueVerificationToken(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a := coreAuth(t, e, nil)
		ctx := context.Background()
		tok := auth.Token("r20-caller-made-token-" + e.engine)
		must0(t, a.IssueVerificationToken(ctx, corePurpose, "who", tok, time.Hour, "m"))
		if v, err := a.ConsumeVerification(ctx, corePurpose, tok); err != nil || v.Identifier != "who" || v.Meta != "m" {
			t.Fatalf("consume = %+v %v", v, err)
		}
		if _, err := a.ConsumeVerification(ctx, corePurpose, tok); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("second consume = %v", err)
		}
	})
}

// A generated code under Reuse is stored sealed and mailed again; a code
// issued without Reuse keeps no sealed copy; an older secret still opens a
// sealed code, and a secret no longer listed means a fresh code.
func TestIssueCodeWith_SealedGeneratedCodes(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		oldSecret := []byte(strings.Repeat("o", auth.MinSecretSize))
		a := coreAuth(t, e, nil, auth.WithSecret(oldSecret))
		ctx := context.Background()
		n := 0
		gen := func(context.Context) (string, error) { n++; return fmt.Sprintf("G%07d-%s", n, e.engine), nil }
		sealedOf := func(subject string) *string {
			t.Helper()
			var v *string
			q := a.Select().Columns(sqlb.Bind(sqlb.Col[*string](auth.TableCode, "code_sealed"), &v)).From(auth.TableCode).
				Where(sqlb.Eq(sqlb.Col[string](auth.TableCode, "subject"), subject))
			if err := a.One(ctx, q); err != nil {
				t.Fatal(err)
			}
			return v
		}
		reuse := auth.CodeOptions{Reuse: true, Generate: gen}

		first := must[string](t)(a.IssueCodeWith(ctx, corePurpose, "sg", time.Minute, reuse))
		if s := sealedOf("sg"); s == nil || strings.Contains(*s, first) {
			t.Fatalf("sealed copy %v of %q: missing or readable", s, first)
		}
		if again := must[string](t)(a.IssueCodeWith(ctx, corePurpose, "sg", time.Minute, reuse)); again != first {
			t.Fatalf("reuse gave %s then %s", first, again)
		}
		if err := a.CheckCode(ctx, corePurpose, "sg", first, 0); err != nil {
			t.Fatalf("the reused generated code does not check: %v", err)
		}

		plain := must[string](t)(a.IssueCodeWith(ctx, corePurpose, "plain", time.Minute, auth.CodeOptions{Generate: gen}))
		if s := sealedOf("plain"); s != nil {
			t.Fatalf("a code issued without Reuse kept a sealed copy for %s", plain)
		}

		// Rotation: the old secret is still listed, so the sealed code opens.
		open := must[string](t)(a.IssueCodeWith(ctx, corePurpose, "rot", time.Hour, reuse))
		b := coreAuth(t, e, nil, auth.WithSecret([]byte(strings.Repeat("n", auth.MinSecretSize)), oldSecret))
		if again := must[string](t)(b.IssueCodeWith(ctx, corePurpose, "rot", time.Hour, reuse)); again != open {
			t.Fatalf("after rotation reuse gave %s, want %s", again, open)
		}
		// The old secret dropped: the copy no longer opens, a fresh code.
		c := coreAuth(t, e, nil, auth.WithSecret([]byte(strings.Repeat("m", auth.MinSecretSize))))
		fresh := must[string](t)(c.IssueCodeWith(ctx, corePurpose, "rot", time.Hour, reuse))
		if fresh == open || c.CheckCode(ctx, corePurpose, "rot", fresh, 0) != nil {
			t.Fatalf("with the secret gone: %s (was %s)", fresh, open)
		}
	})
}
