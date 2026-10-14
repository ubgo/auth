package integration

import (
	"context"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/phone"
	"github.com/ubgo/auth/plugin/username"
	"github.com/ubgo/sqlb"
)

// BenchmarkComposite_OneStatementVsAccessors measures what ADR-0001's
// composite user buys: the same user (core and email columns, the primary
// phone, the handle) read by one LoadUser with two LEFT joins, against the
// three statements an app would run with the per-plugin accessors
// (LoadUserColumns, phone.Of, username.Of). It runs on every engine the
// environment reaches, as the integration suite does:
//
//	go test -mod=mod -run '^$' -bench Composite ./integration
//	task test:engines sets the DSNs for Postgres and MySQL.
func BenchmarkComposite_OneStatementVsAccessors(b *testing.B) {
	for _, eng := range engines(b) {
		b.Run(eng.name, func(b *testing.B) {
			db, d := eng.open(b)
			e := newEnv(b, eng.name, db, d)
			a := e.newAuth(b, nil, e.emailPlugin(), e.passwordPlugin(), e.phonePlugin(phone.Login()), username.New(username.Login()))
			ctx := context.Background()
			u, err := a.CreateUser(ctx, auth.NewUser{Name: "Alice"})
			if err != nil {
				b.Fatal(err)
			}
			for _, idn := range []auth.NewIdentity{
				{UserID: u.ID, Kind: email.KindEmail, Raw: alice, Verified: true, Primary: true},
				{UserID: u.ID, Kind: phone.KindPhone, Raw: "+15550100100", Verified: true, Primary: true},
				{UserID: u.ID, Kind: username.KindUsername, Raw: "Alice", Verified: true, Primary: true},
			} {
				if _, err := a.CreateIdentity(ctx, idn); err != nil {
					b.Fatal(err)
				}
			}
			// check fails the run when a read came back incomplete, so neither
			// side is timed doing less work than the other.
			check := func(got appUser) {
				if got.ID != u.ID || got.PrimaryEmail == nil || got.Phone.Number == "" || got.Handle.Handle == "" {
					b.Fatalf("incomplete read: %+v", got)
				}
			}

			b.Run("composite", func(b *testing.B) {
				for b.Loop() {
					var got appUser
					if err := a.LoadUser(ctx, u.ID, &got); err != nil {
						b.Fatal(err)
					}
					check(got)
				}
			})
			b.Run("accessors", func(b *testing.B) {
				for b.Loop() {
					var got appUser
					if err := a.LoadUserColumns(ctx, u.ID, sqlb.Bindings(auth.UserBindings(&got.User), email.Bindings(&got.EmailColumns))...); err != nil {
						b.Fatal(err)
					}
					pq, err := phone.Of(a, u.ID, &got.Phone)
					if err != nil {
						b.Fatal(err)
					}
					if err := sqlb.One(ctx, db, pq); err != nil {
						b.Fatal(err)
					}
					uq, err := username.Of(a, u.ID, &got.Handle)
					if err != nil {
						b.Fatal(err)
					}
					if err := sqlb.One(ctx, db, uq); err != nil {
						b.Fatal(err)
					}
					check(got)
				}
			})
		})
	}
}
