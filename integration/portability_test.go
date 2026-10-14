package integration

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/sqlb"
)

// TestPortability_UnicodeFoldsInGoAndComparesExactly: the normalizer folds
// "É" to "é" in Go, so every engine stores and compares the same bytes. An
// accent-insensitive collation would also match "emile", merging two people;
// MySQL's default collation does exactly that, which is why the core's MySQL
// tables are utf8mb4_bin.
func TestPortability_UnicodeFoldsInGoAndComparesExactly(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		ctx := context.Background()
		u := must[auth.User](t)(a.CreateUser(ctx, auth.NewUser{}))
		must[auth.Identity](t)(a.CreateIdentity(ctx, auth.NewIdentity{UserID: u.ID, Kind: email.KindEmail, Raw: "ÉMILE@Example.com", Verified: true}))

		got, err := a.FindIdentity(ctx, email.KindEmail, "émile@EXAMPLE.COM", true)
		if err != nil || got.UserID != u.ID || got.Value != "émile@example.com" {
			t.Fatalf("folded lookup = %+v, %v", got, err)
		}
		if _, err := a.FindIdentity(ctx, email.KindEmail, "emile@example.com", true); !errors.Is(err, auth.ErrIdentityNotFound) {
			t.Fatalf("an address without the accent matched: %v; the comparison is not byte-exact", err)
		}
		// And the two can be separate verified identities.
		v := must[auth.User](t)(a.CreateUser(ctx, auth.NewUser{}))
		if _, err := a.CreateIdentity(ctx, auth.NewIdentity{UserID: v.ID, Kind: email.KindEmail, Raw: "emile@example.com", Verified: true}); err != nil {
			t.Fatalf("a different address was refused as a duplicate: %v", err)
		}
		if _, err := a.CreateIdentity(ctx, auth.NewIdentity{UserID: v.ID, Kind: email.KindEmail, Raw: "Émile@example.com", Verified: true}); !errors.Is(err, auth.ErrIdentityTaken) {
			t.Fatalf("the same address verified twice: %v, want ErrIdentityTaken", err)
		}
	})
}

// TestPortability_SQLiteSearchesAnIndexByValue asks SQLite for its plan. The
// exact comparison must be an index search on the value — through the
// partial unique index or the (kind, value) lookup index, whichever the
// planner prefers. A lower() in SQL would reduce it to "kind=?" alone: every
// row of the kind, read one by one.
func TestPortability_SQLiteSearchesAnIndexByValue(t *testing.T) {
	db, d := openSQLite(t)
	e := newEnv(t, auth.EngineSQLite, db, d)
	a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin())
	var idn auth.Identity
	q, err := a.Select().Columns(auth.IdentityBindings(&idn)...).From(auth.TableIdentity).
		Where(sqlb.Eq(auth.IdentityKind, email.KindEmail), sqlb.Eq(auth.IdentityValue, "a@example.com"), auth.VerifiedIdentity()).
		Limit(1).Build()
	if err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query("EXPLAIN QUERY PLAN "+q.SQL, q.Args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	joined := strings.Join(plan, " | ")
	byValue := strings.Contains(joined, "auth_identity_email_verified_uniq (value=?)") ||
		strings.Contains(joined, "auth_identity_lookup_idx (kind=? AND value=?)")
	if !strings.HasPrefix(joined, "SEARCH") || !byValue {
		t.Fatalf("plan = %q, want an index search on the value", joined)
	}
}
