package main

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ubgo/auth"
)

func newApp(t *testing.T) (*auth.Auth, *sql.DB) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	a, err := newAuth(db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if err := migrate(t.Context(), a, openEnt(db)); err != nil {
		t.Fatal(err)
	}
	return a, db
}

// TestEntAlongside_CommitsTogether: the user and the ent note both exist, and
// the sqlb read joins them.
func TestEntAlongside_CommitsTogether(t *testing.T) {
	a, db := newApp(t)
	u, err := createUserWithNote(t.Context(), a, "Alice", "hello", false)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := listUsersWithNotes(t.Context(), a, openEnt(db))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ID != u.ID || rows[0].Name != "Alice" {
		t.Fatalf("rows = %+v", rows)
	}
	if len(rows[0].Notes) != 1 || rows[0].Notes[0].Body != "hello" || rows[0].Notes[0].UserID != u.ID {
		t.Fatalf("notes = %+v", rows[0].Notes)
	}
}

// TestEntAlongside_RollsBackTogether: a failure after both writes leaves
// neither the library's user nor ent's note, which proves ent ran on the
// library's transaction and not on its own connection.
func TestEntAlongside_RollsBackTogether(t *testing.T) {
	a, db := newApp(t)
	if _, err := createUserWithNote(t.Context(), a, "Bob", "gone", true); !errors.Is(err, errRollback) {
		t.Fatalf("err = %v, want errRollback", err)
	}
	rows, err := listUsersWithNotes(t.Context(), a, openEnt(db))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("user survived the rollback: %+v", rows)
	}
	n, err := openEnt(db).Note.Query().Count(t.Context())
	if err != nil || n != 0 {
		t.Fatalf("note count = %d, err = %v; want 0", n, err)
	}
}
