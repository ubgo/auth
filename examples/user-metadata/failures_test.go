package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/metadata"
)

// TestMetadata_GoAPIRefusals: the Go API refuses an unknown kind, a document
// or patch that is not an object, and an unknown user, and writes nothing;
// Set with no document stores {}.
func TestMetadata_GoAPIRefusals(t *testing.T) {
	a, md, ad := newTestApp(t)
	alice := newBrowser(t, newHandler(a, md, ad))
	id := signUp(t, alice, aliceEmail, "Alice")
	ctx := context.Background()

	if err := md.Set(ctx, id, "secret", json.RawMessage(`{}`)); !errors.Is(err, metadata.ErrUnknownKind) {
		t.Fatalf("Set unknown kind = %v", err)
	}
	if _, err := md.Merge(ctx, id, "secret", json.RawMessage(`{}`)); !errors.Is(err, metadata.ErrUnknownKind) {
		t.Fatalf("Merge unknown kind = %v", err)
	}
	if err := md.Set(ctx, id, metadata.Public, json.RawMessage(`[1]`)); !errors.Is(err, metadata.ErrInvalid) {
		t.Fatalf("Set array = %v", err)
	}
	if _, err := md.Merge(ctx, id, metadata.Private, json.RawMessage(`"x"`)); !errors.Is(err, metadata.ErrInvalid) {
		t.Fatalf("Merge string = %v", err)
	}
	if _, err := md.Merge(ctx, "usr_nobody", metadata.Public, json.RawMessage(`{"a":1}`)); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("Merge unknown user = %v", err)
	}
	if _, err := md.PublicOf(ctx, "usr_nobody"); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("PublicOf unknown user = %v", err)
	}
	if err := md.Set(ctx, id, metadata.Public, json.RawMessage(`{"plan":"pro","n":1}`)); err != nil {
		t.Fatal(err)
	}
	if pub, err := md.PublicOf(ctx, id); err != nil || string(pub) != `{"n":1,"plan":"pro"}` {
		t.Fatalf("PublicOf = %s, %v", pub, err)
	}
	if err := md.Set(ctx, id, metadata.Public, nil); err != nil {
		t.Fatal(err)
	}
	if pub, err := md.PublicOf(ctx, id); err != nil || string(pub) != "{}" {
		t.Fatalf("after Set(nil) = %s, %v", pub, err)
	}
}

// TestMetadata_UnsafeCheckRefuses: WithUnsafeCheck sees the merged document
// and its error is the answer; nothing is stored.
func TestMetadata_UnsafeCheckRefuses(t *testing.T) {
	errKey := auth.NewError("app.metadata_key", http.StatusBadRequest, "That key is not allowed.")
	check := metadata.WithUnsafeCheck(func(_ context.Context, _ string, doc json.RawMessage) error {
		var m map[string]any
		if err := json.Unmarshal(doc, &m); err != nil {
			return err
		}
		if _, ok := m["role"]; ok {
			return errKey
		}
		return nil
	})
	a, md, ad := newTestApp(t, check)
	alice := newBrowser(t, newHandler(a, md, ad))
	signUp(t, alice, aliceEmail, "Alice")
	post[metadata.UserMetadata](t, alice, "/auth/metadata/update", rawBody(`{"unsafe":{"theme":"dark"}}`), http.StatusOK)
	if e := postErr(t, alice, "/auth/metadata/update", rawBody(`{"unsafe":{"role":"admin"}}`), http.StatusBadRequest); e.Code != errKey.Code {
		t.Fatalf("refused key: %+v", e)
	}
	if m := get[metadata.UserMetadata](t, alice, "/auth/metadata/get", http.StatusOK); string(m.Unsafe) != `{"theme":"dark"}` {
		t.Fatalf("after refusal = %s", m.Unsafe)
	}
}

// TestMetadata_AdminEdges: an admin patching an unknown user is 404, and an
// authorizer that fails refuses the call (fail closed) rather than allowing.
func TestMetadata_AdminEdges(t *testing.T) {
	a, md, ad := newTestApp(t)
	bob := newBrowser(t, newHandler(a, md, ad))
	bobID := signUp(t, bob, bobEmail, "Bob")
	if err := ad.SetRoleFor(context.Background(), bobID, admin.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if e := postErr(t, bob, "/auth/metadata/admin-update", metadata.AdminUpdateRequest{UserID: "usr_nobody", Public: json.RawMessage(`{"a":1}`)}, http.StatusNotFound); e.Code != auth.ErrUserNotFound.Code {
		t.Fatalf("admin-update unknown user: %+v", e)
	}
	if e := postErr(t, bob, "/auth/metadata/admin-update", metadata.AdminUpdateRequest{UserID: bobID, Public: json.RawMessage(`{"a":1}`), Private: json.RawMessage(`[1]`)}, http.StatusBadRequest); e.Code != metadata.ErrInvalid.Code {
		t.Fatalf("admin-update with a non-object patch: %+v", e)
	}
	if all, err := md.Get(context.Background(), bobID); err != nil || string(all.Public) != "{}" {
		t.Fatalf("a refused admin-update wrote public: %s, %v", all.Public, err)
	}

	down := metadata.WithAdmin(metadata.AuthorizerFunc(func(context.Context, metadata.AccessRequest) (bool, error) {
		return true, errors.New("policy engine down")
	}))
	a2, md2, ad2 := newTestApp(t, down)
	carol := newBrowser(t, newHandler(a2, md2, ad2))
	carolID := signUp(t, carol, aliceEmail, "Carol")
	getRaw(t, carol, "/auth/metadata/admin-get?userId="+carolID, http.StatusInternalServerError)
}

// TestMetadata_StorageFailures drives each database failure of the read and
// write paths with SQLite triggers and a damaged table, and checks it is
// reported as an error rather than read as empty documents or swallowed.
func TestMetadata_StorageFailures(t *testing.T) {
	ctx := context.Background()
	patch := json.RawMessage(`{"a":1}`)

	t.Run("insert fails", func(t *testing.T) {
		db, md, id := newRawApp(t, nil)
		mustExec(t, db, `CREATE TRIGGER no_insert BEFORE INSERT ON auth_user_metadata BEGIN SELECT RAISE(ABORT, 'insert refused'); END`)
		if _, err := md.Merge(ctx, id, metadata.Public, patch); err == nil {
			t.Fatal("Merge succeeded with inserts refused")
		}
	})
	t.Run("first-write race retries once", func(t *testing.T) {
		// The trigger inserts the user's row ahead of the plugin's own
		// insert, which then is a unique violation: the race of two first
		// writes. The retry meets the trigger again, so the violation is
		// what comes back, after exactly one retry.
		db, md, id := newRawApp(t, nil)
		mustExec(t, db, `CREATE TRIGGER race BEFORE INSERT ON auth_user_metadata BEGIN
			INSERT INTO auth_user_metadata (user_id, public_metadata, private_metadata, unsafe_metadata, updated_at)
			VALUES (NEW.user_id, '{}', '{}', '{}', NEW.updated_at); END`)
		if _, err := md.Merge(ctx, id, metadata.Public, patch); !auth.IsUniqueViolation(err) {
			t.Fatalf("Merge = %v, want a unique violation", err)
		}
	})
	t.Run("write fails", func(t *testing.T) {
		db, md, id := newRawApp(t, nil)
		if _, err := md.Merge(ctx, id, metadata.Public, patch); err != nil {
			t.Fatal(err)
		}
		mustExec(t, db, `CREATE TRIGGER no_write BEFORE UPDATE OF public_metadata ON auth_user_metadata BEGIN SELECT RAISE(ABORT, 'write refused'); END`)
		if _, err := md.Merge(ctx, id, metadata.Public, json.RawMessage(`{"b":2}`)); err == nil {
			t.Fatal("Merge succeeded with document writes refused")
		}
	})
	t.Run("table missing", func(t *testing.T) {
		db, md, id := newRawApp(t, nil)
		mustExec(t, db, `DROP TABLE auth_user_metadata`)
		if _, err := md.Merge(ctx, id, metadata.Public, patch); err == nil {
			t.Fatal("Merge succeeded with no table")
		}
		if _, err := md.Get(ctx, id); err == nil {
			t.Fatal("Get read a missing table as empty documents")
		}
	})
	t.Run("unreadable row", func(t *testing.T) {
		// A table created before the migration, without NOT NULL, holds a
		// NULL document: the read fails to scan it, for Get, for the user's
		// own route and inside a write.
		var h http.Handler
		db, md, id := newRawApp(t, func(db *sql.DB) {
			mustExec(t, db, `CREATE TABLE auth_user_metadata (user_id TEXT NOT NULL PRIMARY KEY, public_metadata TEXT, private_metadata TEXT, unsafe_metadata TEXT, updated_at TIMESTAMP NOT NULL)`)
		}, &h)
		mustExec(t, db, `INSERT INTO auth_user_metadata VALUES (?, NULL, '{}', '{}', CURRENT_TIMESTAMP)`, id)
		if _, err := md.Get(ctx, id); err == nil {
			t.Fatal("Get scanned a NULL document")
		}
		if _, err := md.Merge(ctx, id, metadata.Unsafe, patch); err == nil {
			t.Fatal("Merge read a NULL document")
		}
		b := newBrowser(t, h)
		post[signUpAnswer](t, b, "/auth/password/sign-in", map[string]string{"identifier": aliceEmail, "password": testPassword}, http.StatusOK)
		getRaw(t, b, "/auth/metadata/get", http.StatusInternalServerError)
	})
}

// newRawApp builds the app on a fresh SQLite file, runs before (when set) on
// the database ahead of the migrations, signs Alice up and returns the
// database, the plugin and her id. When handler is set it receives the app's
// handler.
func newRawApp(t *testing.T, before func(*sql.DB), handler ...*http.Handler) (*sql.DB, *metadata.Plugin, string) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if before != nil {
		before(db)
	}
	a, md, ad, err := newAuth(db, discardMailer{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := newHandler(a, md, ad)
	for _, dst := range handler {
		*dst = h
	}
	return db, md, signUp(t, newBrowser(t, h), aliceEmail, "Alice")
}

// mustExec runs one statement on the test database.
func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}
