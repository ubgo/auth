package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth/plugin/apikey"
)

// newTestAuth is newAuth on a fresh in-memory database, migrated.
func newTestAuth(t *testing.T) (*apikey.Plugin, func(name string) (string, string, string)) {
	t.Helper()
	ctx := context.Background()
	db, err := sql.Open("sqlite", memoryDSN)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	a, ak, err := newAuth(db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close(); db.Close() })
	if _, err := a.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return ak, func(name string) (string, string, string) {
		botID, keyID, secret, err := provisionBot(ctx, a, ak, name)
		if err != nil {
			t.Fatal(err)
		}
		return botID, keyID, secret
	}
}

// The program runs end to end: the key verifies for the bot, is listed, and
// stops verifying once revoked.
//
//ds:def id=testbotkeys-run-8qn3wk5v owner=@khanakia stability=stable
func TestBotKeys_Run(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"nightly report" scopes=[reports:write]`, "before revoke: valid=true", "after revoke: valid=false"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output lacks %q:\n%s", want, out.String())
		}
	}
}

// Keys stay with their owner: one bot's listing has only its own key, and
// revoking another bot's key by id is ErrNotFound and leaves it working.
//
//ds:def id=testbotkeys-ownership-4wx9mq2n owner=@khanakia stability=stable
func TestBotKeys_Ownership(t *testing.T) {
	ctx := context.Background()
	ak, provision := newTestAuth(t)
	aID, aKey, _ := provision("bot a")
	_, bKey, bSecret := provision("bot b")
	keys, err := botKeys(ctx, ak, aID)
	if err != nil || len(keys) != 1 || keys[0].ID != aKey {
		t.Fatalf("bot a's keys = %+v, %v", keys, err)
	}
	if err := retireBot(ctx, ak, aID, bKey); !errors.Is(err, apikey.ErrNotFound) {
		t.Fatalf("revoking another bot's key: err = %v, want ErrNotFound", err)
	}
	v, err := ak.Verify(ctx, bSecret, scopeReportsWrite)
	if err != nil || !v.Valid {
		t.Fatalf("bot b's key stopped working: %+v %v", v, err)
	}
}

// The key carries only the scope it was made with: a check for any other
// scope fails.
//
//ds:def id=testbotkeys-scopeonly-6kn2xw8q owner=@khanakia stability=stable
func TestBotKeys_ScopeOnly(t *testing.T) {
	ak, provision := newTestAuth(t)
	_, _, secret := provision("bot")
	v, err := ak.Verify(context.Background(), secret, "reports:delete")
	if err != nil {
		t.Fatal(err)
	}
	if v.Valid {
		t.Fatal("a key verified for a scope it does not carry")
	}
}
