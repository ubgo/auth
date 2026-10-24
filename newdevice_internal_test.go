package auth

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/sqlb"
)

// TestDecodeCoreMessageData: the outbox restores the core's own message data
// (the unknown-device message) and leaves every other purpose to the
// plugins; data that is not JSON is an undecodable message, not a panic.
func TestDecodeCoreMessageData(t *testing.T) {
	want := UnknownDeviceData{UserAgent: "ua", IP: "203.0.113.7", SessionID: "ses_1", Method: "password"}
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeCoreMessageData(PurposeUnknownDevice, raw)
	if d, ok := got.(UnknownDeviceData); err != nil || !ok || d.SessionID != want.SessionID || d.UserAgent != "ua" {
		t.Fatalf("decoded = %#v, %v", got, err)
	}
	if got, err := decodeCoreMessageData(PurposeVerify, raw); got != nil || err != nil {
		t.Fatalf("another purpose = %#v, %v; want (nil, nil) for the plugins to decode", got, err)
	}
	a := &Auth{}
	if _, err := a.decodeMessageData(PurposeUnknownDevice, json.RawMessage("{")); !errors.Is(err, ErrMessageDataUndecodable) {
		t.Fatalf("bad JSON = %v, want ErrMessageDataUndecodable", err)
	}
	if v, err := a.decodeMessageData(PurposeUnknownDevice, raw); err != nil || v == nil {
		t.Fatalf("good JSON through decodeMessageData = %#v, %v", v, err)
	}
}

// TestUnknownDeviceText: the English body names the device (or says it is an
// unnamed client), shows the address only when one is kept, and always says
// what to do if it was not the user.
func TestUnknownDeviceText(t *testing.T) {
	at := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	full := unknownDeviceText(UnknownDeviceData{UserAgent: "Firefox/131", IP: "203.0.113.7", At: at})
	for _, want := range []string{"Device: Firefox/131", "IP address: 203.0.113.7", "Fri, 09 Oct 2026 12:00:00 UTC", "change your password"} {
		if !strings.Contains(full, want) {
			t.Errorf("text lacks %q:\n%s", want, full)
		}
	}
	bare := unknownDeviceText(UnknownDeviceData{At: at})
	if !strings.Contains(bare, "an unnamed client") || strings.Contains(bare, "IP address") {
		t.Errorf("a sign-in with no user agent and no address:\n%s", bare)
	}
}

// failingDriver opens connections whose every statement fails, a database
// that is reachable but broken.
type failingDriver struct{}

func (failingDriver) Open(string) (driver.Conn, error) { return failingConn{}, nil }

type failingConn struct{}

var errBroken = errors.New("broken database")

func (failingConn) Prepare(string) (driver.Stmt, error) { return nil, errBroken }
func (failingConn) Close() error                        { return nil }
func (failingConn) Begin() (driver.Tx, error)           { return nil, errBroken }

func init() { sql.Register("auth-failing", failingDriver{}) }

// TestSessionDevices_StoreFailuresAreErrorsNotAnAnswer: when either list of
// sessions cannot be read, the default rule reports the error instead of
// guessing "known" or "unknown"; the notification then sends nothing and
// logs, rather than alarming users while a store is down.
func TestSessionDevices_StoreFailuresAreErrorsNotAnAnswer(t *testing.T) {
	ctx := context.Background()
	// Stateless: only the request's own session is known, so the list fails.
	stateless, err := New(WithPlugins(scriptSignIn{}), WithSecret([]byte(strings.Repeat("s", MinSecretSize))), WithStatelessSessions())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SessionDevices().KnownDevice(ctx, DeviceSignIn{Auth: stateless, UserID: "usr_1"}); !errors.Is(err, ErrSessionsUnavailable) {
		t.Fatalf("stateless = %v, want ErrSessionsUnavailable", err)
	}
	// The live sessions are in memory and fine; the archive is in a broken
	// database.
	db, err := sql.Open("auth-failing", "")
	if err != nil {
		t.Fatal(err)
	}
	broken, err := New(WithPlugins(scriptSignIn{}), WithDB(db, sqlb.SQLiteDialect{}), WithSessionStore(NewMemorySessionStore()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SessionDevices().KnownDevice(ctx, DeviceSignIn{Auth: broken, UserID: "usr_1"}); err == nil || errors.Is(err, ErrNoDatabase) {
		t.Fatalf("a broken archive = %v, want its error", err)
	}
	// With no database at all the archive does not exist, which is not a
	// failure: the live sessions decide.
	memory, err := New(WithPlugins(scriptSignIn{}), WithSessionStore(NewMemorySessionStore()))
	if err != nil {
		t.Fatal(err)
	}
	if known, err := SessionDevices().KnownDevice(ctx, DeviceSignIn{Auth: memory, UserID: "usr_1"}); err != nil || !known {
		t.Fatalf("no sessions and no archive = %v, %v; want known (nothing to compare with)", known, err)
	}
}
