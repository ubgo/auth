// Command ent-alongside uses ent for the app's own tables beside the library:
// ent opens on the same *sql.DB, joins the library's transaction so a user and
// the app's row commit or roll back together, and the app reads auth_user with
// sqlb handles next to ent queries.
//
//	go run ./ent-alongside
//
// There is no ent schema for an auth table and no ent migration for one: the
// library creates and migrates its own tables.
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/url"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/examples/ent-alongside/ent"
	"github.com/ubgo/auth/examples/ent-alongside/ent/note"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// dbFile is the SQLite database, created next to where you run the program.
	dbFile = "ent-alongside.db"
	// sqlitePragmas: WAL so readers do not block the writer, and a busy timeout
	// instead of an immediate "database is locked", and foreign keys, which
	// ent's migrator refuses to run without.
	sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	// entDialect is ent's name for SQLite. It is not the database/sql driver
	// name ("sqlite"): ent picks its SQL flavour from this string.
	entDialect = dialect.SQLite
)

// errRollback is the failure the demo and the test use to prove the library's
// user is rolled back together with the app's ent row.
var errRollback = errors.New("ent-alongside: forced failure after both writes")

// newAuth wires the library on db. The test builds the app with this same
// function. Mail is dropped: this recipe sends none.
func newAuth(db *sql.DB) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL("http://localhost:8081"),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(discardMailer{})), password.New()),
	)
}

// discardMailer drops every message. Replace it with SMTP or an email API.
type discardMailer struct{}

// Send drops the message.
func (discardMailer) Send(context.Context, email.Mail) error { return nil }

func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}

func main() {
	ctx := context.Background()
	db, err := sql.Open("sqlite", sqliteDSN(dbFile))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	a, err := newAuth(db)
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	client := openEnt(db)
	if err := migrate(ctx, a, client); err != nil {
		log.Fatal(err)
	}
	if _, err := createUserWithNote(ctx, a, "Alice", "first note", false); err != nil {
		log.Fatal(err)
	}
	rows, err := listUsersWithNotes(ctx, a, client)
	if err != nil {
		log.Fatal(err)
	}
	for _, r := range rows {
		fmt.Printf("%s %s notes=%d\n", r.ID, r.Name, len(r.Notes))
	}
}

// openEnt opens ent on the database the library uses. ent and the library then
// share one connection pool, so there is one set of limits and one place the
// database is closed; closing ent's client is not needed, db.Close does it.
//
//ds:def id=entalong-open-4kd2m7qx owner=@khanakia stability=stable
func openEnt(db *sql.DB) *ent.Client {
	return ent.NewClient(ent.Driver(entsql.OpenDB(entDialect, db)))
}

// migrate creates the library's tables with its own migrator and the app's
// tables with ent's. The two never touch each other's tables: ent's schema
// holds no auth table, so its migration has nothing to alter in them.
func migrate(ctx context.Context, a *auth.Auth, client *ent.Client) error {
	if _, err := a.Migrate(ctx); err != nil {
		return err
	}
	return client.Schema.Create(ctx)
}

// txClient returns an ent client whose every statement runs on tx. The driver
// is built with entsql.Conn on the *sql.Tx, so this is ent's builder on the
// library's transaction, not a second transaction.
//
// Do not call txClient(...).Tx(): that would begin a transaction inside a
// transaction. Write through the returned client directly.
//
//ds:def id=entalong-txclient-9wr3hcvb owner=@khanakia stability=stable
func txClient(tx *sql.Tx) *ent.Client {
	return ent.NewClient(ent.Driver(entsql.NewDriver(entDialect, entsql.Conn{ExecQuerier: tx})))
}

// createUserWithNote creates a user through the library and a note through ent
// in one transaction. When fail is set it returns an error after both writes,
// and neither row exists afterwards.
//
//ds:def id=entalong-create-m5tn8zpe owner=@khanakia stability=stable
func createUserWithNote(ctx context.Context, a *auth.Auth, name, body string, fail bool) (auth.User, error) {
	var u auth.User
	err := a.Tx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		if u, err = a.CreateUser(ctx, auth.NewUser{Name: name}); err != nil {
			return err
		}
		if _, err = txClient(tx).Note.Create().SetUserID(u.ID).SetBody(body).Save(ctx); err != nil {
			return err
		}
		if fail {
			return errRollback
		}
		return nil
	})
	return u, err
}

// UserRow is one auth_user row with the app's notes for it.
type UserRow struct {
	ID    string
	Name  string
	Notes []*ent.Note
}

// listUsersWithNotes reads auth_user with the library's typed column handles
// and the app's notes with ent. The columns come from handles (auth.UserID),
// not SQL text, so a renamed column keeps working and a removed one fails to
// compile at upgrade.
//
//ds:def id=entalong-list-c2vj6ahs owner=@khanakia stability=stable
func listUsersWithNotes(ctx context.Context, a *auth.Auth, client *ent.Client) ([]UserRow, error) {
	var row UserRow
	q, err := a.Select().
		Columns(sqlb.Bind(auth.UserID, &row.ID), sqlb.Bind(auth.UserName, &row.Name)).
		From(auth.TableUser).
		Order(sqlb.OrderBy(auth.UserCreatedAt, sqlb.SortAsc), sqlb.OrderBy(auth.UserID, sqlb.SortAsc)).
		Build()
	if err != nil {
		return nil, err
	}
	var out []UserRow
	if err := sqlb.Each(ctx, a.DB(), q, func() error {
		out = append(out, row) // the targets are reused for every row
		return nil
	}); err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Notes, err = client.Note.Query().Where(note.UserID(out[i].ID)).All(ctx)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
