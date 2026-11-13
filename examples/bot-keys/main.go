// Command bot-keys shows an app managing the API keys of a user it names,
// with no session: a parent account owns a bot user, and the app provisions,
// lists and revokes the bot's keys from Go. The HTTP key routes act only on
// the signed-in user's own keys and refuse a request signed with a key, so
// this is the path for keys the app itself looks after.
//
//	go run ./bot-keys
//
// It prints each step and exits; the database is in memory.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/apikey"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

const (
	// memoryDSN is a private in-memory SQLite database; one connection keeps
	// it alive for the whole run.
	memoryDSN = "file::memory:"
	// baseURL is required by auth.New; nothing is served here.
	baseURL = "http://localhost:8081"
	// scopeReportsWrite is the only thing the bot's key may do.
	scopeReportsWrite = "reports:write"
	// botKeyName labels the bot's key in every listing.
	botKeyName = "nightly report"
)

// newAuth wires the API key plugin with the one scope the bot needs, beside
// password sign-in for the people who own bots (auth.New needs a sign-in
// method). email.NoMail stores addresses without a mailer and
// password.WithoutRecovery accepts that nobody can reset by mail, since this
// program sends no mail.
//
//ds:def id=botkeys-newauth-3kq8wn5x owner=@khanakia stability=stable
func newAuth(db *sql.DB) (*auth.Auth, *apikey.Plugin, error) {
	ak := apikey.New(apikey.Scopes(scopeReportsWrite))
	a, err := auth.New(auth.WithDB(db, sqlb.SQLiteDialect{}), auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.NoMail()), password.New(password.WithoutRecovery()), ak))
	return a, ak, err
}

// provisionBot creates a bot user and a key for it with CreateFor. The
// secret is returned once, here, and stored hashed; hand it to the bot's
// configuration and never log it.
//
//ds:def id=botkeys-provisionbot-7wm2xq4k owner=@khanakia stability=stable
func provisionBot(ctx context.Context, a *auth.Auth, ak *apikey.Plugin, name string) (botID, keyID, secret string, err error) {
	bot, err := a.CreateUser(ctx, auth.NewUser{Name: name})
	if err != nil {
		return "", "", "", err
	}
	res, err := ak.CreateFor(ctx, bot.ID, apikey.CreateRequest{Name: botKeyName, Scopes: []string{scopeReportsWrite}}, apikey.Limits{})
	if err != nil {
		return "", "", "", err
	}
	return bot.ID, res.Key.ID, res.Secret, nil
}

// botKeys lists the keys of the user the app names, a page at a time, with
// the same paging the HTTP list route has. Deciding who may see whose keys
// is the app's job before this call.
//
//ds:def id=botkeys-botkeys-5nv9kw2q owner=@khanakia stability=stable
func botKeys(ctx context.Context, ak *apikey.Plugin, botID string) ([]apikey.Key, error) {
	res, err := ak.ListFor(ctx, botID, apikey.ListRequest{})
	return res.Keys, err
}

// retireBot revokes one of the bot's keys. A key id that belongs to another
// user is apikey.ErrNotFound, exactly as on the HTTP route.
//
//ds:def id=botkeys-retirebot-2xq7mn4w owner=@khanakia stability=stable
func retireBot(ctx context.Context, ak *apikey.Plugin, botID, keyID string) error {
	return ak.RevokeFor(ctx, botID, keyID)
}

// run walks the whole life of the bot's key and prints each step to w.
func run(ctx context.Context, w io.Writer) error {
	db, err := sql.Open("sqlite", memoryDSN)
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	a, ak, err := newAuth(db)
	if err != nil {
		return err
	}
	defer a.Close()
	if _, err := a.Migrate(ctx); err != nil {
		return err
	}
	botID, keyID, secret, err := provisionBot(ctx, a, ak, "report bot")
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "provisioned bot %s with key %s\n", botID, keyID)
	keys, err := botKeys(ctx, ak, botID)
	if err != nil {
		return err
	}
	for _, k := range keys {
		fmt.Fprintf(w, "listed %s %q scopes=%v\n", k.ID, k.Name, k.Scopes)
	}
	v, err := ak.Verify(ctx, secret, scopeReportsWrite)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "before revoke: valid=%v user=%s\n", v.Valid, v.UserID)
	if err := retireBot(ctx, ak, botID, keyID); err != nil {
		return err
	}
	v, err = ak.Verify(ctx, secret, scopeReportsWrite)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "after revoke: valid=%v reason=%v\n", v.Valid, v.Reason)
	return nil
}

func main() {
	log.SetFlags(0)
	if err := run(context.Background(), os.Stdout); err != nil {
		log.Fatal(err)
	}
}
