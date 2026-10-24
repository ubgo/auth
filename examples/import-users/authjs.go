package main

import (
	"encoding/json"
	"fmt"
)

// Auth.js (NextAuth) keeps four tables through its database adapters:
// users, accounts, sessions and verification tokens. The import reads the
// first two as JSON arrays (`users.json` and `accounts.json`, dumped with the
// ORM or `psql`'s `json_agg`); sessions are not moved, since every migration
// signs everyone out, and verification tokens are minutes old by design.
// Auth.js stores no passwords: its Credentials provider calls the app's own
// code, so a password table, if any, is the app's and goes through
// password.ImportHash with that table's hashes.

// authjsUser is an Auth.js users row. `emailVerified` is a timestamp or
// null, which is why it is read as a string: anything non-empty means
// verified.
type authjsUser struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Email         string `json:"email"`
	EmailVerified string `json:"emailVerified"`
	Image         string `json:"image"`
}

// authjsAccount is an Auth.js accounts row. The provider name is the Auth.js
// provider id (`google`, `github`), the same names this library's providers
// use by default.
type authjsAccount struct {
	UserID            string `json:"userId"`
	Type              string `json:"type"`
	Provider          string `json:"provider"`
	ProviderAccountID string `json:"providerAccountId"`
}

// authjsOAuthTypes are the account types that are linked providers; an
// `email` (magic link) or `credentials` account is not one.
var authjsOAuthTypes = map[string]bool{"oauth": true, "oidc": true}

// readAuthJS reads the users array and, when given, the accounts array.
//
//ds:def id=import-readauthjs-2p6zm9vt
func readAuthJS(in input) ([]record, error) {
	var users []authjsUser
	if err := json.NewDecoder(in.Main).Decode(&users); err != nil {
		return nil, fmt.Errorf("auth.js users: %w", err)
	}
	accounts := map[string][]account{}
	if in.Identities != nil {
		var accs []authjsAccount
		if err := json.NewDecoder(in.Identities).Decode(&accs); err != nil {
			return nil, fmt.Errorf("auth.js accounts: %w", err)
		}
		for _, a := range accs {
			if !authjsOAuthTypes[a.Type] {
				continue
			}
			accounts[a.UserID] = append(accounts[a.UserID], account{Provider: a.Provider, AccountID: a.ProviderAccountID})
		}
	}
	out := make([]record, 0, len(users))
	for _, u := range users {
		r := record{ID: u.ID, Name: u.Name, Image: u.Image, Accounts: accounts[u.ID]}
		if u.Email != "" {
			r.Emails = []identifier{{Value: u.Email, Verified: u.EmailVerified != "", Primary: true}}
		}
		out = append(out, r)
	}
	return out, nil
}
