package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/metadata"
	"github.com/ubgo/auth/plugin/password"
)

// The seeded demo user, so someone can sign in the moment the demo starts.
// The demo README and the web app's home page show the same values
// (web/src/demo-user.ts); change all three together.
const (
	demoUserName     = "Ada Lovelace"
	demoUserEmail    = "ada@example.com"
	demoUserPassword = "correct horse battery staple"
)

// The second user with a password, so the admin dashboard has someone with
// live sessions to look at and revoke (sign in as them in another browser).
// web/src/demo-user.ts names the same values.
const (
	secondUserName  = "Linus Pauling"
	secondUserEmail = "linus@example.com"
	// secondUserPublicMetadata is Linus's public metadata, as an app's checkout would set it.
	secondUserPublicMetadata = `{"plan":"pro","seats":5}`
)

// The user the forced-enrolment rule applies to (admin.go mustEnrol): signing
// in as them opens the set-up-two-factor task before anything else works.
// Same password as the demo user; web/src/demo-user.ts names the address.
const (
	mfaUserName  = "Grace Required"
	mfaUserEmail = "mfa@example.com"
)

// directorySize is how many sign-in-less users the seed adds, so the admin
// dashboard's users table has more than one page at its default page size
// (50) and a search has something to find.
const directorySize = 64

// directoryBanned is how many of those users the seed bans, so the table's
// "Banned" filter shows rows on a fresh database.
const directoryBanned = 3

// directoryDomain is the address domain of the directory users; the first
// one's address tells the seed whether the directory exists already.
const directoryDomain = "directory.test"

// directoryNames are combined (first × last) into the directory users' names.
var (
	directoryFirst = []string{"Alan", "Barbara", "Charles", "Dorothy", "Edsger", "Frances", "Grace", "Hedy", "Ivan", "Jean", "Ken", "Lynn", "Margaret", "Niklaus", "Radia", "Tim"}
	directoryLast  = []string{"Turing", "Liskov", "Shannon", "Vaughan"}
)

// seed creates the demo user with a verified address and admin rights, the
// second password user, the user who must enrol a second factor, and the
// directory users, each only when missing, so
// a fresh database (task demo:reset) is ready to use and an older one gains
// what it lacks. Running it on every start is safe: existing users are left
// as they are.
func seed(ctx context.Context, d demo) error {
	ada, err := seedPasswordUser(ctx, d, demoUserName, demoUserEmail)
	if err != nil {
		return err
	}
	if err := seedAdmin(ctx, d, ada); err != nil {
		return err
	}
	linus, err := seedPasswordUser(ctx, d, secondUserName, secondUserEmail)
	if err != nil {
		return err
	}
	// Public metadata an app would set from its own logic (a checkout), so
	// the admin dashboard's metadata section has something to show. A merge
	// patch, so running it again changes nothing.
	if _, err := d.metadata.Merge(ctx, linus, metadata.Public, json.RawMessage(secondUserPublicMetadata)); err != nil {
		return fmt.Errorf("seed: metadata for %s: %w", secondUserEmail, err)
	}
	if _, err := seedPasswordUser(ctx, d, mfaUserName, mfaUserEmail); err != nil {
		return err
	}
	return seedDirectory(ctx, d)
}

// seedPasswordUser signs a user up with the demo password and verifies the
// address, unless the address exists; it returns the user's id either way.
func seedPasswordUser(ctx context.Context, d demo, name, address string) (string, error) {
	idn, err := d.auth.FindIdentity(ctx, email.KindEmail, address, false)
	if err == nil {
		return idn.UserID, nil
	}
	if !errors.Is(err, auth.ErrIdentityNotFound) {
		return "", fmt.Errorf("seed: look up %s: %w", address, err)
	}
	if _, err := d.password.SignUp(ctx, password.SignUpRequest{Name: name, Identifier: address, Password: password.Secret(demoUserPassword)}); err != nil {
		return "", fmt.Errorf("seed: sign up %s: %w", address, err)
	}
	idn, err = d.auth.FindIdentity(ctx, email.KindEmail, address, false)
	if err != nil {
		return "", fmt.Errorf("seed: find %s: %w", address, err)
	}
	if _, err := d.auth.VerifyIdentity(ctx, idn.ID); err != nil {
		return "", fmt.Errorf("seed: verify %s: %w", address, err)
	}
	log.Printf("seeded the demo user %s / %s", address, demoUserPassword)
	return idn.UserID, nil
}

// seedAdmin grants the demo user admin rights unless they have them, the way
// an app grants its first admin from trusted code: nobody can grant it over
// HTTP before an admin exists.
func seedAdmin(ctx context.Context, d demo, userID string) error {
	var cols admin.AdminColumns
	if err := d.auth.LoadUserColumns(ctx, userID, admin.Bindings(&cols)...); err != nil {
		return fmt.Errorf("seed: read admin columns: %w", err)
	}
	if cols.AdminGrantedAt != nil {
		return nil
	}
	if err := d.admin.Grant(ctx, userID); err != nil {
		return fmt.Errorf("seed: grant admin: %w", err)
	}
	log.Printf("granted %s admin rights", demoUserEmail)
	return nil
}

// directoryAddress is the i-th directory user's address, lowercase as the
// email plugin stores it.
func directoryAddress(i int) string {
	return strings.ToLower(fmt.Sprintf("%s.%s.%d@%s", directoryFirst[i%len(directoryFirst)], directoryLast[(i/len(directoryFirst))%len(directoryLast)], i+1, directoryDomain))
}

// seedDirectory adds directorySize users with a verified address and no way
// to sign in, a few of them banned, unless the first one exists. They are
// plain rows for the admin dashboard to page, search, filter and act on;
// creation times are spread over past days so the sort has something to do.
func seedDirectory(ctx context.Context, d demo) error {
	if _, err := d.auth.FindIdentity(ctx, email.KindEmail, directoryAddress(0), false); err == nil {
		return nil
	} else if !errors.Is(err, auth.ErrIdentityNotFound) {
		return fmt.Errorf("seed: look up the directory: %w", err)
	}
	now := d.auth.Now()
	for i := range directorySize {
		name := directoryFirst[i%len(directoryFirst)] + " " + directoryLast[(i/len(directoryFirst))%len(directoryLast)]
		err := d.auth.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
			u, err := d.auth.CreateUser(ctx, auth.NewUser{Name: name, CreatedAt: now.Add(-time.Duration(directorySize-i) * 24 * time.Hour)})
			if err != nil {
				return err
			}
			if _, err := d.auth.CreateIdentity(ctx, auth.NewIdentity{UserID: u.ID, Kind: email.KindEmail, Raw: directoryAddress(i), Verified: true, Primary: true}); err != nil {
				return err
			}
			if i < directoryBanned {
				return d.admin.BanFor(ctx, u.ID, "Seeded as banned by the demo", time.Time{})
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("seed: directory user %d: %w", i, err)
		}
	}
	log.Printf("seeded %d directory users (@%s) for the admin dashboard", directorySize, directoryDomain)
	return nil
}
