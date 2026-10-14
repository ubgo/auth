package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strings"
)

// Auth0 exports users as newline-delimited JSON: one Management API user
// object per line, from a user export job (Dashboard, or the Management
// API's export endpoint) or from the Management API itself, page by page.
// Password hashes are in the same objects only in the export Auth0's support
// hands to a tenant that asks for it (the `password_hash` field); the
// Management API never returns them.

// auth0User is the part of an Auth0 user object the import reads. Every
// other field in the line is ignored, so an export with more fields than
// these still imports.
type auth0User struct {
	UserID        string          `json:"user_id"`
	Email         string          `json:"email"`
	EmailVerified bool            `json:"email_verified"`
	PhoneNumber   string          `json:"phone_number"`
	PhoneVerified bool            `json:"phone_verified"`
	Name          string          `json:"name"`
	Nickname      string          `json:"nickname"`
	Username      string          `json:"username"`
	Picture       string          `json:"picture"`
	CreatedAt     string          `json:"created_at"`
	Blocked       bool            `json:"blocked"`
	PasswordHash  string          `json:"password_hash"`
	Identities    []auth0Identity `json:"identities"`
	MFAFactors    []auth0Factor   `json:"mfa_factors"`
}

// auth0Identity is one entry of the `identities` array: the database
// connection the user signs in with, or a social provider.
type auth0Identity struct {
	Provider   string `json:"provider"`
	UserID     string `json:"user_id"`
	Connection string `json:"connection"`
	IsSocial   bool   `json:"isSocial"`
}

// auth0Factor is one MFA factor; only `totp` carries a secret the import can
// move.
type auth0Factor struct {
	TOTP *struct {
		Secret string `json:"secret"`
	} `json:"totp"`
}

// auth0Providers maps Auth0's provider names to the names the oauth plugin's
// providers are configured under here. A provider not in the map keeps its
// Auth0 name, so an app that configured a provider under that same name
// still matches.
var auth0Providers = map[string]string{
	"google-oauth2": "google",
	"windowslive":   "microsoft",
	"github":        "github",
	"apple":         "apple",
	"facebook":      "facebook",
}

// readAuth0 reads an Auth0 user export.
//
//ds:def id=import-readauth0-3m8vk2qp
func readAuth0(in input) ([]record, error) {
	var out []record
	sc := bufio.NewScanner(in.Main)
	sc.Buffer(make([]byte, 0, scanBufferSize), scanBufferSize)
	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		var u auth0User
		if err := json.Unmarshal([]byte(raw), &u); err != nil {
			return nil, fmt.Errorf("auth0 line %d: %w", line, err)
		}
		out = append(out, auth0Record(u))
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("auth0: %w", err)
	}
	return out, nil
}

// auth0Record maps one Auth0 user. Auth0 keeps the user id as
// `provider|id`, which is kept as our user id: it is opaque text and
// unique, so the app's rows keep their foreign keys.
func auth0Record(u auth0User) record {
	r := record{
		ID:           u.UserID,
		Name:         firstNonEmpty(u.Name, u.Nickname),
		Image:        u.Picture,
		CreatedAt:    parseTime(u.CreatedAt),
		Username:     u.Username,
		PasswordHash: u.PasswordHash,
	}
	if u.Email != "" {
		r.Emails = []identifier{{Value: u.Email, Verified: u.EmailVerified, Primary: true}}
	}
	if u.PhoneNumber != "" {
		r.Phones = []identifier{{Value: u.PhoneNumber, Verified: u.PhoneVerified, Primary: true}}
	}
	if u.Blocked {
		// Auth0's block has no end date: a permanent ban.
		r.Banned, r.BanReason = true, auth0BlockedReason
	}
	for _, idn := range u.Identities {
		if !idn.IsSocial {
			continue // the database, email or sms connection: that is the user, not a linked account
		}
		name := idn.Provider
		if mapped, ok := auth0Providers[name]; ok {
			name = mapped
		}
		r.Accounts = append(r.Accounts, account{Provider: name, AccountID: idn.UserID})
	}
	for _, f := range u.MFAFactors {
		if f.TOTP != nil && f.TOTP.Secret != "" {
			r.TOTPSecret = f.TOTP.Secret
			break
		}
	}
	return r
}

// auth0BlockedReason is the reason stored with an imported block, since Auth0
// keeps none.
const auth0BlockedReason = "blocked in Auth0"
