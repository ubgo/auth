package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"
)

// Clerk exports users from the Dashboard as a CSV with one row per user. The
// columns the import reads are named below; a column that is missing reads
// as empty, and extra columns are ignored, so the file can carry more than
// the import needs. The export carries password hashes (`password_digest`
// with its `password_hasher`) and the TOTP secret, but no social accounts:
// Clerk's CSV has no column for them, so a user who signed in with Google
// signs in with Google here and the oauth plugin links the account to the
// user that holds the verified address (`oauth.TrustedProviders`).

// Clerk column names.
const (
	clerkColID            = "id"
	clerkColFirstName     = "first_name"
	clerkColLastName      = "last_name"
	clerkColUsername      = "username"
	clerkColImage         = "image_url"
	clerkColCreatedAt     = "created_at"
	clerkColPrimaryEmail  = "primary_email_address"
	clerkColPrimaryPhone  = "primary_phone_number"
	clerkColVerifiedEmail = "verified_email_addresses"
	clerkColOtherEmail    = "unverified_email_addresses"
	clerkColVerifiedPhone = "verified_phone_numbers"
	clerkColOtherPhone    = "unverified_phone_numbers"
	clerkColTOTP          = "totp_secret"
	clerkColDigest        = "password_digest"
	clerkColHasher        = "password_hasher"
)

// Clerk `password_hasher` values the password plugin can verify: bcrypt
// strings as they are, Django's PBKDF2 strings as they are, and argon2id,
// which is the plugin's own format. Any other hasher (Firebase scrypt,
// phpass, md5, sha256, Werkzeug) is reported and the user resets.
var clerkHashers = map[string]bool{
	"bcrypt":               true,
	"pbkdf2_sha256_django": true,
	"argon2id":             true,
}

// readClerk reads a Clerk CSV export.
//
//ds:def id=import-readclerk-9t4xw6hn
func readClerk(in input) ([]record, error) {
	rd := csv.NewReader(in.Main)
	rd.FieldsPerRecord = -1 // a short row reads as empty cells rather than an error
	header, err := rd.Read()
	if err != nil {
		return nil, fmt.Errorf("clerk: header: %w", err)
	}
	col := indexColumns(header)
	var out []record
	for line := 2; ; line++ {
		row, err := rd.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("clerk line %d: %w", line, err)
		}
		out = append(out, clerkRecord(cell(col, row)))
	}
	return out, nil
}

// clerkRecord maps one row. Clerk lists several addresses in one cell; the
// primary is the one in its own column.
func clerkRecord(get func(string) string) record {
	r := record{
		ID:         get(clerkColID),
		Name:       strings.TrimSpace(get(clerkColFirstName) + " " + get(clerkColLastName)),
		Image:      get(clerkColImage),
		CreatedAt:  parseTime(get(clerkColCreatedAt)),
		Username:   get(clerkColUsername),
		TOTPSecret: get(clerkColTOTP),
	}
	r.Emails = listedIdentifiers(get(clerkColPrimaryEmail), get(clerkColVerifiedEmail), get(clerkColOtherEmail))
	r.Phones = listedIdentifiers(get(clerkColPrimaryPhone), get(clerkColVerifiedPhone), get(clerkColOtherPhone))
	if digest := get(clerkColDigest); digest != "" {
		if hasher := get(clerkColHasher); clerkHashers[hasher] {
			r.PasswordHash = digest
		} else {
			r.PasswordNote = "Clerk hasher " + hasher + " is not verifiable here"
		}
	}
	return r
}

// listedIdentifiers builds a kind's list from Clerk's three cells: the
// primary value, the verified list and the unverified list. The primary is
// marked; a primary that Clerk lists as unverified stays unverified, since
// a primary here must be proven.
func listedIdentifiers(primary, verified, unverified string) []identifier {
	var out []identifier
	seen := map[string]bool{}
	add := func(v string, ok bool) {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, identifier{Value: v, Verified: ok, Primary: v == strings.TrimSpace(primary)})
	}
	for _, v := range splitList(verified) {
		add(v, true)
	}
	for _, v := range splitList(unverified) {
		add(v, false)
	}
	return out
}

// splitList splits a multi-valued CSV cell. Clerk separates values with a
// comma; a semicolon or a pipe is accepted too, since a hand-edited file
// often uses one.
func splitList(cell string) []string {
	return strings.FieldsFunc(cell, func(r rune) bool { return r == ',' || r == ';' || r == '|' })
}

// indexColumns maps a CSV header to column positions, case-insensitively.
func indexColumns(header []string) map[string]int {
	col := make(map[string]int, len(header))
	for i, h := range header {
		col[strings.ToLower(strings.TrimSpace(h))] = i
	}
	return col
}

// cell returns a getter for one row: the named column's value, or "" when
// the column is missing or the row is short.
func cell(col map[string]int, row []string) func(string) string {
	return func(name string) string {
		i, ok := col[name]
		if !ok || i >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[i])
	}
}
