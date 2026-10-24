package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Supabase keeps users in its own `auth` schema, which psql can copy out as
// CSV. The guide gives the three queries; the import reads their files:
//
//   - users: id, email, encrypted_password, email_confirmed_at, phone,
//     phone_confirmed_at, raw_user_meta_data, created_at, is_super_admin,
//     banned_until, is_anonymous, deleted_at
//   - identities: user_id, provider, provider_id, identity_data
//   - factors (optional): user_id, factor_type, status, secret
//
// Postgres writes booleans as `t` and `f`, nulls as empty cells and JSON as
// text, which is what the readers below expect.

// Supabase column names.
const (
	sbColID             = "id"
	sbColEmail          = "email"
	sbColPassword       = "encrypted_password"
	sbColEmailConfirmed = "email_confirmed_at"
	sbColPhone          = "phone"
	sbColPhoneConfirmed = "phone_confirmed_at"
	sbColMeta           = "raw_user_meta_data"
	sbColCreatedAt      = "created_at"
	sbColSuperAdmin     = "is_super_admin"
	sbColBannedUntil    = "banned_until"
	sbColAnonymous      = "is_anonymous"
	sbColDeletedAt      = "deleted_at"

	sbColUserID       = "user_id"
	sbColProvider     = "provider"
	sbColProviderID   = "provider_id"
	sbColIdentityData = "identity_data"
	sbColFactorType   = "factor_type"
	sbColStatus       = "status"
	sbColSecret       = "secret"
)

// Supabase values.
const (
	// pgTrue is how Postgres writes a true boolean in CSV.
	pgTrue = "t"
	// sbFactorTOTP and sbStatusVerified select the factors worth moving: a
	// phone factor has no secret, an unverified one was never finished.
	sbFactorTOTP     = "totp"
	sbStatusVerified = "verified"
)

// sbBannedReason is stored with an imported ban, since Supabase keeps none.
const sbBannedReason = "banned in Supabase"

// sbCredentialProviders are the identities that are the user's own sign-in,
// not a linked account; the user's address and number already come from the
// users table.
var sbCredentialProviders = map[string]bool{"email": true, "phone": true}

// sbMeta is the part of raw_user_meta_data the import reads: the name and
// picture OAuth providers write there.
type sbMeta struct {
	FullName  string `json:"full_name"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"`
	Picture   string `json:"picture"`
}

// readSupabase reads the users CSV, then the identities and factors CSVs,
// joining them on the user id.
func readSupabase(in input) ([]record, error) {
	rows, err := readCSV(in.Main, "supabase users")
	if err != nil {
		return nil, err
	}
	accounts := map[string][]account{}
	if in.Identities != nil {
		ids, err := readCSV(in.Identities, "supabase identities")
		if err != nil {
			return nil, err
		}
		for _, get := range ids {
			if sbCredentialProviders[get(sbColProvider)] {
				continue
			}
			var data struct {
				Email string `json:"email"`
			}
			_ = json.Unmarshal([]byte(get(sbColIdentityData)), &data) // a missing or odd identity_data only loses the email hint
			accounts[get(sbColUserID)] = append(accounts[get(sbColUserID)], account{Provider: get(sbColProvider), AccountID: get(sbColProviderID), Email: data.Email})
		}
	}
	secrets := map[string]string{}
	if in.Factors != nil {
		fs, err := readCSV(in.Factors, "supabase factors")
		if err != nil {
			return nil, err
		}
		for _, get := range fs {
			if get(sbColFactorType) == sbFactorTOTP && get(sbColStatus) == sbStatusVerified && get(sbColSecret) != "" {
				secrets[get(sbColUserID)] = get(sbColSecret)
			}
		}
	}
	out := make([]record, 0, len(rows))
	for _, get := range rows {
		r := supabaseRecord(get)
		r.Accounts = accounts[r.ID]
		r.TOTPSecret = secrets[r.ID]
		out = append(out, r)
	}
	return out, nil
}

// supabaseRecord maps one users row. An anonymous user has no identifier
// and no credential: there is nothing they could come back with, so the row
// is skipped; so is a soft-deleted one.
//
//ds:def id=import-supabaserecord-5w7rj2kc
func supabaseRecord(get func(string) string) record {
	var meta sbMeta
	_ = json.Unmarshal([]byte(get(sbColMeta)), &meta) // odd metadata only loses name and picture
	r := record{
		ID:           get(sbColID),
		Name:         firstNonEmpty(meta.FullName, meta.Name),
		Image:        firstNonEmpty(meta.AvatarURL, meta.Picture),
		CreatedAt:    parseTime(get(sbColCreatedAt)),
		PasswordHash: get(sbColPassword),
		Admin:        get(sbColSuperAdmin) == pgTrue,
	}
	// A ban still in force comes along with its end; one that has lapsed is
	// history Supabase kept, not a ban.
	if until := parseTime(get(sbColBannedUntil)); !until.IsZero() && until.After(now()) {
		r.Banned, r.BannedUntil, r.BanReason = true, until, sbBannedReason
	}
	switch {
	case get(sbColDeletedAt) != "":
		r.Skip = "deleted in Supabase"
	case get(sbColAnonymous) == pgTrue:
		r.Skip = "anonymous user, nothing to sign in with"
	}
	if e := get(sbColEmail); e != "" {
		r.Emails = []identifier{{Value: e, Verified: get(sbColEmailConfirmed) != "", Primary: true}}
	}
	if p := get(sbColPhone); p != "" {
		r.Phones = []identifier{{Value: "+" + strings.TrimPrefix(p, "+"), Verified: get(sbColPhoneConfirmed) != "", Primary: true}}
	}
	return r
}

// readCSV reads a whole CSV with a header into row getters.
func readCSV(r io.Reader, what string) ([]func(string) string, error) {
	rd := csv.NewReader(r)
	rd.FieldsPerRecord = -1
	header, err := rd.Read()
	if err != nil {
		return nil, fmt.Errorf("%s: header: %w", what, err)
	}
	col := indexColumns(header)
	var out []func(string) string
	for line := 2; ; line++ {
		row, err := rd.Read()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %w", what, line, err)
		}
		out = append(out, cell(col, row))
	}
}
