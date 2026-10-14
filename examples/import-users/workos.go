package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// WorkOS has no export; users are listed through the User Management API
// (`GET /user_management/users`, 100 per page) and saved as JSON. The import
// reads either the bare array or the API's `{"data": [...]}` envelope, so a
// page saved as it came works too. WorkOS does not hand out password hashes,
// so every user arrives without a password and sets one through the forgot
// flow at their first sign-in, or signs in with a magic link or a social
// provider; the guide covers the choice.

// workosUser is a WorkOS user object, in the REST API's snake_case.
type workosUser struct {
	ID                string `json:"id"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	FirstName         string `json:"first_name"`
	LastName          string `json:"last_name"`
	ProfilePictureURL string `json:"profile_picture_url"`
	CreatedAt         string `json:"created_at"`
}

// workosPage is the API's list envelope.
type workosPage struct {
	Data []workosUser `json:"data"`
}

// workosNoPassword is the note every WorkOS record carries.
const workosNoPassword = "WorkOS does not export password hashes; the user sets one through the forgot flow"

// readWorkOS reads a saved list of WorkOS users.
//
//ds:def id=import-readworkos-8d3hq5tn
func readWorkOS(in input) ([]record, error) {
	var raw json.RawMessage
	if err := json.NewDecoder(in.Main).Decode(&raw); err != nil {
		return nil, fmt.Errorf("workos: %w", err)
	}
	var users []workosUser
	if err := json.Unmarshal(raw, &users); err != nil {
		var page workosPage
		if err := json.Unmarshal(raw, &page); err != nil {
			return nil, fmt.Errorf("workos: neither an array nor a {\"data\": [...]} page: %w", err)
		}
		users = page.Data
	}
	out := make([]record, 0, len(users))
	for _, u := range users {
		r := record{
			ID:           u.ID,
			Name:         strings.TrimSpace(u.FirstName + " " + u.LastName),
			Image:        u.ProfilePictureURL,
			CreatedAt:    parseTime(u.CreatedAt),
			PasswordNote: workosNoPassword,
		}
		if u.Email != "" {
			r.Emails = []identifier{{Value: u.Email, Verified: u.EmailVerified, Primary: true}}
		}
		out = append(out, r)
	}
	return out, nil
}
