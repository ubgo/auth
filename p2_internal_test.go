package auth

import "testing"

// statementShape reads the verb and the first table of each form the
// builder renders, unquoted, and nothing else.
func TestStatementShape(t *testing.T) {
	cases := map[string][2]string{
		`SELECT a, b FROM "auth_user" WHERE id = $1`:          {dbSelect, "auth_user"},
		"select x from `app_auth_session` where y = ?":        {dbSelect, "app_auth_session"},
		`INSERT INTO auth_identity (id) VALUES ($1)`:          {dbInsert, "auth_identity"},
		`UPDATE "auth_user" SET name = $1`:                    {dbUpdate, "auth_user"},
		`DELETE FROM auth_verification WHERE expires_at < $1`: {dbDelete, "auth_verification"},
		`WITH x AS (SELECT 1) SELECT * FROM x`:                {dbOther, ""},
		`SELECT 1`:                                            {dbSelect, ""},
		`UPDATE`:                                              {dbUpdate, ""},
		``:                                                    {dbOther, ""},
	}
	for sql, want := range cases {
		if op, table := statementShape(sql); op != want[0] || table != want[1] {
			t.Errorf("%q: %s %s, want %s %s", sql, op, table, want[0], want[1])
		}
	}
	if hookModel(&Identity{}) != "identity" || hookModel(&Verification{}) != "verification" || hookModel(1) != "" {
		t.Fatal("hookModel")
	}
}
