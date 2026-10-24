package auth

import (
	"errors"
	"strings"
)

// Unique-violation signatures of the three supported drivers.
//
// The core cannot import the drivers — that would give every consumer all
// three — so it recognizes each driver's error by the one stable property it
// exposes: Postgres's SQLSTATE through an SQLState() method (pgx and lib/pq
// both provide it), and the message text for MySQL and SQLite, whose drivers
// expose only a number field or a code without a shared interface. Each form
// is pinned by an integration test on its engine, so a driver that changes its
// wording fails a test instead of turning a duplicate into a 500.
const (
	pgUniqueViolation = "23505"
	mysqlDuplicate    = "Error 1062"
	sqliteUnique      = "UNIQUE constraint failed"
)

// IsUniqueViolation reports whether err is a unique-constraint failure on any
// supported engine. Plugins use it for their own tables, so a duplicate becomes
// a declared error instead of a 500.
func IsUniqueViolation(err error) bool { return isUniqueViolation(err) }

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	var state interface{ SQLState() string }
	if errors.As(err, &state) && state.SQLState() == pgUniqueViolation {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, mysqlDuplicate) || strings.Contains(msg, sqliteUnique)
}
