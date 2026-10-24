//go:build typecheck_negative

// Package typecheck holds deliberately WRONG code, excluded from normal builds
// by its build tag.
//
// It exists because "fully typesafe" is a claim, and a claim nobody has tested
// is not verified. Build this package with the tag to see the compiler reject
// each line:
//
//	go build -tags typecheck_negative ./examples/typecheck/
//
// Every error below is a bug class that a hand-written query would ship
// silently and discover in production.
package typecheck

import (
	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

func wrong() {
	// Comparing a timestamp column against a string.
	_ = sqlb.Eq(auth.UserCreatedAt, "yesterday")

	// Scanning a text column into an int destination.
	var n int
	_ = sqlb.Bind(auth.UserName, &n)

	// Joining a string column to a bool column.
	_ = sqlb.EqExpr(auth.IdentityUserID, auth.IdentityIsPrimary)

	// Passing a string VARIABLE where an identifier kind is required.
	//
	// Note the limit of named string types, stated honestly: an untyped string
	// CONSTANT such as sqlb.Eq(auth.IdentityKind, "email") does compile, because
	// Go converts untyped constants implicitly. The named type catches the case
	// that actually causes bugs — a string that travelled through a variable,
	// a function return, or a request field — and does not catch a literal
	// typed inline. That is why the kind constants that plugins export exist: the
	// literal is meant to never be written at a call site in the first place.
	kindFromRequest := "email"
	_ = sqlb.Eq(auth.IdentityKind, kindFromRequest)
}
