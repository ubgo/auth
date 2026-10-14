package access_test

import (
	"errors"
	"fmt"

	"github.com/ubgo/auth/plugin/access"
)

// Example declares a vocabulary, builds two roles from it and checks them.
// ds:def id=example-gwg3tegh owner=@khanakia stability=stable
func Example() {
	ac := access.MustNew(access.Statements{
		"project": {"create", "share", "delete"},
		"billing": {"read", "update"},
	})
	editor := ac.MustRole(access.Permissions{"project": {"create", "share"}})
	accountant := ac.MustRole(access.Permissions{"billing": {"read", "update"}})

	fmt.Println(editor.Allows(access.Request{"project": access.All("create", "share")}))
	fmt.Println(editor.Authorize(access.Request{"project": access.Any("delete", "share")}, access.And) == nil)
	err := accountant.Authorize(access.Request{"project": access.All("create")}, access.And)
	fmt.Println(errors.Is(err, access.ErrDenied), err)
	// Output:
	// true
	// true
	// true access: denied: You are not allowed to access resource: project
}
