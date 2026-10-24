package phone_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/phone"
)

// TestMultiple_RegistersListAndMakePrimary: the list and make-primary routes
// exist only under Multiple, and without it the Go methods say so instead of
// calling an operation nothing wired. The behaviour on a database is in
// integration/r23_test.go.
func TestMultiple_RegistersListAndMakePrimary(t *testing.T) {
	single := phone.New(phone.WithSMS(noSMS))
	a, err := auth.New(auth.WithPlugins(signIn{}, single))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []auth.EndpointID{phone.EndpointList, phone.EndpointMakePrimary} {
		if _, ok := a.Operation(id); ok {
			t.Fatalf("%s registered without Multiple", id)
		}
	}
	if _, err := single.List(context.Background()); !errors.Is(err, auth.ErrOperationNotWired) {
		t.Fatalf("List without Multiple = %v", err)
	}
	if err := single.MakePrimary(context.Background(), "+14155550100"); !errors.Is(err, auth.ErrOperationNotWired) {
		t.Fatalf("MakePrimary without Multiple = %v", err)
	}
	a, err = auth.New(auth.WithPlugins(signIn{}, phone.New(phone.WithSMS(noSMS), phone.Multiple())))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []auth.EndpointID{phone.EndpointList, phone.EndpointMakePrimary} {
		if _, ok := a.Operation(id); !ok {
			t.Fatalf("%s missing under Multiple", id)
		}
	}
}
