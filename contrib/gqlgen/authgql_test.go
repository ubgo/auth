package authgql

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ubgo/auth"
)

func TestErrorPresenter_KeepsAuthCodesAndHidesTheRest(t *testing.T) {
	ctx := context.Background()
	got := ErrorPresenter(ctx, fmt.Errorf("resolver: %w", auth.ErrTokenInvalid))
	if Code(got) != auth.ErrTokenInvalid.Code || got.Message != auth.ErrTokenInvalid.Message {
		t.Fatalf("auth error = %+v", got)
	}
	got = ErrorPresenter(ctx, errors.New(`pq: relation "auth_secret" does not exist`))
	if Code(got) != auth.ErrInternal.Code || strings.Contains(got.Message, "auth_secret") {
		t.Fatalf("internal error leaked: %+v", got)
	}
	if Code(nil) != "" {
		t.Fatal("Code(nil)")
	}
}

func TestSignedIn_RefusesWithoutASession(t *testing.T) {
	ran := false
	_, err := SignedIn(context.Background(), nil, func(context.Context) (any, error) { ran = true; return nil, nil })
	if !errors.Is(err, auth.ErrSignedOut) || ran {
		t.Fatalf("err = %v ran = %v", err, ran)
	}
}

func TestSchema_DeclaresTheDirective(t *testing.T) {
	if !strings.Contains(Schema, "directive @signedIn on FIELD_DEFINITION") {
		t.Fatal("schema lacks @signedIn")
	}
}
