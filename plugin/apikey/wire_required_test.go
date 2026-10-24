package apikey_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/apikey"
)

// TestWire_OptionalFieldsAreOptional: the fields create and update treat as
// optional (every one of create's, all but update's id) are optional in the
// OpenAPI document and in the generated TypeScript types, so a client that
// sends only what it means compiles. Scopes is omitzero, not omitempty, and
// is optional all the same.
func TestWire_OptionalFieldsAreOptional(t *testing.T) {
	a, err := auth.New(auth.WithPlugins(signIn{}, apikey.New(apikey.Scopes("orders:read"))))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]struct {
				Required []string `json:"required"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(authhttp.OpenAPIDocument(a, authhttp.OpenAPIInfo{Title: "t", Version: "1"}), &doc); err != nil {
		t.Fatal(err)
	}
	for schema, want := range map[string][]string{
		"apikey.CreateRequest": nil,
		"apikey.UpdateRequest": {"id"},
		"apikey.RevokeRequest": {"id"},
	} {
		s, ok := doc.Components.Schemas[schema]
		if !ok {
			t.Fatalf("no schema %s", schema)
		}
		if !slices.Equal(s.Required, want) {
			t.Errorf("%s required = %v, want %v", schema, s.Required, want)
		}
	}
	files, err := authhttp.TypeScriptClient(a)
	if err != nil {
		t.Fatal(err)
	}
	client := string(files[authhttp.TSFileClient])
	for _, want := range []string{"  name?: string;", "  scopes?: string[] | null;", "  configId?: string;"} {
		if !strings.Contains(client, want) {
			t.Errorf("client.ts lacks %q", want)
		}
	}
}
