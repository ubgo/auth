package sso

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// ProviderField is an app-defined field on every provider (better-auth's
// schema.ssoProvider.additionalFields), stored as JSON beside the provider.
type ProviderField struct {
	Name string
	// Required refuses a registration without it.
	Required bool
	// NoInput refuses it in a register or update body (better-auth's
	// input: false): only the app's Go code sets it, with SetProviderFields.
	NoInput bool
}

// WithProviderFields declares the provider's additional fields.
func WithProviderFields(fields ...ProviderField) Option {
	return func(p *Plugin) { p.fields = append(p.fields, fields...) }
}

// Errors of additional fields.
var (
	ErrFieldNotAllowed = auth.NewError("sso.field_not_allowed", http.StatusBadRequest, "A provider field may not be set here.")
	ErrBadFields       = errors.New("sso: a provider field name is empty, repeated, or a built-in key")
)

// builtinKeys are the provider and response keys a field may not shadow.
var builtinKeys = []string{"id", "providerId", "issuer", "domain", "organizationId", "userId", "oidcConfig", "samlConfig",
	"domainVerified", "type", "protocols", "redirectURI", "acsURL", "spMetadataURL", "domainVerificationToken", "additionalFields"}

// validateFields checks the declared fields.
func (p *Plugin) validateFields() error {
	seen := map[string]bool{}
	for _, f := range p.fields {
		if f.Name == "" || seen[f.Name] || slices.Contains(builtinKeys, f.Name) {
			return fmt.Errorf("%w: sso.WithProviderFields: %q", ErrBadFields, f.Name)
		}
		seen[f.Name] = true
	}
	return nil
}

// checkFieldInput refuses unknown and NoInput fields in a request body;
// with register, a missing Required field too.
func (p *Plugin) checkFieldInput(in map[string]any, register bool) error {
	for k := range in {
		i := slices.IndexFunc(p.fields, func(f ProviderField) bool { return f.Name == k })
		switch {
		case i < 0:
			return fmt.Errorf("%w: unknown field %q", ErrBadProvider, k)
		case p.fields[i].NoInput:
			return fmt.Errorf("%w: %q is not allowed to be set", ErrFieldNotAllowed, k)
		}
	}
	if register {
		for _, f := range p.fields {
			if _, ok := in[f.Name]; f.Required && !ok && !f.NoInput {
				return fmt.Errorf("%w: field %q is required", ErrBadProvider, f.Name)
			}
		}
	}
	return nil
}

// encodeFields is the fields column: NULL when there are none.
func encodeFields(m map[string]any) (*string, error) {
	if len(m) == 0 {
		return nil, nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	s := string(b)
	return &s, nil
}

// SetProviderFields sets additional fields from Go, NoInput ones included;
// a field not declared is refused.
func (p *Plugin) SetProviderFields(ctx context.Context, providerID string, values map[string]any) error {
	pr, err := p.ProviderByID(ctx, providerID)
	if err != nil {
		return err
	}
	if pr.Default {
		return ErrForbidden
	}
	merged := map[string]any{}
	for k, v := range pr.Fields {
		merged[k] = v
	}
	for k, v := range values {
		if !slices.ContainsFunc(p.fields, func(f ProviderField) bool { return f.Name == k }) {
			return fmt.Errorf("%w: unknown field %q", ErrBadProvider, k)
		}
		merged[k] = v
	}
	col, err := encodeFields(merged)
	if err != nil {
		return err
	}
	_, err = p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableProvider).Set(sqlb.Set(ProviderFields, col)).Where(sqlb.Eq(ProviderRowID, pr.ID)))
	return err
}
