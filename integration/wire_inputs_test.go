package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/deviceauth"
	"github.com/ubgo/auth/plugin/oauthprovider"
)

// openAPISchemas is the components.schemas of a's OpenAPI document: each
// schema's required names and its property names.
func openAPISchemas(t *testing.T, a *auth.Auth) map[string]struct {
	Required   []string       `json:"required"`
	Properties map[string]any `json:"properties"`
} {
	t.Helper()
	var doc struct {
		Components struct {
			Schemas map[string]struct {
				Required   []string       `json:"required"`
				Properties map[string]any `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(authhttp.OpenAPIDocument(a, authhttp.OpenAPIInfo{Title: "t", Version: "1"}), &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Components.Schemas
}

// tsInterface is the body of one generated TypeScript interface.
func tsInterface(t *testing.T, a *auth.Auth, name string) string {
	t.Helper()
	files, err := authhttp.TypeScriptClient(a)
	if err != nil {
		t.Fatal(err)
	}
	src := string(files[authhttp.TSFileClient])
	_, body, ok := strings.Cut(src, "export interface "+name+" {")
	if !ok {
		t.Fatalf("client.ts has no interface %s", name)
	}
	body, _, _ = strings.Cut(body, "\n}")
	return body
}

// oauthDefaulted are the registration fields the provider defaults: optional
// in the input, always present in the answer (RFC 7591 section 3.2.1).
var oauthDefaulted = []string{"client_name", "grant_types", "response_types", "token_endpoint_auth_method", "scope"}

// TestWire_OAuthClientMetadata: the registration input leaves the defaulted
// fields optional in the OpenAPI document and the TypeScript client, while
// the client and the registration answer keep them required, and a real
// registration that sent none of them answers every one.
func TestWire_OAuthClientMetadata(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e, oauthprovider.AllowDynamicRegistration(), oauthprovider.AllowUnauthenticatedRegistration())
		schemas := openAPISchemas(t, o.a)
		if got := schemas["oauthprovider.ClientMetadata"].Required; !slices.Equal(got, []string{"redirect_uris"}) {
			t.Errorf("ClientMetadata required = %v, want [redirect_uris]", got)
		}
		for _, out := range []string{"oauthprovider.Client", "oauthprovider.Registration"} {
			for _, f := range oauthDefaulted {
				if !slices.Contains(schemas[out].Required, f) {
					t.Errorf("%s does not require %s", out, f)
				}
			}
		}
		in, out := tsInterface(t, o.a, "OauthproviderClientMetadata"), tsInterface(t, o.a, "OauthproviderClient")
		for _, f := range oauthDefaulted {
			if !strings.Contains(in, "\n  "+f+"?: ") {
				t.Errorf("OauthproviderClientMetadata.%s is not optional", f)
			}
			if !strings.Contains(out, "\n  "+f+": ") {
				t.Errorf("OauthproviderClient.%s is not required", f)
			}
		}

		w := c1Do(o.op.Handler(), http.MethodPost, "/oauth2/register", "application/json", `{"redirect_uris":["`+opRedirect+`"]}`, nil)
		if w.Code != http.StatusCreated {
			t.Fatalf("register = %d %s", w.Code, w.Body)
		}
		var reg map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &reg); err != nil {
			t.Fatal(err)
		}
		for _, f := range oauthDefaulted {
			if _, ok := reg[f]; !ok {
				t.Errorf("registration answer lacks %s: %s", f, w.Body)
			}
		}
		if reg["token_endpoint_auth_method"] != oauthprovider.AuthMethodBasic {
			t.Errorf("token_endpoint_auth_method = %v, want the default", reg["token_endpoint_auth_method"])
		}
	})
}

// TestWire_DeviceCodeUserID: CodeRequest.UserID is Go-only. It is absent
// from the OpenAPI document and the TypeScript client, the JSON route
// refuses it as an unknown field, Code from Go still binds the code, and an
// operation reached through Invoke with a decoder that sets it is refused.
func TestWire_DeviceCodeUserID(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newDeviceWorld(t, e)
		if _, ok := openAPISchemas(t, w.a)["deviceauth.CodeRequest"].Properties["user_id"]; ok {
			t.Error("the OpenAPI CodeRequest offers user_id")
		}
		if strings.Contains(tsInterface(t, w.a, "DeviceauthCodeRequest"), "user_id") {
			t.Error("the TypeScript CodeRequest offers user_id")
		}

		h := authhttp.Handler(w.a, authhttp.Prefix("/auth"))
		req := httptest.NewRequest(http.MethodPost, testBaseURL+"/auth/device/code", strings.NewReader(`{"client_id":"cli","user_id":"`+w.alice+`"}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("user_id over the JSON route = %d %s", rec.Code, rec.Body)
		}

		bound := must[deviceauth.CodeResult](t)(w.dp.Code(anon(w.a), deviceauth.CodeRequest{ClientID: "cli", UserID: w.bob}))
		if v := must[deviceauth.VerifyResult](t)(w.dp.Verify(request(w.a, w.aliceTok), bound.UserCode)); v.Owned {
			t.Fatal("Code from Go did not bind the code to bob")
		}

		op, ok := w.a.Operation(deviceauth.EndpointCode)
		if !ok {
			t.Fatal("no device code operation")
		}
		_, err := op.Invoke(w.a.WithRequest(context.Background(), auth.Request{}), func(dst any) error {
			in, ok := dst.(*deviceauth.CodeRequest)
			if !ok {
				return errors.New("not a CodeRequest")
			}
			in.ClientID, in.UserID = "cli", w.alice
			return nil
		})
		if !errors.Is(err, deviceauth.ErrInvalidRequest) {
			t.Fatalf("UserID through Invoke: %v", err)
		}
	})
}
