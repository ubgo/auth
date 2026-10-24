package scim

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/ubgo/auth"
)

// Media types. A request body must be one of them; every answer is SCIM's.
const (
	MediaType     = "application/scim+json"
	mediaTypeJSON = "application/json"
)

// Schema URNs (RFC 7643, RFC 7644).
const (
	SchemaUser           = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaEnterpriseUser = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	SchemaGroup          = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SchemaListResponse   = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaPatchOp        = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	SchemaError          = "urn:ietf:params:scim:api:messages:2.0:Error"
	SchemaSPConfig       = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	SchemaResourceType   = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	SchemaSchema         = "urn:ietf:params:scim:schemas:core:2.0:Schema"
)

// ErrorType is RFC 7644 §3.12's scimType.
type ErrorType string

// Error types.
const (
	InvalidFilter ErrorType = "invalidFilter"
	TooMany       ErrorType = "tooMany"
	Uniqueness    ErrorType = "uniqueness"
	Mutability    ErrorType = "mutability"
	InvalidSyntax ErrorType = "invalidSyntax"
	InvalidPath   ErrorType = "invalidPath"
	NoTarget      ErrorType = "noTarget"
	InvalidValue  ErrorType = "invalidValue"
	InvalidVers   ErrorType = "invalidVers"
	Sensitive     ErrorType = "sensitive"
)

// Error is a SCIM error answer. It is returned by the plugin's Go methods
// and written by Handler in SCIM's error schema.
//
//ds:def id=scim-error-8k3vn6wq owner=@khanakia stability=stable
type Error struct {
	Status int
	Type   ErrorType
	Detail string
}

func (e *Error) Error() string {
	return "scim: " + strconv.Itoa(e.Status) + " " + string(e.Type) + ": " + e.Detail
}

// errorf builds an Error.
func errorf(status int, t ErrorType, detail string) *Error {
	return &Error{Status: status, Type: t, Detail: detail}
}

// Request errors that are not about a value.
var (
	errMissingToken = errorf(http.StatusUnauthorized, "", "SCIM bearer token is required")
	errInvalidToken = errorf(http.StatusUnauthorized, "", "Invalid SCIM bearer token")
	errExpiredToken = errorf(http.StatusUnauthorized, "", "SCIM bearer token has expired")
	errScope        = errorf(http.StatusForbidden, "", "The credential lacks the scope this request needs")
	errNotFound     = errorf(http.StatusNotFound, "", "Resource not found")
	errMediaType    = errorf(http.StatusUnsupportedMediaType, "", "Content-Type must be application/scim+json or application/json")
	errMethod       = errorf(http.StatusMethodNotAllowed, "", "Method not allowed")
	errSyntax       = errorf(http.StatusBadRequest, InvalidSyntax, "The request body is not valid JSON")
)

// errorBody is the SCIM error schema.
type errorBody struct {
	Schemas  []string  `json:"schemas"`
	Status   string    `json:"status"`
	ScimType ErrorType `json:"scimType,omitempty"`
	Detail   string    `json:"detail,omitempty"`
}

// writeError answers err in SCIM's schema: a *Error as itself, a coded
// library error with its status (an identity taken is SCIM's uniqueness),
// anything else as 500 with no detail.
func writeError(w http.ResponseWriter, err error) {
	var se *Error
	switch {
	case errors.As(err, &se):
	case errors.Is(err, auth.ErrIdentityTaken):
		se = errorf(http.StatusConflict, Uniqueness, "The email is already used by another account")
	case errors.Is(err, auth.ErrIdentifierInvalid):
		se = errorf(http.StatusBadRequest, InvalidValue, "An email is not valid")
	default:
		info := auth.ErrorOf(err)
		se = errorf(info.Status, "", info.Message)
		if info.Status >= http.StatusInternalServerError {
			se.Detail = "Internal error"
		}
	}
	if se.Status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="SCIM"`)
	}
	writeJSON(w, se.Status, errorBody{Schemas: []string{SchemaError}, Status: strconv.Itoa(se.Status), ScimType: se.Type, Detail: se.Detail})
}

// writeJSON writes v in SCIM's media type. v is any because it is whichever
// resource or document the request asked for; the encoder is the boundary.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", MediaType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v) // a client that hung up cannot be told
}
