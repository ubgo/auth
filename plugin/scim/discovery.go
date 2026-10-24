package scim

import (
	"net/http"
	"strings"
)

// attr is one attribute definition of a published schema (RFC 7643 §7).
type attr struct {
	Name          string `json:"name"`
	Type          string `json:"type"`
	MultiValued   bool   `json:"multiValued"`
	Required      bool   `json:"required"`
	CaseExact     bool   `json:"caseExact"`
	Mutability    string `json:"mutability"`
	Returned      string `json:"returned"`
	Uniqueness    string `json:"uniqueness"`
	SubAttributes []attr `json:"subAttributes,omitempty"`
}

// Attribute shorthands for the schema tables below.
func str(name string) attr {
	return attr{Name: name, Type: "string", Mutability: "readWrite", Returned: "default", Uniqueness: "none"}
}
func multi(name string, subs ...attr) attr {
	return attr{Name: name, Type: "complex", MultiValued: true, Mutability: "readWrite", Returned: "default", Uniqueness: "none", SubAttributes: subs}
}
func complexAttr(name string, subs ...attr) attr {
	return attr{Name: name, Type: "complex", Mutability: "readWrite", Returned: "default", Uniqueness: "none", SubAttributes: subs}
}
func boolean(name string) attr {
	return attr{Name: name, Type: "boolean", Mutability: "readWrite", Returned: "default", Uniqueness: "none"}
}

// typedValue is the value, display, type and primary of a multi-valued
// attribute.
func typedValue(name string) attr {
	return multi(name, str("value"), str("display"), str("type"), boolean("primary"))
}

// schemaDoc is a published schema.
type schemaDoc struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Attributes  []attr   `json:"attributes"`
	Meta        docMeta  `json:"meta"`
}

// docMeta is a discovery document's meta.
type docMeta struct {
	ResourceType string `json:"resourceType"`
	Location     string `json:"location,omitempty"`
}

// schemas are the three published schemas.
func schemas() []schemaDoc {
	userName := str("userName")
	userName.Required, userName.Uniqueness = true, "server"
	id := str("id")
	id.Mutability, id.Returned, id.CaseExact, id.Uniqueness = "readOnly", "always", true, "server"
	ext := str("externalId")
	ext.CaseExact = true
	display := str("displayName")
	groupName := display
	groupName.Required = true
	return []schemaDoc{
		{Schemas: []string{SchemaSchema}, ID: SchemaUser, Name: "User", Description: "User Account", Meta: docMeta{ResourceType: "Schema"},
			Attributes: []attr{id, ext, userName,
				complexAttr("name", str("formatted"), str("familyName"), str("givenName"), str("middleName"), str("honorificPrefix"), str("honorificSuffix")),
				display, str("title"), str("userType"), str("preferredLanguage"), str("locale"), str("timezone"), boolean("active"),
				typedValue("emails"), typedValue("phoneNumbers"),
				multi("addresses", str("formatted"), str("streetAddress"), str("locality"), str("region"), str("postalCode"), str("country"), str("type"), boolean("primary")),
				typedValue("roles"), typedValue("entitlements")}},
		{Schemas: []string{SchemaSchema}, ID: SchemaEnterpriseUser, Name: "EnterpriseUser", Description: "Enterprise User", Meta: docMeta{ResourceType: "Schema"},
			Attributes: []attr{str("employeeNumber"), str("costCenter"), str("organization"), str("division"), str("department"),
				complexAttr("manager", str("value"), str("$ref"))}},
		{Schemas: []string{SchemaSchema}, ID: SchemaGroup, Name: "Group", Description: "Group", Meta: docMeta{ResourceType: "Schema"},
			Attributes: []attr{id, ext, groupName, multi("members", str("value"), str("display"), str("type"), str("$ref"))}},
	}
}

// resourceType is a published resource type.
type resourceType struct {
	Schemas          []string          `json:"schemas"`
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Endpoint         string            `json:"endpoint"`
	Description      string            `json:"description"`
	Schema           string            `json:"schema"`
	SchemaExtensions []schemaExtension `json:"schemaExtensions,omitempty"`
	Meta             docMeta           `json:"meta"`
}

// schemaExtension names an extension a resource type accepts.
type schemaExtension struct {
	Schema   string `json:"schema"`
	Required bool   `json:"required"`
}

// resourceTypes are User and Group.
func resourceTypes() []resourceType {
	return []resourceType{
		{Schemas: []string{SchemaResourceType}, ID: "User", Name: "User", Endpoint: pathUsers, Description: "User Account", Schema: SchemaUser,
			SchemaExtensions: []schemaExtension{{Schema: SchemaEnterpriseUser}}, Meta: docMeta{ResourceType: "ResourceType"}},
		{Schemas: []string{SchemaResourceType}, ID: "Group", Name: "Group", Endpoint: pathGroups, Description: "Group", Schema: SchemaGroup,
			Meta: docMeta{ResourceType: "ResourceType"}},
	}
}

// supported is a ServiceProviderConfig feature flag.
type supported struct {
	Supported bool `json:"supported"`
}

// spConfig is the ServiceProviderConfig document: PATCH and filters yes,
// weak ETags on users (meta.version, If-Match); bulk, password change and
// sort no; bearer tokens.
func spConfig() map[string]any {
	return map[string]any{
		"schemas":          []string{SchemaSPConfig},
		"documentationUri": "https://github.com/ubgo/auth/blob/main/docs/plugins/scim.md",
		"patch":            supported{true},
		"bulk":             map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           map[string]any{"supported": true, "maxResults": MaxPageSize},
		"changePassword":   supported{false},
		"sort":             supported{false},
		"etag":             supported{true},
		"authenticationSchemes": []map[string]any{{
			"type": "oauthbearertoken", "name": "OAuth Bearer Token", "primary": true,
			"description": "Authentication with a bearer token issued for the SCIM connection",
		}},
		"meta": docMeta{ResourceType: "ServiceProviderConfig"},
	}
}

// discovery answers the public documents: ok is false for any other path,
// and the document is nil for an unknown schema or resource type.
func (p *Plugin) discovery(_ *http.Request, path string) (any, bool) {
	switch {
	case path == pathSPConfig:
		return spConfig(), true
	case path == pathSchemas:
		list := schemas()
		docs := make([]any, len(list))
		for i := range list {
			docs[i] = list[i]
		}
		return map[string]any{"schemas": []string{SchemaListResponse}, "totalResults": len(list), "startIndex": 1, "itemsPerPage": len(list), "Resources": docs}, true
	case strings.HasPrefix(path, pathSchemas+"/"):
		id := strings.TrimPrefix(path, pathSchemas+"/")
		for _, s := range schemas() {
			if s.ID == id {
				return s, true
			}
		}
		return nil, true
	case path == pathResourceTypes:
		list := resourceTypes()
		docs := make([]any, len(list))
		for i := range list {
			docs[i] = list[i]
		}
		return map[string]any{"schemas": []string{SchemaListResponse}, "totalResults": len(list), "startIndex": 1, "itemsPerPage": len(list), "Resources": docs}, true
	case strings.HasPrefix(path, pathResourceTypes+"/"):
		id := strings.TrimPrefix(path, pathResourceTypes+"/")
		for _, rt := range resourceTypes() {
			if rt.ID == id {
				return rt, true
			}
		}
		return nil, true
	}
	return nil, false
}
