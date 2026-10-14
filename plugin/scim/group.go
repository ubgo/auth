package scim

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Group is a SCIM group resource (RFC 7643 §4.2). Members are users of the
// same connection; nested groups are refused.
//
//ds:def id=scim-group-6v2qm8xn owner=@khanakia stability=stable
type Group struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id,omitempty"`
	ExternalID  string   `json:"externalId,omitempty"`
	DisplayName string   `json:"displayName"`
	Members     []Member `json:"members,omitempty"`
	Meta        *Meta    `json:"meta,omitempty"`
}

// Member is one group member: Value is the SCIM user id.
type Member struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"`
	Ref     string `json:"$ref,omitempty"`
}

// memberTypeUser is the only member type; groups do not nest.
const memberTypeUser = "User"

// decodeGroup turns a request document into a validated Group, with
// duplicate members collapsed.
func decodeGroup(doc map[string]any) (Group, error) {
	// doc came out of json.Unmarshal (and PATCH, which copies values of
	// the same kinds), so it always marshals.
	b, _ := json.Marshal(doc)
	var g Group
	if err := json.Unmarshal(b, &g); err != nil {
		return Group{}, errorf(http.StatusBadRequest, InvalidValue, "An attribute has the wrong type: "+err.Error())
	}
	g.ID, g.Meta = "", nil
	g.DisplayName = strings.TrimSpace(g.DisplayName)
	if err := checkSchemas(g.Schemas, SchemaGroup); err != nil {
		return Group{}, err
	}
	if g.DisplayName == "" || len(g.DisplayName) > maxLongString || len(g.ExternalID) > maxLongString {
		return Group{}, invalid(fmt.Sprintf("displayName is required; displayName and externalId are at most %d characters", maxLongString))
	}
	seen := map[string]bool{}
	members := g.Members[:0:0]
	for _, m := range g.Members {
		if m.Value == "" || (m.Type != "" && !strings.EqualFold(m.Type, memberTypeUser)) {
			return Group{}, invalid("a member is a User with a value")
		}
		if seen[m.Value] {
			continue
		}
		seen[m.Value] = true
		members = append(members, Member{Value: m.Value, Type: memberTypeUser})
	}
	if len(members) > MaxGroupMembers {
		return Group{}, errorf(http.StatusBadRequest, TooMany, "a group has at most 1000 members")
	}
	g.Members = members
	return g, nil
}
