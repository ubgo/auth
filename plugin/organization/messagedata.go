package organization

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
)

// InvitationData is the typed payload of every PurposeInvite message
// (auth.Message.Data): what better-auth hands its sendInvitationEmail
// (invitation id, role, invited address, the organization, the inviter), for
// an app template to read with
//
//	d, ok := m.Data.(organization.InvitationData)
//
// instead of parsing the default wording. The link is Message.Link. Through
// auth.WithDeliveryOutbox the value comes back as this type, restored by the
// plugin's DecodeMessageData.
//
// InviterEmail is the inviter's primary verified address, "" when they have
// none: the invitee is told who invited them, as better-auth's template is.
type InvitationData struct {
	InvitationID string `json:"invitationId"`
	// Email is the invited address of an email invitation, "" for another
	// kind; Kind and Identifier address every invitation.
	Email            string                  `json:"email"`
	Kind             auth.IdentifierKindName `json:"kind"`
	Identifier       string                  `json:"identifier"`
	Role             Role                    `json:"role"`
	TeamID           *string                 `json:"teamId,omitempty"`
	ExpiresAt        time.Time               `json:"expiresAt"`
	OrganizationID   string                  `json:"organizationId"`
	OrganizationName string                  `json:"organizationName"`
	OrganizationSlug string                  `json:"organizationSlug"`
	OrganizationLogo *string                 `json:"organizationLogo,omitempty"`
	InviterID        string                  `json:"inviterId"`
	InviterName      string                  `json:"inviterName"`
	InviterEmail     string                  `json:"inviterEmail,omitempty"`
}

var _ auth.MessageDataDecoder = (*Plugin)(nil)

// DecodeMessageData restores an InvitationData the delivery outbox stored as
// JSON. Any other purpose is not this plugin's: (nil, nil).
func (p *Plugin) DecodeMessageData(purpose auth.Purpose, raw json.RawMessage) (any, error) {
	if purpose != PurposeInvite {
		return nil, nil
	}
	var d InvitationData
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	return d, nil
}

// invitationData builds the payload of row's mail, sent by inviter.
func (p *Plugin) invitationData(ctx context.Context, row Invitation, org Org, inviter auth.User) (InvitationData, error) {
	addr, err := p.primaryEmail(ctx, inviter.ID)
	if err != nil {
		return InvitationData{}, err
	}
	return InvitationData{
		InvitationID: row.ID, Email: row.Email, Kind: row.Kind, Identifier: row.Identifier, Role: row.Role, TeamID: row.TeamID, ExpiresAt: row.ExpiresAt,
		OrganizationID: org.ID, OrganizationName: org.Name, OrganizationSlug: org.Slug, OrganizationLogo: org.Logo,
		InviterID: inviter.ID, InviterName: inviter.Name, InviterEmail: addr,
	}, nil
}

// primaryEmail is userID's primary verified address, else the first verified
// one, else "".
func (p *Plugin) primaryEmail(ctx context.Context, userID string) (string, error) {
	ids, err := p.core.VerifiedIdentities(ctx, userID, email.KindEmail)
	if err != nil || len(ids) == 0 {
		return "", err
	}
	for _, idn := range ids {
		if idn.IsPrimary {
			return idn.Value, nil
		}
	}
	return ids[0].Value, nil
}
