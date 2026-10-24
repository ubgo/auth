package webhook

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// EventType names what a webhook reports, full-stop delimited as the spec
// asks. The constants are what the plugin emits on its own; Publish sends any
// other valid type, and security events are SecurityEventPrefix plus the
// auth.SecurityKind.
type EventType = string

// Event types the plugin emits.
const (
	// EventUserCreated: a user row was created (sign-up, import, an admin).
	// Data is UserData.
	EventUserCreated EventType = "user.created"
	// EventUserUpdated: the user's profile (name, image) changed. Data is
	// UserData, the new values.
	EventUserUpdated EventType = "user.updated"
	// EventUserDeleted: the user is being deleted; sent only if the
	// deletion commits. Data is UserData as it was.
	EventUserDeleted EventType = "user.deleted"
	// EventSessionCreated: a session that signs someone in was created.
	// A session still waiting for a second factor is not reported; the
	// full session that replaces it is. Data is SessionData.
	EventSessionCreated EventType = "session.created"
	// EventSessionRevoked: a session ended before the user let it expire, for
	// any reason (sign-out, revoke, an admin, a ban, a password change,
	// token-reuse theft, user deletion) or was removed by the expiry sweep.
	// Data is SessionRevokedData: SessionData plus the reason.
	EventSessionRevoked EventType = "session.revoked"
	// EventIdentityCreated, EventIdentityUpdated and EventIdentityDeleted:
	// an email address, phone number or username was added, changed
	// (verified, made primary) or removed. Data is IdentityData.
	EventIdentityCreated EventType = "identity.created"
	EventIdentityUpdated EventType = "identity.updated"
	EventIdentityDeleted EventType = "identity.deleted"
	// SecurityEventPrefix starts the type of every security event the
	// plugin's SecuritySink forwards: "security.rate.limit",
	// "security.credential.stuffing", … Data is SecurityData.
	SecurityEventPrefix = "security."
)

// EventTypeValues lists the fixed types the plugin emits, for an admin screen
// that offers them as filters. Security events add SecurityEventPrefix plus
// each auth.SecurityKindValues entry.
var EventTypeValues = []EventType{
	EventUserCreated, EventUserUpdated, EventUserDeleted, EventSessionCreated, EventSessionRevoked,
	EventIdentityCreated, EventIdentityUpdated, EventIdentityDeleted,
}

// Shapes of event types and filters. A type is lower-case words joined by
// dots; a filter is a type, a type prefix ending ".*", or "*" for all.
// The dot-free alphabet also keeps a type safe inside the signed content.
var (
	eventTypePattern   = regexp.MustCompile(`^[a-z0-9_-]+(\.[a-z0-9_-]+)*$`)
	eventFilterPattern = regexp.MustCompile(`^(\*|[a-z0-9_-]+(\.[a-z0-9_-]+)*(\.\*)?)$`)
)

// maxEventTypeLength fits a type in its Key column on every engine.
const maxEventTypeLength = 191

// validType reports whether t can be an event type.
func validType(t string) bool { return len(t) <= maxEventTypeLength && eventTypePattern.MatchString(t) }

// matches reports whether an endpoint with filters wants an event of type t.
// No filter means every event.
func matches(filters []string, t string) bool {
	if len(filters) == 0 {
		return true
	}
	for _, f := range filters {
		if f == "*" || f == t {
			return true
		}
		if prefix, ok := strings.CutSuffix(f, "*"); ok && strings.HasPrefix(t, prefix) {
			return true
		}
	}
	return false
}

// Envelope is the JSON body of every webhook, the spec's payload structure.
type Envelope struct {
	Type EventType `json:"type"`
	// Timestamp is when the event happened, not when this attempt was sent
	// (that is the webhook-timestamp header).
	Timestamp time.Time `json:"timestamp"`
	Data      any       `json:"data"`
}

// UserData is the data of the user.* events: the profile, never a credential.
type UserData struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Image     string    `json:"image"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// SessionData is the data of the session.* events. It never carries the
// token. IP is empty under auth.WithoutIPTracking.
type SessionData struct {
	ID             string    `json:"id"`
	UserID         string    `json:"userId"`
	CreatedAt      time.Time `json:"createdAt"`
	ExpiresAt      time.Time `json:"expiresAt"`
	IP             string    `json:"ip,omitempty"`
	UserAgent      string    `json:"userAgent,omitempty"`
	ImpersonatedBy string    `json:"impersonatedBy,omitempty"`
}

// SessionRevokedData is the data of session.revoked: the session and why it
// ended. Reason is an auth.SessionEndReason string ("sign_out", "revoked",
// "admin_revoked", "banned", "password_changed", "token_reuse",
// "user_deleted", "expired", …; auth.SessionEndReasonValues lists them). For
// "sign out everywhere" in stateless mode, where the server holds no list of
// sessions, ID is empty and the event means every session of UserID.
type SessionRevokedData struct {
	SessionData
	Reason string `json:"reason"`
}

// IdentityData is the data of the identity.* events.
type IdentityData struct {
	ID         string     `json:"id"`
	UserID     string     `json:"userId"`
	Kind       string     `json:"kind"`
	Value      string     `json:"value"`
	Verified   bool       `json:"verified"`
	VerifiedAt *time.Time `json:"verifiedAt,omitempty"`
	IsPrimary  bool       `json:"isPrimary"`
}

// SecurityData is the data of the security.* events: auth.SecurityEvent,
// which already carries no password, token or code, with JSON names.
type SecurityData struct {
	ID        string            `json:"id"`
	Kind      string            `json:"kind"`
	Severity  string            `json:"severity"`
	Outcome   string            `json:"outcome"`
	Op        string            `json:"op,omitempty"`
	Plugin    string            `json:"plugin,omitempty"`
	Transport string            `json:"transport,omitempty"`
	UserID    string            `json:"userId,omitempty"`
	IP        string            `json:"ip,omitempty"`
	Attrs     map[string]string `json:"attrs,omitempty"`
}

func userData(u auth.User) UserData {
	return UserData{ID: u.ID, Name: u.Name, Image: u.Image, CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt}
}

func (p *Plugin) sessionData(s auth.Session) SessionData {
	d := SessionData{ID: s.ID, UserID: s.UserID, CreatedAt: s.CreatedAt, ExpiresAt: s.ExpiresAt, UserAgent: s.UserAgent}
	if p.core.TracksIP() {
		d.IP = s.IP
	}
	if s.ImpersonatedBy != nil {
		d.ImpersonatedBy = *s.ImpersonatedBy
	}
	return d
}

func (p *Plugin) sessionRevokedData(e auth.SessionEnd) SessionRevokedData {
	return SessionRevokedData{SessionData: p.sessionData(e.Session), Reason: string(e.Reason)}
}

func identityData(i auth.Identity) IdentityData {
	return IdentityData{ID: i.ID, UserID: i.UserID, Kind: string(i.Kind), Value: i.Value, Verified: i.VerifiedAt != nil, VerifiedAt: i.VerifiedAt, IsPrimary: i.IsPrimary}
}

// DataHooks turn core writes into events. Each runs inside the writing
// transaction, so its delivery rows commit or roll back with the write.
func (p *Plugin) DataHooks() auth.DataHooks {
	return auth.DataHooks{
		User: auth.TableHooks[auth.User]{
			AfterCreate: func(ctx context.Context, _ sqlb.DBTX, u *auth.User) error {
				return p.enqueue(ctx, EventUserCreated, userData(*u))
			},
			AfterUpdate: func(ctx context.Context, _ sqlb.DBTX, _, u *auth.User) error {
				return p.enqueue(ctx, EventUserUpdated, userData(*u))
			},
			BeforeDelete: func(ctx context.Context, _ sqlb.DBTX, u *auth.User) error {
				return p.enqueue(ctx, EventUserDeleted, userData(*u))
			},
		},
		Session: auth.TableHooks[auth.Session]{
			AfterCreate: func(ctx context.Context, _ sqlb.DBTX, s *auth.Session) error {
				if s.SecondFactorPending || s.APIKeyID != "" {
					return nil
				}
				return p.enqueue(ctx, EventSessionCreated, p.sessionData(*s))
			},
		},
		// Every end of a signed-in session, with its reason (auth.SessionEnd).
		// API-key sessions are not sign-ins and are not reported, as for
		// session.created.
		SessionEnded: func(ctx context.Context, _ sqlb.DBTX, e auth.SessionEnd) error {
			if e.Session.APIKeyID != "" {
				return nil
			}
			return p.enqueue(ctx, EventSessionRevoked, p.sessionRevokedData(e))
		},
		Identity: auth.TableHooks[auth.Identity]{
			AfterCreate: func(ctx context.Context, _ sqlb.DBTX, i *auth.Identity) error {
				return p.enqueue(ctx, EventIdentityCreated, identityData(*i))
			},
			AfterUpdate: func(ctx context.Context, _ sqlb.DBTX, _, i *auth.Identity) error {
				return p.enqueue(ctx, EventIdentityUpdated, identityData(*i))
			},
			BeforeDelete: func(ctx context.Context, _ sqlb.DBTX, i *auth.Identity) error {
				return p.enqueue(ctx, EventIdentityDeleted, identityData(*i))
			},
		},
	}
}

// Publish sends an event of the app's own, or another plugin's, to every
// endpoint subscribed to eventType: an organization hook, a billing change,
// anything. It joins the transaction in ctx (auth.Tx), so the event is sent
// only if that transaction commits; outside one it is written at once. data
// is marshalled to JSON now. eventType must be lower-case words joined by
// dots ("org.member.added").
func (p *Plugin) Publish(ctx context.Context, eventType EventType, data any) error {
	if !validType(eventType) {
		return ErrBadEventType
	}
	return p.core.Tx(ctx, func(ctx context.Context, _ sqlbTx) error {
		return p.enqueue(ctx, eventType, data)
	})
}

// SecuritySink returns the sink that forwards the security event stream as
// security.* webhooks. Register it with auth.WithSecuritySink:
//
//	hooks := webhook.New()
//	a, err := auth.New(auth.WithPlugins(hooks, ...),
//		auth.WithSecuritySink(hooks.SecuritySink(), auth.SecurityQueue{Name: "webhook"}))
//
// The stream is not durable and may drop events under pressure (see
// auth.WithSecuritySink); once an event reaches this sink its deliveries are
// written to the table and retried like any other.
func (p *Plugin) SecuritySink() auth.SecuritySink {
	return auth.SecuritySinkFunc(func(ctx context.Context, batch []auth.SecurityEvent) error {
		if p.core == nil {
			return nil
		}
		for _, ev := range batch {
			t := SecurityEventPrefix + string(ev.Kind)
			if !validType(t) {
				p.core.Logger().Warn("webhook: security event kind is not a valid event type; not sent", "kind", string(ev.Kind))
				continue
			}
			data := SecurityData{ID: ev.ID, Kind: string(ev.Kind), Severity: string(ev.Severity), Outcome: string(ev.Outcome),
				Op: string(ev.Op), Plugin: ev.Plugin, Transport: string(ev.Transport), UserID: ev.UserID, IP: ev.IP, Attrs: ev.Attrs}
			at := ev.At
			if err := p.core.Tx(ctx, func(ctx context.Context, _ sqlbTx) error {
				return p.enqueueAt(ctx, t, at, data)
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

// enqueue is enqueueAt at the core clock's now.
func (p *Plugin) enqueue(ctx context.Context, t EventType, data any) error {
	return p.enqueueAt(ctx, t, p.core.Now(), data)
}

// enqueueAt writes one pending delivery per enabled endpoint whose filter
// matches t, in the transaction in ctx, and schedules their first send after
// the commit. A rollback discards the rows and runs nothing. With no matching
// endpoint it writes nothing and builds no payload.
func (p *Plugin) enqueueAt(ctx context.Context, t EventType, at time.Time, data any) error {
	eps, err := p.listEndpoints(ctx, true)
	if err != nil {
		return err
	}
	var targets []string
	for _, ep := range eps {
		if matches(ep.Events, t) {
			targets = append(targets, ep.ID)
		}
	}
	if len(targets) == 0 {
		return nil
	}
	body, err := json.Marshal(Envelope{Type: t, Timestamp: at.UTC(), Data: data})
	if err != nil {
		return fmt.Errorf("webhook: encode %s: %w", t, err)
	}
	msgID := newMessageID()
	ids := make([]string, 0, len(targets))
	for _, epID := range targets {
		id, err := p.insertDelivery(ctx, msgID, epID, t, string(body))
		if err != nil {
			return err
		}
		ids = append(ids, id)
	}
	p.sendAfterCommit(ctx, ids...)
	return nil
}

// messageIDBytes is the random part of a message id: 128 bits.
const messageIDBytes = 16

// messageIDPrefix starts every webhook-id, as Svix's do, so a receiver's log
// line says what the id is.
const messageIDPrefix = "msg_"

// newMessageID makes a webhook-id. The plugin makes its own rather than using
// auth.NewID, because an app's WithIDs generator may produce a ".", which the
// spec forbids in the id (it would make the signed content ambiguous).
func newMessageID() string {
	b := make([]byte, messageIDBytes)
	_, _ = rand.Read(b) // crypto/rand.Read is documented never to return an error
	return messageIDPrefix + hex.EncodeToString(b)
}
