package oauthprovider

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ubgo/sqlb"
)

// replayRecord is what RefreshReplay stores on a rotated token row: the
// response its first use got, and the request it answered, so a reuse can
// be told apart from a different request.
type replayRecord struct {
	Response replayResponse `json:"response"`
	Extra    map[string]any `json:"extra,omitempty"`
	Scope    string         `json:"scope"`
	Resource string         `json:"resource"`
	Proof    bool           `json:"proof"`
}

// replayResponse is TokenResponse without its MarshalJSON, so the fields
// round-trip and Extra is kept beside it.
type replayResponse TokenResponse

// replayFingerprint is the part of a refresh request a replay must match.
func replayFingerprint(in TokenRequest) (scope, resource string, proof bool) {
	return in.Scope, in.Resource, in.DPoPProof != ""
}

// storeReplay seals res onto the rotated row until the reuse window ends.
func (p *Plugin) storeReplay(ctx context.Context, rowID string, in TokenRequest, res TokenResponse) error {
	scope, resource, proof := replayFingerprint(in)
	b, _ := json.Marshal(replayRecord{Response: replayResponse(res), Extra: res.Extra, Scope: scope, Resource: resource, Proof: proof}) // plain strings and the TokenResponseFields map, which already encoded once
	sealed, err := p.replay.Encrypt(string(b))
	if err != nil {
		return err
	}
	exp := p.core.Now().Add(p.refreshReuse)
	_, err = p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableToken).Set(
		sqlb.Set(TokenReplay, &sealed), sqlb.Set(TokenReplayExpires, &exp)).Where(sqlb.Eq(TokenID, rowID)))
	return err
}

// replayed answers a reuse inside the window from the stored response:
// found false when nothing usable is stored (the caller issues a new pair,
// as without RefreshReplay), ErrInvalidGrant when the reuse asks for
// something else than the first use did, which better-auth refuses without
// revoking the family.
func (p *Plugin) replayed(ctx context.Context, rowID string, in TokenRequest, now time.Time) (TokenResponse, bool, error) {
	var sealed *string
	var exp *time.Time
	if err := p.core.One(ctx, p.core.Select().Columns(sqlb.Bind(TokenReplay, &sealed), sqlb.Bind(TokenReplayExpires, &exp)).From(TableToken).Where(sqlb.Eq(TokenID, rowID))); err != nil {
		return TokenResponse{}, false, err
	}
	if sealed == nil || exp == nil || !now.Before(*exp) {
		return TokenResponse{}, false, nil
	}
	plain, err := p.replay.Decrypt(*sealed)
	var rec replayRecord
	if err != nil || json.Unmarshal([]byte(plain), &rec) != nil {
		// A record the key no longer opens is treated as absent.
		return TokenResponse{}, false, nil
	}
	scope, resource, proof := replayFingerprint(in)
	if rec.Scope != scope || rec.Resource != resource || rec.Proof != proof {
		return TokenResponse{}, false, ErrInvalidGrant
	}
	res := TokenResponse(rec.Response)
	res.Extra = rec.Extra
	return res, true, nil
}
