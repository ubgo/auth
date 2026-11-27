package oauthprovider

import (
	"context"
	"encoding/json"
	"time"
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
	return p.store.SetReplay(ctx, rowID, ReplayRecord{Sealed: sealed, ExpiresAt: p.core.Now().Add(p.refreshReuse)})
}

// replayed answers a reuse inside the window from the stored response:
// found false when nothing usable is stored (the caller issues a new pair,
// as without RefreshReplay), ErrInvalidGrant when the reuse asks for
// something else than the first use did, refused without revoking the
// family.
//
// The store's Replay reads the newest committed record (a locking read in
// the SQL store), for the reason refresh's re-read does: the response was
// stored by the request that rotated the token, which may have committed
// while this transaction was open, and a stale read would miss it and issue
// a second pair.
func (p *Plugin) replayed(ctx context.Context, rowID string, in TokenRequest, now time.Time) (TokenResponse, bool, error) {
	stored, found, err := p.store.Replay(ctx, rowID)
	if err != nil {
		return TokenResponse{}, false, err
	}
	if !found || !now.Before(stored.ExpiresAt) {
		return TokenResponse{}, false, nil
	}
	plain, err := p.replay.Decrypt(stored.Sealed)
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
