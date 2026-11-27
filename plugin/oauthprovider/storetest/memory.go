package storetest

import (
	"bytes"
	"context"
	"encoding/hex"
	"maps"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ubgo/auth/plugin/oauthprovider"
)

// MemoryStore is an oauthprovider.Store in this process's memory: the
// reference the suite proves itself against, and a stand-in for an app's
// own unit tests. It is not for production: nothing survives a restart, two
// instances of an app never see each other's tokens, and nothing is ever
// expired except by Sweep. One lock guards everything, which is what makes
// every method atomic.
type MemoryStore struct {
	mu       sync.Mutex
	clients  map[string]oauthprovider.ClientRecord
	codes    map[string]oauthprovider.CodeRecord
	tokens   map[string]oauthprovider.TokenRecord
	byAccess map[string]string
	byRefsh  map[string]string
	replays  map[string]oauthprovider.ReplayRecord
	consents map[string]oauthprovider.ConsentRecord
	// flaw breaks one rule, for the suite's own tests; flawNone in every
	// store NewMemoryStore returns.
	flaw flaw
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		clients: map[string]oauthprovider.ClientRecord{}, codes: map[string]oauthprovider.CodeRecord{},
		tokens: map[string]oauthprovider.TokenRecord{}, byAccess: map[string]string{}, byRefsh: map[string]string{},
		replays: map[string]oauthprovider.ReplayRecord{}, consents: map[string]oauthprovider.ConsentRecord{},
	}
}

var _ oauthprovider.Store = (*MemoryStore)(nil)

// key is the map key of a hash.
func key(h []byte) string { return hex.EncodeToString(h) }

// pause lets racing goroutines interleave inside a flawed, non-atomic step.
func pause() {
	runtime.Gosched()
	time.Sleep(time.Millisecond)
}

// The copies keep a caller from changing a stored record through a slice it
// passed in or got back.
func cloneClient(c oauthprovider.ClientRecord) oauthprovider.ClientRecord {
	c.SecretHash = bytes.Clone(c.SecretHash)
	return c
}

func cloneCode(c oauthprovider.CodeRecord) oauthprovider.CodeRecord {
	c.Hash = bytes.Clone(c.Hash)
	return c
}

func cloneToken(t oauthprovider.TokenRecord) oauthprovider.TokenRecord {
	t.AccessHash, t.RefreshHash = bytes.Clone(t.AccessHash), bytes.Clone(t.RefreshHash)
	return t
}

// Client implements oauthprovider.Store.
func (m *MemoryStore) Client(_ context.Context, id string) (oauthprovider.ClientRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.clients[id]
	if !ok {
		return oauthprovider.ClientRecord{}, oauthprovider.ErrRecordNotFound
	}
	if m.flaw == flawDropsField {
		c.SecretEncrypted = nil
	}
	return cloneClient(c), nil
}

// InsertClient implements oauthprovider.Store.
func (m *MemoryStore) InsertClient(_ context.Context, c oauthprovider.ClientRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.clients[c.ID]; ok && m.flaw != flawInsertOverwrites {
		return oauthprovider.ErrRecordExists
	}
	m.clients[c.ID] = cloneClient(c)
	return nil
}

// UpdateClient implements oauthprovider.Store.
func (m *MemoryStore) UpdateClient(_ context.Context, u oauthprovider.ClientUpdate) (bool, error) {
	if len(u.Fields) == 0 {
		return false, oauthprovider.ErrBadClientField
	}
	m.mu.Lock()
	c, ok := m.clients[u.ID]
	if !ok || (u.IfDiscovery != nil && (c.Discovery == nil || *c.Discovery != *u.IfDiscovery)) {
		m.mu.Unlock()
		return false, nil
	}
	switch m.flaw {
	case flawUpdateWholeRecord:
		r := cloneClient(u.Record)
		r.ID, r.CreatedAt, r.Discovery = c.ID, c.CreatedAt, c.Discovery
		m.clients[u.ID] = r
		m.mu.Unlock()
		return true, nil
	case flawUpdateNonAtomic:
		m.mu.Unlock()
		pause()
		if err := u.Apply(&c); err != nil {
			return false, err
		}
		m.mu.Lock()
		m.clients[u.ID] = cloneClient(c)
		m.mu.Unlock()
		return true, nil
	}
	defer m.mu.Unlock()
	if err := u.Apply(&c); err != nil {
		return false, err
	}
	m.clients[u.ID] = cloneClient(c)
	return true, nil
}

// DeleteClient implements oauthprovider.Store.
func (m *MemoryStore) DeleteClient(_ context.Context, id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.clients[id]
	delete(m.clients, id)
	for k, c := range m.codes {
		if c.ClientID == id {
			delete(m.codes, k)
		}
	}
	if m.flaw != flawDeleteClientKeepsTokens {
		for _, t := range m.tokens {
			if t.ClientID == id {
				m.dropToken(t)
			}
		}
	}
	for k, c := range m.consents {
		if c.ClientID == id {
			delete(m.consents, k)
		}
	}
	return ok, nil
}

// clientMatches reports whether c passes f.
func clientMatches(f oauthprovider.ClientFilter, c oauthprovider.ClientRecord) bool {
	if f.OwnerID != nil && (c.OwnerID == nil || *c.OwnerID != *f.OwnerID) {
		return false
	}
	return f.ReferenceID == nil || (c.ReferenceID != nil && *c.ReferenceID == *f.ReferenceID)
}

// Clients implements oauthprovider.Store.
func (m *MemoryStore) Clients(_ context.Context, f oauthprovider.ClientFilter) ([]oauthprovider.ClientRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []oauthprovider.ClientRecord{}
	for _, c := range m.clients {
		if clientMatches(f, c) {
			out = append(out, cloneClient(c))
		}
	}
	slices.SortFunc(out, func(a, b oauthprovider.ClientRecord) int {
		if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out, nil
}

// CountClients implements oauthprovider.Store.
func (m *MemoryStore) CountClients(ctx context.Context, f oauthprovider.ClientFilter) (int64, error) {
	all, err := m.Clients(ctx, f)
	return int64(len(all)), err
}

// InsertCode implements oauthprovider.Store.
func (m *MemoryStore) InsertCode(_ context.Context, c oauthprovider.CodeRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.codes[key(c.Hash)]; ok {
		return oauthprovider.ErrRecordExists
	}
	m.codes[key(c.Hash)] = cloneCode(c)
	return nil
}

// RedeemCode implements oauthprovider.Store.
func (m *MemoryStore) RedeemCode(_ context.Context, hash []byte, now time.Time) (oauthprovider.CodeRecord, bool, error) {
	m.mu.Lock()
	c, ok := m.codes[key(hash)]
	if !ok {
		m.mu.Unlock()
		return oauthprovider.CodeRecord{}, false, oauthprovider.ErrRecordNotFound
	}
	switch m.flaw {
	case flawRedeemReusable:
		m.mu.Unlock()
		c.ConsumedAt = &now
		return cloneCode(c), true, nil
	case flawRedeemNonAtomic:
		m.mu.Unlock()
		if c.ConsumedAt != nil {
			return cloneCode(c), false, nil
		}
		pause()
		c.ConsumedAt = &now
		m.mu.Lock()
		m.codes[key(hash)] = c
		m.mu.Unlock()
		return cloneCode(c), true, nil
	}
	defer m.mu.Unlock()
	if c.ConsumedAt != nil {
		return cloneCode(c), false, nil
	}
	c.ConsumedAt = &now
	m.codes[key(hash)] = c
	return cloneCode(c), true, nil
}

// RestoreCode implements oauthprovider.Store.
func (m *MemoryStore) RestoreCode(_ context.Context, hash []byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.codes[key(hash)]
	if !ok || c.ConsumedAt == nil {
		return false, nil
	}
	c.ConsumedAt = nil
	m.codes[key(hash)] = c
	return true, nil
}

// BurnCode implements oauthprovider.Store.
func (m *MemoryStore) BurnCode(_ context.Context, hash []byte, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.codes[key(hash)]
	if !ok || c.ConsumedAt != nil || m.flaw == flawBurnDoesNothing {
		return false, nil
	}
	c.ConsumedAt = &now
	m.codes[key(hash)] = c
	return true, nil
}

// DeleteCodes implements oauthprovider.Store.
func (m *MemoryStore) DeleteCodes(_ context.Context, f oauthprovider.CodeFilter) (int64, error) {
	if f.Empty() {
		return 0, oauthprovider.ErrEmptyFilter
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for k, c := range m.codes {
		if (f.UserID != "" && c.UserID != f.UserID) || (f.ClientID != "" && c.ClientID != f.ClientID) {
			continue
		}
		if f.OnlyUnredeemed && c.ConsumedAt != nil && m.flaw != flawDeleteCodesIgnoresRedeemed {
			continue
		}
		delete(m.codes, k)
		n++
	}
	return n, nil
}

// InsertToken implements oauthprovider.Store.
func (m *MemoryStore) InsertToken(_ context.Context, t oauthprovider.TokenRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tokens[t.ID]; ok {
		return oauthprovider.ErrRecordExists
	}
	if _, ok := m.byAccess[key(t.AccessHash)]; ok {
		return oauthprovider.ErrRecordExists
	}
	if t.RefreshHash != nil {
		if _, ok := m.byRefsh[key(t.RefreshHash)]; ok {
			return oauthprovider.ErrRecordExists
		}
		m.byRefsh[key(t.RefreshHash)] = t.ID
	}
	m.byAccess[key(t.AccessHash)] = t.ID
	m.tokens[t.ID] = cloneToken(t)
	return nil
}

// dropToken removes t and its indexes; the caller holds the lock.
func (m *MemoryStore) dropToken(t oauthprovider.TokenRecord) {
	delete(m.tokens, t.ID)
	delete(m.byAccess, key(t.AccessHash))
	if t.RefreshHash != nil {
		delete(m.byRefsh, key(t.RefreshHash))
	}
	delete(m.replays, t.ID)
}

// tokenBy reads a token through an index.
func (m *MemoryStore) tokenBy(index map[string]string, hash []byte) (oauthprovider.TokenRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := index[key(hash)]
	if !ok {
		return oauthprovider.TokenRecord{}, oauthprovider.ErrRecordNotFound
	}
	return cloneToken(m.tokens[id]), nil
}

// TokenByAccessHash implements oauthprovider.Store.
func (m *MemoryStore) TokenByAccessHash(_ context.Context, hash []byte) (oauthprovider.TokenRecord, error) {
	return m.tokenBy(m.byAccess, hash)
}

// TokenByRefreshHash implements oauthprovider.Store.
func (m *MemoryStore) TokenByRefreshHash(_ context.Context, hash []byte) (oauthprovider.TokenRecord, error) {
	return m.tokenBy(m.byRefsh, hash)
}

// RotateRefresh implements oauthprovider.Store.
func (m *MemoryStore) RotateRefresh(_ context.Context, hash []byte, now time.Time) (oauthprovider.TokenRecord, bool, error) {
	m.mu.Lock()
	id, ok := m.byRefsh[key(hash)]
	if !ok {
		m.mu.Unlock()
		return oauthprovider.TokenRecord{}, false, oauthprovider.ErrRecordNotFound
	}
	t := m.tokens[id]
	spent := t.RotatedAt != nil || (t.RevokedAt != nil && m.flaw != flawRotateRevoked)
	switch m.flaw {
	case flawRotateNonAtomic:
		m.mu.Unlock()
		if spent {
			return cloneToken(t), false, nil
		}
		pause()
		t.RotatedAt = &now
		m.mu.Lock()
		m.tokens[id] = t
		m.mu.Unlock()
		return cloneToken(t), true, nil
	case flawRotateStale:
		if spent {
			stale := t
			stale.RotatedAt = nil
			m.mu.Unlock()
			return cloneToken(stale), false, nil
		}
	}
	defer m.mu.Unlock()
	if spent {
		return cloneToken(t), false, nil
	}
	t.RotatedAt = &now
	m.tokens[id] = t
	return cloneToken(t), true, nil
}

// RestoreRefresh implements oauthprovider.Store.
func (m *MemoryStore) RestoreRefresh(_ context.Context, hash []byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byRefsh[key(hash)]
	if !ok {
		return false, nil
	}
	t := m.tokens[id]
	if t.RotatedAt == nil || (t.RevokedAt != nil && m.flaw != flawRestoreRevoked) {
		return false, nil
	}
	t.RotatedAt = nil
	m.tokens[id] = t
	return true, nil
}

// tokenMatches reports whether t passes f.
func tokenMatches(f oauthprovider.TokenFilter, t oauthprovider.TokenRecord) bool {
	switch {
	case f.ID != "" && t.ID != f.ID,
		f.Family != "" && t.Family != f.Family,
		f.UserID != "" && (t.UserID == nil || *t.UserID != f.UserID),
		f.ClientID != "" && t.ClientID != f.ClientID,
		f.SessionID != "" && (t.SessionID == nil || *t.SessionID != f.SessionID),
		f.AnySession && t.SessionID == nil,
		f.AnySession && f.ExceptSession != "" && *t.SessionID == f.ExceptSession,
		f.OnlyUnrevoked && t.RevokedAt != nil:
		return false
	}
	return true
}

// RevokeTokens implements oauthprovider.Store.
func (m *MemoryStore) RevokeTokens(_ context.Context, f oauthprovider.TokenFilter, now time.Time) (int64, error) {
	if f.Empty() && m.flaw != flawEmptyFilterAccepted {
		return 0, oauthprovider.ErrEmptyFilter
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for _, id := range slices.Sorted(maps.Keys(m.tokens)) {
		t := m.tokens[id]
		if !tokenMatches(f, t) {
			continue
		}
		if t.RevokedAt != nil {
			if m.flaw == flawRevokeRecounts {
				n++
			}
			continue
		}
		t.RevokedAt = &now
		m.tokens[id] = t
		n++
		if m.flaw == flawRevokeFirstOnly {
			break
		}
	}
	return n, nil
}

// RevokeAccess implements oauthprovider.Store.
func (m *MemoryStore) RevokeAccess(_ context.Context, id string, now time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[id]
	if !ok || t.AccessRevokedAt != nil {
		return 0, nil
	}
	t.AccessRevokedAt = &now
	if m.flaw == flawRevokeAccessEndsAll {
		t.RevokedAt = &now
	}
	m.tokens[id] = t
	return 1, nil
}

// Tokens implements oauthprovider.Store.
func (m *MemoryStore) Tokens(_ context.Context, f oauthprovider.TokenFilter) ([]oauthprovider.TokenRecord, error) {
	if f.Empty() {
		return nil, oauthprovider.ErrEmptyFilter
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []oauthprovider.TokenRecord
	for _, t := range m.tokens {
		if tokenMatches(f, t) {
			out = append(out, cloneToken(t))
		}
	}
	return out, nil
}

// EndTokenSession implements oauthprovider.Store.
func (m *MemoryStore) EndTokenSession(_ context.Context, id string, now time.Time, revokeRefresh bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[id]
	if !ok {
		return nil
	}
	t.AccessExpiresAt = now
	if revokeRefresh {
		t.RevokedAt = &now
	}
	m.tokens[id] = t
	return nil
}

// MoveSession implements oauthprovider.Store.
func (m *MemoryStore) MoveSession(_ context.Context, from, to string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, t := range m.tokens {
		if t.SessionID != nil && *t.SessionID == from {
			t.SessionID = &to
			m.tokens[id] = t
		}
	}
	return nil
}

// SetReplay implements oauthprovider.Store.
func (m *MemoryStore) SetReplay(_ context.Context, id string, r oauthprovider.ReplayRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tokens[id]; ok {
		m.replays[id] = r
	}
	return nil
}

// Replay implements oauthprovider.Store.
func (m *MemoryStore) Replay(_ context.Context, id string) (oauthprovider.ReplayRecord, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tokens[id]; !ok {
		return oauthprovider.ReplayRecord{}, false, oauthprovider.ErrRecordNotFound
	}
	r, ok := m.replays[id]
	return r, ok, nil
}

// Consent implements oauthprovider.Store.
func (m *MemoryStore) Consent(_ context.Context, userID, clientID string) (oauthprovider.ConsentRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.consents {
		if c.UserID == userID && c.ClientID == clientID {
			return c, nil
		}
	}
	return oauthprovider.ConsentRecord{}, oauthprovider.ErrRecordNotFound
}

// ConsentByID implements oauthprovider.Store.
func (m *MemoryStore) ConsentByID(_ context.Context, userID, id string) (oauthprovider.ConsentRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.consents[id]
	if !ok || c.UserID != userID {
		return oauthprovider.ConsentRecord{}, oauthprovider.ErrRecordNotFound
	}
	return c, nil
}

// Consents implements oauthprovider.Store.
func (m *MemoryStore) Consents(_ context.Context, userID string) ([]oauthprovider.ConsentRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []oauthprovider.ConsentRecord{}
	for _, c := range m.consents {
		if c.UserID == userID {
			out = append(out, c)
		}
	}
	slices.SortFunc(out, func(a, b oauthprovider.ConsentRecord) int {
		if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out, nil
}

// InsertConsent implements oauthprovider.Store.
func (m *MemoryStore) InsertConsent(_ context.Context, c oauthprovider.ConsentRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.consents[c.ID]; ok {
		return oauthprovider.ErrRecordExists
	}
	for _, have := range m.consents {
		if have.UserID == c.UserID && have.ClientID == c.ClientID {
			return oauthprovider.ErrRecordExists
		}
	}
	m.consents[c.ID] = c
	return nil
}

// UpdateConsent implements oauthprovider.Store.
func (m *MemoryStore) UpdateConsent(_ context.Context, c oauthprovider.ConsentRecord) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	have, ok := m.consents[c.ID]
	if !ok {
		return false, nil
	}
	if m.flaw == flawConsentMerges {
		for _, s := range strings.Fields(have.Scopes) {
			if !slices.Contains(strings.Fields(c.Scopes), s) {
				c.Scopes += " " + s
			}
		}
	}
	have.Scopes, have.Claims, have.Resources, have.ReferenceID, have.UpdatedAt = c.Scopes, c.Claims, c.Resources, c.ReferenceID, c.UpdatedAt
	m.consents[c.ID] = have
	return true, nil
}

// DeleteConsent implements oauthprovider.Store.
func (m *MemoryStore) DeleteConsent(_ context.Context, userID, clientID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, c := range m.consents {
		if c.UserID == userID && c.ClientID == clientID {
			delete(m.consents, id)
			return true, nil
		}
	}
	return false, nil
}

// Sweep implements oauthprovider.Store.
func (m *MemoryStore) Sweep(_ context.Context, cutoff time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for k, c := range m.codes {
		if c.ExpiresAt.Before(cutoff) {
			delete(m.codes, k)
			n++
		}
	}
	for _, t := range m.tokens {
		refreshDone := t.RefreshExpiresAt == nil || t.RefreshExpiresAt.Before(cutoff) || m.flaw == flawSweepsRefreshable
		if t.AccessExpiresAt.Before(cutoff) && refreshDone {
			m.dropToken(t)
			n++
		}
	}
	return n, nil
}

// DeleteUser implements oauthprovider.Store.
func (m *MemoryStore) DeleteUser(_ context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, c := range m.clients {
		if c.OwnerID != nil && *c.OwnerID == userID {
			delete(m.clients, id)
		}
	}
	for k, c := range m.codes {
		if c.UserID == userID {
			delete(m.codes, k)
		}
	}
	for _, t := range m.tokens {
		if t.UserID != nil && *t.UserID == userID {
			m.dropToken(t)
		}
	}
	for id, c := range m.consents {
		if c.UserID == userID || (m.flaw == flawDeleteUserTooBroad && c.ClientID != "") {
			delete(m.consents, id)
		}
	}
	return nil
}
