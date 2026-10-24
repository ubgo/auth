package oauthprovider

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
)

// Subject types (OpenID Connect Core section 8).
const (
	SubjectPublic   = "public"
	SubjectPairwise = "pairwise"
	// minPairwiseSecret is the minimum PairwiseSecret length.
	minPairwiseSecret = 32
)

// ErrBadPairwiseSecret is a PairwiseSecret shorter than 32 characters.
var ErrBadPairwiseSecret = errors.New("oauthprovider: PairwiseSecret needs at least 32 characters")

// PairwiseSecret enables pairwise subject identifiers: a client registered with
// subject_type "pairwise" sees each user under its own sub, so two clients
// cannot join their users by sub. At least 32 characters; changing it changes
// every pairwise sub.
func PairwiseSecret(secret string) Option { return func(p *Plugin) { p.pairwise = secret } }

// sector is a client's sector identifier: the host of its first redirect
// URI.
func sector(r clientRow) string {
	uris := splitList(r.redirects, redirectSeparator)
	if len(uris) == 0 {
		return ""
	}
	u, err := url.Parse(uris[0])
	if err != nil {
		return ""
	}
	return u.Host
}

// subjectFor is the sub a client sees for a user: the user id, or for a
// pairwise client base64(HMAC-SHA256(secret, "<sector>.<user id>")).
func (p *Plugin) subjectFor(r clientRow, userID string) string {
	if p.pairwise == "" || deref(r.subjectType) != SubjectPairwise || userID == "" {
		return userID
	}
	m := hmac.New(sha256.New, []byte(p.pairwise))
	m.Write([]byte(sector(r) + "." + userID))
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// subjectForClient is subjectFor by client id, for a token already found
// active. Falling back to the public subject when the client cannot be
// read would hand a pairwise client the user's real id, so a failed read
// is an error, and a client deleted since the token was read (its tokens
// go with it) makes the token invalid.
func (p *Plugin) subjectForClient(ctx context.Context, clientID, userID string) (string, error) {
	r, err := p.loadClient(ctx, clientID)
	if errors.Is(err, ErrClientNotFound) {
		return "", ErrInvalidToken
	}
	if err != nil {
		return "", err
	}
	return p.subjectFor(r, userID), nil
}

// subjectTypes is subject_types_supported.
func (p *Plugin) subjectTypes() []string {
	if p.pairwise != "" {
		return []string{SubjectPublic, SubjectPairwise}
	}
	return []string{SubjectPublic}
}

// checkSubjectType validates a registration's subject_type: public or
// pairwise; pairwise needs PairwiseSecret and redirect URIs that all share
// one host, the sector.
func (p *Plugin) checkSubjectType(m ClientMetadata) error {
	switch m.SubjectType {
	case "", SubjectPublic:
		return nil
	case SubjectPairwise:
		if p.pairwise == "" {
			return ErrInvalidClientMetadata
		}
		host := ""
		for i, raw := range m.RedirectURIs {
			u, err := url.Parse(raw)
			if err != nil || (i > 0 && u.Host != host) {
				return ErrInvalidClientMetadata
			}
			host = u.Host
		}
		return nil
	}
	return ErrInvalidClientMetadata
}
