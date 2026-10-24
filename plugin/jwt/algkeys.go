package jwt

import (
	"crypto"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/ubgo/auth"
)

// Errors of AlgorithmKeys.
var (
	// ErrNoAlgorithmKey is a Sign whose SignRequest.Alg names an algorithm
	// that neither the signing key nor an AlgorithmKeys key signs, better-
	// auth's descriptive error for an algorithm absent from keyPairConfig and
	// keyPairConfigs.
	ErrNoAlgorithmKey = errors.New("jwt: no signing key for this algorithm; add one with jwt.AlgorithmKeys")
	// ErrAlgorithmKeys is a configuration error: an AlgorithmKeys key that is
	// nil or a short Ed25519 key, or one key given twice (counting the
	// signing key), which would publish one key id twice.
	ErrAlgorithmKeys = errors.New("jwt: AlgorithmKeys holds valid keys, each once and none the signing key")
	// ErrNoSigningKey is a Sign whose SignRequest.KeyID names no key the
	// plugin signs with (the signing key or an AlgorithmKeys key), or one
	// of another algorithm than SignRequest.Alg.
	ErrNoSigningKey = errors.New("jwt: no signing key with this key id")
)

// AlgorithmKeys adds signing keys beside the signing key: a token signed by
// Sign with SignRequest.Alg set to an algorithm uses the first key of it (the
// signing key before these), SignRequest.KeyID picks one by key id, and every
// one is published in the key set (after the signer's keys, before
// PreviousKeys), so a verifier finds it by kid. The
// session token route and Token keep signing with the main key. Several
// keys may share an algorithm; one key given twice (the signing key
// included) fails auth.New with ErrAlgorithmKeys.
// This plugin stores no keys, so the app passes them (GenerateKey makes one)
// from its secret store.
//
//ds:def id=algorithmkeys-h7tn2xqc owner=@khanakia stability=stable
func AlgorithmKeys(keys ...crypto.Signer) Option {
	return func(p *Plugin) {
		if auth.RefuseNilEach(&p.optErrs, "jwt.AlgorithmKeys", keys) {
			return
		}
		for _, k := range keys {
			if ek, ok := k.(ed25519.PrivateKey); ok && len(ek) != ed25519.PrivateKeySize {
				p.algKeysErr = fmt.Errorf("%w: a short Ed25519 key", ErrAlgorithmKeys)
				continue
			}
			p.algKeys = append(p.algKeys, keySigner{key: k})
		}
	}
}

// validateAlgorithmKeys checks AlgorithmKeys against each other and the
// signing key.
func (p *Plugin) validateAlgorithmKeys() error {
	if p.algKeysErr != nil {
		return p.algKeysErr
	}
	seen := map[string]bool{}
	if keys := p.signer.PublicKeys(); len(keys) > 0 {
		seen[KeyID(keys[0])] = true
	}
	for _, s := range p.algKeys {
		if _, err := AlgOf(s.key.Public()); err != nil {
			return err
		}
		kid := KeyID(s.key.Public())
		if seen[kid] {
			return fmt.Errorf("%w: key %s given twice", ErrAlgorithmKeys, kid)
		}
		seen[kid] = true
	}
	return nil
}

// signerFor is the Signer that signs alg: the main signer for "" or its own
// algorithm, else the AlgorithmKeys key of alg, else ErrNoAlgorithmKey.
func (p *Plugin) signerFor(alg Alg) (Signer, error) {
	if alg == "" {
		return p.signer, nil
	}
	if keys := p.signer.PublicKeys(); len(keys) > 0 {
		if main, err := AlgOf(keys[0]); err == nil && main == alg {
			return p.signer, nil
		}
	}
	for _, s := range p.algKeys {
		if a, err := AlgOf(s.key.Public()); err == nil && a == alg {
			return s, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrNoAlgorithmKey, alg)
}

// signerForKey is the Signer whose current key has id kid, checked against
// alg when one is given; signerFor(alg) for an empty kid.
func (p *Plugin) signerForKey(alg Alg, kid string) (Signer, error) {
	if kid == "" {
		return p.signerFor(alg)
	}
	candidates := []Signer{p.signer}
	for _, s := range p.algKeys {
		candidates = append(candidates, s)
	}
	for _, s := range candidates {
		keys := s.PublicKeys()
		if len(keys) == 0 || KeyID(keys[0]) != kid {
			continue
		}
		if a, _ := AlgOf(keys[0]); alg != "" && a != alg {
			return nil, fmt.Errorf("%w: %s is not a %s key", ErrNoSigningKey, kid, alg)
		}
		return s, nil
	}
	return nil, fmt.Errorf("%w: %s", ErrNoSigningKey, kid)
}

// algKeyPublics is the public half of every AlgorithmKeys key, for the key
// set.
func (p *Plugin) algKeyPublics() []crypto.PublicKey {
	out := make([]crypto.PublicKey, 0, len(p.algKeys))
	for _, s := range p.algKeys {
		out = append(out, s.key.Public())
	}
	return out
}
