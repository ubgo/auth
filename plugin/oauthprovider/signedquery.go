package oauthprovider

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"net/url"
	"slices"
	"strconv"

	"github.com/ubgo/auth"
)

// The signed authorize query, better-auth's signParams and
// verifyOAuthQueryParams: the parameters the provider hands a login or
// consent page carry an expiry, the time they were issued, the list of
// signed parameter names and an HMAC over all of them, so what the page
// posts back is exactly what the provider sent.
const (
	paramSig       = "sig"
	paramExp       = "exp"
	paramIssuedAt  = "ba_iat"
	paramSignedSet = "ba_param"
	paramPostLogin = "ba_pl"
	// keyLabelQuery derives the signing key from auth.WithSecret.
	keyLabelQuery = "oauthprovider.query"
)

// signedControl are the signed query's own parameters, which are not part
// of the authorization request.
var signedControl = []string{paramSig, paramExp, paramIssuedAt, paramSignedSet, paramPostLogin}

// ErrInvalidSignature is an oauth_query whose signature, set of signed
// names or expiry does not verify.
var ErrInvalidSignature = auth.NewError("oauthprovider.invalid_signature", http.StatusUnauthorized, "The authorization request was altered or has expired.")

// AllowPublicClientPrelogin serves the public-client-prelogin operation:
// the consent or login page may read a client's public fields before the
// user signs in, with the signed query it was given, better-auth's
// allowPublicClientPrelogin.
func AllowPublicClientPrelogin() Option { return func(p *Plugin) { p.prelogin = true } }

// queryKeys are the signing keys, the current first; none without a secret.
func (p *Plugin) queryKeys() [][]byte {
	cfg := p.core.Config()
	keys, err := cfg.DeriveKeys(keyLabelQuery)
	if err != nil {
		return nil
	}
	return keys
}

// canonical is the query sorted by name, then value, URL-encoded: what is
// signed.
func canonical(v url.Values) string {
	type kv struct{ k, v string }
	var all []kv
	for k, vs := range v {
		for _, x := range vs {
			all = append(all, kv{k, x})
		}
	}
	slices.SortFunc(all, func(a, b kv) int {
		if a.k != b.k {
			if a.k < b.k {
				return -1
			}
			return 1
		}
		if a.v < b.v {
			return -1
		}
		if a.v > b.v {
			return 1
		}
		return 0
	})
	out := url.Values{}
	for _, e := range all {
		out.Add(e.k, e.v)
	}
	// url.Values.Encode sorts by key and keeps each key's values in order.
	return out.Encode()
}

func querySignature(key []byte, v url.Values) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(canonical(v)))
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// signQuery adds the expiry (the code lifetime), the issue time, the signed
// names and the signature; without a secret it returns the query as is.
func (p *Plugin) signQuery(v url.Values) url.Values {
	keys := p.queryKeys()
	if len(keys) == 0 {
		return v
	}
	now := p.core.Now()
	for _, c := range signedControl {
		if c != paramPostLogin {
			// The post-login marker, when the caller set one, is signed.
			v.Del(c)
		}
	}
	v.Set(paramExp, strconv.FormatInt(now.Add(p.codeTTL).Unix(), 10))
	v.Set(paramIssuedAt, strconv.FormatInt(now.UnixMilli(), 10))
	names := []string{paramSignedSet}
	for k := range v {
		names = append(names, k)
	}
	slices.Sort(names)
	for _, n := range slices.Compact(names) {
		v.Add(paramSignedSet, n)
	}
	v.Set(paramSig, querySignature(keys[0], v))
	return v
}

// VerifyOAuthQuery checks an oauth_query a page posted back: exactly one
// signature, valid under a current or previous secret (compared in
// constant time), and not expired. Without a secret no query is signed and
// every query passes. better-auth's verifyOAuthQueryParams.
func (p *Plugin) VerifyOAuthQuery(raw string) error {
	keys := p.queryKeys()
	if len(keys) == 0 {
		return nil
	}
	v, err := url.ParseQuery(raw)
	if err != nil {
		return ErrInvalidSignature
	}
	sigs := v[paramSig]
	exp, err := strconv.ParseInt(v.Get(paramExp), 10, 64)
	if len(sigs) != 1 || err != nil || p.core.Now().Unix() > exp {
		return ErrInvalidSignature
	}
	v.Del(paramSig)
	for _, k := range keys {
		if subtle.ConstantTimeCompare([]byte(sigs[0]), []byte(querySignature(k, v))) == 1 {
			return nil
		}
	}
	return ErrInvalidSignature
}

// stripSigned removes the signed query's own parameters, leaving the
// authorization request.
func stripSigned(v url.Values) url.Values {
	out := url.Values{}
	for k, vs := range v {
		if !slices.Contains(signedControl, k) {
			out[k] = vs
		}
	}
	return out
}

// PreloginRequest asks for a client's public fields before sign-in.
type PreloginRequest struct {
	ClientID   string `json:"client_id"`
	OAuthQuery string `json:"oauth_query"`
}

// doPublicClientPrelogin answers a client's public fields to a page that
// holds a valid signed query for that client.
func (p *Plugin) doPublicClientPrelogin(ctx context.Context, _ *auth.Call, in PreloginRequest) (PublicClient, error) {
	if !p.prelogin {
		return PublicClient{}, ErrClientNotFound
	}
	if len(p.queryKeys()) == 0 || p.VerifyOAuthQuery(in.OAuthQuery) != nil {
		return PublicClient{}, ErrInvalidSignature
	}
	q, _ := url.ParseQuery(in.OAuthQuery) // VerifyOAuthQuery parsed it
	clientID := in.ClientID
	if clientID == "" {
		clientID = q.Get("client_id")
	}
	if clientID != q.Get("client_id") {
		return PublicClient{}, ErrInvalidSignature
	}
	return p.doPublicClient(ctx, nil, ClientIDRequest{ClientID: clientID})
}
