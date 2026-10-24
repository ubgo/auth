package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/siwe"
	"github.com/ubgo/auth/plugin/siwe/siwetest"
	"github.com/ubgo/sqlb"
)

// world is the example's app on an in-memory database with a frozen clock,
// one browser on it and the fixed test wallet.
type world struct {
	e   *authtest.Env
	b   *authtest.Browser
	key *siwetest.Key
}

func newWorld(t *testing.T, extra ...siwe.Option) *world {
	t.Helper()
	e := authtest.New(t, authtest.WithPlugins(func(*authtest.Env) []auth.Plugin {
		ps := plugins()
		if len(extra) > 0 {
			ps[len(ps)-1] = siwe.New(append([]siwe.Option{siwe.Chains(mainnet)}, extra...)...)
		}
		return ps
	}))
	return &world{e: e, b: e.Browser(newHandler(e.Auth)), key: siwetest.MustKey(siwetest.HardhatKey0)}
}

// nonce asks the server for a nonce for address on mainnet.
func (w *world) nonce(t *testing.T, address string) string {
	t.Helper()
	var out siwe.NonceResult
	w.b.Post("/auth/siwe/nonce", map[string]any{"walletAddress": address, "chainId": mainnet}).Expect(http.StatusOK).Decode(&out)
	return out.Nonce
}

// message is the ERC-4361 message the page builds, for the app's own site,
// issued now by the test clock.
func (w *world) message(address, nonce string) siwe.Message {
	base, _ := url.Parse(w.e.BaseURL)
	return siwe.Message{
		Domain: base.Host, Address: address, Statement: "Sign in to the example app.", URI: w.e.BaseURL,
		Version: siwe.Version, ChainID: mainnet, Nonce: nonce, IssuedAt: w.e.Clock.Now(),
	}
}

// verify posts a signed message and returns the response.
func (w *world) verify(text, signature string, extra map[string]any) *authtest.Response {
	body := map[string]any{"message": text, "signature": signature}
	for k, v := range extra {
		body[k] = v
	}
	return w.b.Post("/auth/siwe/verify", body)
}

// signIn runs the whole flow with key and returns the verify answer.
func (w *world) signIn(t *testing.T, key *siwetest.Key) siwe.SignInResult {
	t.Helper()
	text := w.message(key.Address(), w.nonce(t, key.Address())).String()
	var out siwe.SignInResult
	w.verify(text, key.Sign(text), nil).Expect(http.StatusOK).Decode(&out)
	return out
}

// TestSIWE_FirstSignInCreatesThenSignsIn: a wallet's first sign-in creates
// the account and a session; the next one signs in to the same account.
//
//ds:def id=siwe-example-test-signin-6h3k9p2m
func TestSIWE_FirstSignInCreatesThenSignsIn(t *testing.T) {
	w := newWorld(t)
	first := w.signIn(t, w.key)
	if !first.Created || first.User.ID == "" || first.Wallet.Address != w.key.Address() || !first.Wallet.Primary {
		t.Fatalf("first sign-in = %+v", first)
	}
	var me meResponse
	w.b.Get("/me").Expect(http.StatusOK).Decode(&me)
	if me.ID != first.User.ID {
		t.Fatalf("/me = %+v", me)
	}
	again := w.signIn(t, w.key)
	if again.Created || again.User.ID != first.User.ID || again.Wallet.ID != first.Wallet.ID {
		t.Fatalf("second sign-in = %+v, want the same user and wallet", again)
	}
}

// TestSIWE_ReplayedNonceIsRefused: a signed message works once; sending the
// same message and signature again is refused, so a captured sign-in cannot
// be replayed.
func TestSIWE_ReplayedNonceIsRefused(t *testing.T) {
	w := newWorld(t)
	text := w.message(w.key.Address(), w.nonce(t, w.key.Address())).String()
	sig := w.key.Sign(text)
	w.verify(text, sig, nil).Expect(http.StatusOK)
	if code := w.verify(text, sig, nil).Expect(http.StatusBadRequest).ErrorCode(); code != siwe.ErrNonceInvalid.Code {
		t.Fatalf("replay answered %s", code)
	}
	// A nonce the server never issued is refused the same way.
	made := w.message(w.key.Address(), "a1b2c3d4e5f6a7b8").String()
	if code := w.verify(made, w.key.Sign(made), nil).Expect(http.StatusBadRequest).ErrorCode(); code != siwe.ErrNonceInvalid.Code {
		t.Fatalf("invented nonce answered %s", code)
	}
}

// TestSIWE_WrongDomainIsRefused: a message signed for another site, which a
// phishing page would relay, is refused, whether the domain, the URI or the
// scheme names the other site. The nonce stays usable.
func TestSIWE_WrongDomainIsRefused(t *testing.T) {
	w := newWorld(t)
	nonce := w.nonce(t, w.key.Address())
	for name, mutate := range map[string]func(*siwe.Message){
		"domain":          func(m *siwe.Message) { m.Domain = "evil.example" },
		"uri":             func(m *siwe.Message) { m.URI = "https://evil.example/login" },
		"both":            func(m *siwe.Message) { m.Domain, m.URI = "evil.example", "https://evil.example" },
		"scheme":          func(m *siwe.Message) { m.Scheme = "http" },
		"domain and port": func(m *siwe.Message) { m.Domain += ":8443" },
	} {
		m := w.message(w.key.Address(), nonce)
		mutate(&m)
		text := m.String()
		if code := w.verify(text, w.key.Sign(text), nil).Expect(http.StatusBadRequest).ErrorCode(); code != siwe.ErrDomainInvalid.Code {
			t.Errorf("%s: answered %s, want %s", name, code, siwe.ErrDomainInvalid.Code)
		}
	}
	text := w.message(w.key.Address(), nonce).String()
	w.verify(text, w.key.Sign(text), nil).Expect(http.StatusOK)
}

// TestSIWE_ExpiredMessageIsRefused: a message past its Expiration Time, one
// issued longer ago than a nonce lives, one issued in the future and one
// before its Not Before are all refused.
func TestSIWE_ExpiredMessageIsRefused(t *testing.T) {
	w := newWorld(t)
	nonce := w.nonce(t, w.key.Address())
	now := w.e.Clock.Now()
	soon, later := now.Add(time.Minute), now.Add(time.Hour)
	for name, mutate := range map[string]func(*siwe.Message){
		"issued long ago": func(m *siwe.Message) { m.IssuedAt = now.Add(-siwe.DefaultNonceTTL - 2*siwe.ClockSkew) },
		"issued later":    func(m *siwe.Message) { m.IssuedAt = now.Add(2 * siwe.ClockSkew) },
		"not before":      func(m *siwe.Message) { m.NotBefore = &later },
	} {
		m := w.message(w.key.Address(), nonce)
		mutate(&m)
		text := m.String()
		if code := w.verify(text, w.key.Sign(text), nil).Expect(http.StatusBadRequest).ErrorCode(); code != siwe.ErrMessageExpired.Code {
			t.Errorf("%s: answered %s", name, code)
		}
	}
	m := w.message(w.key.Address(), nonce)
	m.ExpirationTime = &soon
	text := m.String()
	w.e.Clock.Advance(2*time.Minute + siwe.ClockSkew)
	if code := w.verify(text, w.key.Sign(text), nil).Expect(http.StatusBadRequest).ErrorCode(); code != siwe.ErrMessageExpired.Code {
		t.Fatalf("past its expiration time: answered %s", code)
	}
	// And the nonce itself expires with the clock.
	w.e.Clock.Advance(siwe.DefaultNonceTTL)
	m = w.message(w.key.Address(), nonce)
	text = m.String()
	if code := w.verify(text, w.key.Sign(text), nil).Expect(http.StatusBadRequest).ErrorCode(); code != siwe.ErrNonceInvalid.Code {
		t.Fatalf("an expired nonce: answered %s", code)
	}
}

// TestSIWE_AddressCase: the nonce asked for with the lower-case address a
// wallet reports matches the checksummed address in the message (one
// wallet); a mixed-case address with a wrong checksum is refused; a nonce
// issued for another wallet does not sign this one in.
func TestSIWE_AddressCase(t *testing.T) {
	w := newWorld(t)
	addr := w.key.Address()
	nonce := w.nonce(t, strings.ToLower(addr))
	// One letter's case flipped breaks the EIP-55 checksum.
	i := strings.IndexAny(addr[2:], "abcdef") + 2
	bad := addr[:i] + strings.ToUpper(addr[i:i+1]) + addr[i+1:]
	m := w.message(bad, nonce)
	text := m.String()
	if code := w.verify(text, w.key.Sign(text), nil).Expect(http.StatusBadRequest).ErrorCode(); code != siwe.ErrMessageInvalid.Code {
		t.Fatalf("a wrong checksum: answered %s", code)
	}
	other := siwetest.MustKey(siwetest.SecondKey)
	otherNonce := w.nonce(t, other.Address())
	text = w.message(addr, otherNonce).String()
	if code := w.verify(text, w.key.Sign(text), nil).Expect(http.StatusBadRequest).ErrorCode(); code != siwe.ErrNonceInvalid.Code {
		t.Fatalf("another wallet's nonce: answered %s", code)
	}
	text = w.message(addr, nonce).String()
	var out siwe.SignInResult
	w.verify(text, w.key.Sign(text), map[string]any{"walletAddress": strings.ToLower(addr), "chainId": mainnet}).Expect(http.StatusOK).Decode(&out)
	if out.Wallet.Address != addr {
		t.Fatalf("wallet = %s, want the checksummed %s", out.Wallet.Address, addr)
	}
}

// TestSIWE_SignatureAndRequestChecks: a signature by another key, a
// walletAddress or chainId in the request that differs from the message, a
// chain the app does not accept, and an address that is not one are refused.
func TestSIWE_SignatureAndRequestChecks(t *testing.T) {
	w := newWorld(t)
	addr := w.key.Address()
	text := w.message(addr, w.nonce(t, addr)).String()
	other := siwetest.MustKey(siwetest.SecondKey)
	if code := w.verify(text, other.Sign(text), nil).Expect(http.StatusUnauthorized).ErrorCode(); code != siwe.ErrSignatureInvalid.Code {
		t.Fatalf("another key's signature: %s", code)
	}
	if code := w.verify(text, w.key.Sign(text), map[string]any{"walletAddress": other.Address()}).Expect(http.StatusBadRequest).ErrorCode(); code != siwe.ErrMessageInvalid.Code {
		t.Fatalf("a different walletAddress: %s", code)
	}
	if code := w.verify(text, w.key.Sign(text), map[string]any{"chainId": 5}).Expect(http.StatusBadRequest).ErrorCode(); code != siwe.ErrMessageInvalid.Code {
		t.Fatalf("a different chainId: %s", code)
	}
	if code := w.b.Post("/auth/siwe/nonce", map[string]any{"walletAddress": addr, "chainId": 5}).Expect(http.StatusBadRequest).ErrorCode(); code != siwe.ErrChainInvalid.Code {
		t.Fatalf("a nonce for a chain the app refuses: %s", code)
	}
	if code := w.b.Post("/auth/siwe/nonce", map[string]any{"walletAddress": "0x1234", "chainId": mainnet}).Expect(http.StatusBadRequest).ErrorCode(); code != siwe.ErrAddressInvalidInput.Code {
		t.Fatalf("not an address: %s", code)
	}
	// Every refusal above rolled back: the nonce still signs in.
	w.verify(text, w.key.Sign(text), nil).Expect(http.StatusOK)
}

// TestSIWE_ManyWalletsPerUser: a signed-in user links a second wallet, both
// are listed, either signs in to the same account, the second can be
// unlinked and the last cannot; a wallet another user owns cannot be linked.
func TestSIWE_ManyWalletsPerUser(t *testing.T) {
	w := newWorld(t)
	first := w.signIn(t, w.key)
	second := siwetest.MustKey(siwetest.SecondKey)
	text := w.message(second.Address(), w.nonce(t, second.Address())).String()
	var linked siwe.Wallet
	w.b.Post("/auth/siwe/link", map[string]any{"message": text, "signature": second.Sign(text)}).Expect(http.StatusOK).Decode(&linked)
	if linked.Primary || linked.Address != second.Address() {
		t.Fatalf("linked = %+v", linked)
	}
	var list siwe.WalletsResult
	w.b.Get("/auth/siwe/wallets").Expect(http.StatusOK).Decode(&list)
	if len(list.Wallets) != 2 {
		t.Fatalf("wallets = %+v", list)
	}
	if got := w.signIn(t, second); got.User.ID != first.User.ID || got.Created {
		t.Fatalf("the second wallet signed in to %+v, want user %s", got, first.User.ID)
	}

	// Another person, signed in with a wallet of their own, cannot take
	// the first user's wallet.
	stranger := newBrowserOn(w)
	third := siwetest.MustKey("0000000000000000000000000000000000000000000000000000000000000003")
	t3 := w.message(third.Address(), w.nonce(t, third.Address())).String()
	stranger.Post("/auth/siwe/verify", map[string]any{"message": t3, "signature": third.Sign(t3)}).Expect(http.StatusOK)
	t4 := w.message(w.key.Address(), w.nonce(t, w.key.Address())).String()
	if code := stranger.Post("/auth/siwe/link", map[string]any{"message": t4, "signature": w.key.Sign(t4)}).Expect(http.StatusConflict).ErrorCode(); code != siwe.ErrWalletLinkedElsewhere.Code {
		t.Fatalf("linking another user's wallet: %s", code)
	}
	if code := stranger.Post("/auth/siwe/unlink", map[string]any{"id": linked.ID}).Expect(http.StatusNotFound).ErrorCode(); code != siwe.ErrWalletNotFound.Code {
		t.Fatalf("unlinking another user's wallet: %s", code)
	}

	w.b.Post("/auth/siwe/unlink", map[string]any{"id": linked.ID}).Expect(http.StatusOK)
	if code := w.b.Post("/auth/siwe/unlink", map[string]any{"id": first.Wallet.ID}).Expect(http.StatusConflict).ErrorCode(); code != auth.ErrLastSignInMethod.Code {
		t.Fatalf("unlinking the last wallet: %s", code)
	}
}

// TestSIWE_RequireEmail: with RequireEmail a first sign-in without an email
// is refused and spends nothing, so the same signed message then succeeds
// with one; the address is stored unverified.
func TestSIWE_RequireEmail(t *testing.T) {
	w := newWorld(t, siwe.RequireEmail())
	text := w.message(w.key.Address(), w.nonce(t, w.key.Address())).String()
	sig := w.key.Sign(text)
	if code := w.verify(text, sig, nil).Expect(http.StatusBadRequest).ErrorCode(); code != siwe.ErrEmailRequired.Code {
		t.Fatalf("no email: %s", code)
	}
	var out siwe.SignInResult
	w.verify(text, sig, map[string]any{"email": "ada@example.com"}).Expect(http.StatusOK).Decode(&out)
	ids, err := w.e.Auth.Identities(t.Context(), out.User.ID)
	if err != nil || len(ids) != 1 || ids[0].Value != "ada@example.com" || ids[0].Verified() {
		t.Fatalf("identities = %+v, %v; want one unverified address", ids, err)
	}
}

// TestSIWE_NoSignUp: with NoSignUp a wallet nobody linked is refused and
// spends nothing; once a signed-in user links it, it signs in.
func TestSIWE_NoSignUp(t *testing.T) {
	w := newWorld(t, siwe.NoSignUp())
	text := w.message(w.key.Address(), w.nonce(t, w.key.Address())).String()
	if code := w.verify(text, w.key.Sign(text), nil).Expect(http.StatusForbidden).ErrorCode(); code != siwe.ErrSignUpDisabled.Code {
		t.Fatalf("an unlinked wallet: %s", code)
	}
}

// TestSIWE_OversizedSignatureIsRefusedBeforeAnyWork: a signature far longer
// than any wallet produces is refused as an invalid signature.
func TestSIWE_OversizedSignatureIsRefusedBeforeAnyWork(t *testing.T) {
	w := newWorld(t)
	text := w.message(w.key.Address(), w.nonce(t, w.key.Address())).String()
	huge := "0x" + strings.Repeat("ab", 16<<10)
	if code := w.verify(text, huge, nil).Expect(http.StatusUnauthorized).ErrorCode(); code != siwe.ErrSignatureInvalid.Code {
		t.Fatalf("an oversized signature: %s", code)
	}
}

// TestSIWE_EmailWithoutTheEmailPluginIsRefused: an app that registered no
// email plugin has nowhere to keep an address, so one sent with the sign-in
// is refused rather than silently dropped.
func TestSIWE_EmailWithoutTheEmailPluginIsRefused(t *testing.T) {
	e := authtest.New(t, authtest.WithPlugins(func(*authtest.Env) []auth.Plugin { return []auth.Plugin{siwe.New(siwe.Chains(mainnet))} }))
	w := &world{e: e, b: e.Browser(newHandler(e.Auth)), key: siwetest.MustKey(siwetest.HardhatKey0)}
	text := w.message(w.key.Address(), w.nonce(t, w.key.Address())).String()
	if code := w.verify(text, w.key.Sign(text), map[string]any{"email": "ada@example.com"}).Expect(http.StatusBadRequest).ErrorCode(); code != siwe.ErrEmailNotAccepted.Code {
		t.Fatalf("an email without the email plugin: %s", code)
	}
}

// newBrowserOn opens a second browser on the same app, a second person.
func newBrowserOn(w *world) *authtest.Browser { return w.e.Browser(newHandler(w.e.Auth)) }

// swarm is an app wired for the typed-method and fault tests: no chain
// limit unless asked for, the plugin in hand, a fixed key and a frozen clock.
type swarm struct {
	*authtest.Env
	p   *siwe.Plugin
	key *siwetest.Key
}

// newSwarm builds a fresh Env around siwe.New(opts...) with a counter on the
// database and the email plugin beside it.
func newSwarm(t *testing.T, extra []auth.Option, opts ...siwe.Option) *swarm {
	t.Helper()
	s := &swarm{key: siwetest.MustKey(siwetest.HardhatKey0)}
	s.Env = authtest.New(t, authtest.WithFaults(authtest.NewFaults()), authtest.WithOptions(extra...), authtest.WithPlugins(func(e *authtest.Env) []auth.Plugin {
		ps := plugins()
		s.p = siwe.New(opts...)
		ps[len(ps)-1] = s.p
		return ps
	}))
	return s
}

// signed asks for a nonce for key on chain and returns the request that
// verifies, link or sign-in alike, for a message issued now.
func (s *swarm) signed(t *testing.T, key *siwetest.Key, chain int64) siwe.VerifyRequest {
	t.Helper()
	ctx := s.Anonymous(context.Background())
	nonce, err := s.p.Nonce(ctx, key.Address(), chain)
	if err != nil {
		t.Fatal(err)
	}
	base, _ := url.Parse(s.BaseURL)
	text := siwe.Message{Domain: base.Host, Address: key.Address(), Statement: "Sign in.", URI: s.BaseURL, Version: siwe.Version, ChainID: chain, Nonce: nonce, IssuedAt: s.Clock.Now()}.String()
	return siwe.VerifyRequest{Message: text, Signature: key.Sign(text)}
}

// signIn signs key in on chain and returns the result and a context holding
// its session.
func (s *swarm) signIn(t *testing.T, key *siwetest.Key, chain int64) (siwe.SignInResult, context.Context) {
	t.Helper()
	out, err := s.p.Verify(s.Anonymous(context.Background()), s.signed(t, key, chain))
	if err != nil {
		t.Fatal(err)
	}
	in := s.Auth.WithRequest(context.Background(), auth.Request{
		Transport: auth.TransportHTTP, Client: auth.Client{IP: "203.0.113.1", UserAgent: "authtest", Origin: s.BaseURL},
		Credential: auth.CredentialCookie, Token: out.Token,
	})
	return out, in
}

// TestSIWE_EveryDatabaseFailureReachesTheCaller: each typed method is run
// once per database call it makes with that call failing, and must return the
// failure. A sign-in that could not store its wallet, a link that could not
// check who owns the address, an unlink that could not delete: none of them
// may report success.
func TestSIWE_EveryDatabaseFailureReachesTheCaller(t *testing.T) {
	second := siwetest.MustKey(siwetest.SecondKey)
	holder := authtest.Identity{Kind: "email", Value: "ada@example.com"}
	type scenario struct {
		opts  []siwe.Option
		extra []auth.Option
		setup func(t *testing.T, s *swarm) func(ctx context.Context) error
	}
	run := func(t *testing.T, sc scenario) {
		authtest.SweepFaults(t,
			func() (*swarm, *authtest.Faults) {
				s := newSwarm(t, sc.extra, sc.opts...)
				return s, s.Faults
			},
			func(s *swarm) func(context.Context) error { return sc.setup(t, s) })
	}
	for name, sc := range map[string]scenario{
		"nonce": {setup: func(t *testing.T, s *swarm) func(context.Context) error {
			return func(ctx context.Context) error {
				_, err := s.p.Nonce(s.Anonymous(ctx), s.key.Address(), mainnet)
				return err
			}
		}},
		"a new wallet": {setup: func(t *testing.T, s *swarm) func(context.Context) error {
			req := s.signed(t, s.key, mainnet)
			return func(ctx context.Context) error { _, err := s.p.Verify(s.Anonymous(ctx), req); return err }
		}},
		"a new wallet with a name, an email another user holds, mail through the outbox": {
			extra: []auth.Option{auth.WithDeliveryOutbox(bytes.Repeat([]byte{42}, auth.SealKeySize))},
			opts: []siwe.Option{siwe.RequireEmail(), siwe.WithNameResolver(siwe.NameResolverFunc(func(context.Context, string, int64) (siwe.WalletName, error) {
				return siwe.WalletName{Name: "ada.eth", Avatar: "https://img.example/ada.png"}, nil
			}))},
			setup: func(t *testing.T, s *swarm) func(context.Context) error {
				s.CreateUser("Holder", holder)
				req := s.signed(t, s.key, mainnet)
				req.Email = holder.Value
				return func(ctx context.Context) error { _, err := s.p.Verify(s.Anonymous(ctx), req); return err }
			}},
		"a returning wallet": {setup: func(t *testing.T, s *swarm) func(context.Context) error {
			s.signIn(t, s.key, mainnet)
			req := s.signed(t, s.key, mainnet)
			return func(ctx context.Context) error { _, err := s.p.Verify(s.Anonymous(ctx), req); return err }
		}},
		"the same address on another chain": {setup: func(t *testing.T, s *swarm) func(context.Context) error {
			s.signIn(t, s.key, mainnet)
			req := s.signed(t, s.key, 137)
			return func(ctx context.Context) error { _, err := s.p.Verify(s.Anonymous(ctx), req); return err }
		}},
		"link a second wallet": {setup: func(t *testing.T, s *swarm) func(context.Context) error {
			_, in := s.signIn(t, s.key, mainnet)
			req := s.signed(t, second, mainnet)
			return func(context.Context) error {
				_, err := s.p.Link(in, siwe.LinkRequest{Message: req.Message, Signature: req.Signature})
				return err
			}
		}},
		"link a wallet already linked": {setup: func(t *testing.T, s *swarm) func(context.Context) error {
			_, in := s.signIn(t, s.key, mainnet)
			req := s.signed(t, s.key, mainnet)
			return func(context.Context) error {
				_, err := s.p.Link(in, siwe.LinkRequest{Message: req.Message, Signature: req.Signature})
				return err
			}
		}},
		"list wallets": {setup: func(t *testing.T, s *swarm) func(context.Context) error {
			_, in := s.signIn(t, s.key, mainnet)
			return func(context.Context) error { _, err := s.p.Wallets(in); return err }
		}},
		"unlink a wallet": {setup: func(t *testing.T, s *swarm) func(context.Context) error {
			first, in := s.signIn(t, s.key, mainnet)
			_ = first
			req := s.signed(t, second, mainnet)
			w, err := s.p.Link(in, siwe.LinkRequest{Message: req.Message, Signature: req.Signature})
			if err != nil {
				t.Fatal(err)
			}
			return func(context.Context) error { return s.p.Unlink(in, w.ID) }
		}},
	} {
		t.Run(name, func(t *testing.T) { run(t, sc) })
	}
}

// TestSIWE_ChecksThatNeedNoWallet: the refusals before any signature is
// weighed. Garbage is not a message; a message on a chain the app does not
// accept is refused even with a nonce; a URI that names no host cannot be a
// site; a signature that is not hex is not a signature; Origins replaces the
// core's trusted origins as the sites a message may name; and a chain id of
// zero never gets a nonce.
func TestSIWE_ChecksThatNeedNoWallet(t *testing.T) {
	s := newSwarm(t, nil, siwe.Chains(mainnet), siwe.Origins(authtest.BaseURL))
	ctx := s.Anonymous(context.Background())
	good := s.signed(t, s.key, mainnet)
	for name, c := range map[string]struct {
		req  siwe.VerifyRequest
		want *auth.Error
	}{
		"garbage":       {siwe.VerifyRequest{Message: "hello", Signature: good.Signature}, siwe.ErrMessageInvalid},
		"not hex":       {siwe.VerifyRequest{Message: good.Message, Signature: "zz"}, siwe.ErrSignatureInvalid},
		"no host":       {siwe.VerifyRequest{Message: strings.Replace(good.Message, "URI: "+s.BaseURL, "URI: mailto:ada@example.com", 1), Signature: good.Signature}, siwe.ErrDomainInvalid},
		"another site":  {siwe.VerifyRequest{Message: strings.Replace(good.Message, "URI: "+s.BaseURL, "URI: https://app.example.test.evil.example", 1), Signature: good.Signature}, siwe.ErrDomainInvalid},
		"another chain": {siwe.VerifyRequest{Message: strings.Replace(good.Message, "Chain ID: 1", "Chain ID: 5", 1), Signature: good.Signature}, siwe.ErrChainInvalid},
	} {
		if _, err := s.p.Verify(ctx, c.req); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %s", name, err, c.want.Code)
		}
	}
	if _, err := s.p.Nonce(ctx, s.key.Address(), 0); !errors.Is(err, siwe.ErrChainInvalid) {
		t.Errorf("a nonce for chain 0: %v", err)
	}
	if _, err := s.p.Verify(ctx, good); err != nil {
		t.Errorf("the untouched message under Origins: %v", err)
	}
}

// TestSIWE_ANameServiceOutageDoesNotStopSignIn: a NameResolver that fails is
// logged and the user is created without a name; one that answers names the
// user.
func TestSIWE_ANameServiceOutageDoesNotStopSignIn(t *testing.T) {
	down := newSwarm(t, nil, siwe.WithNameResolver(siwe.NameResolverFunc(func(context.Context, string, int64) (siwe.WalletName, error) {
		return siwe.WalletName{}, errors.New("rpc down")
	})))
	if out, _ := down.signIn(t, down.key, mainnet); !out.Created || out.User.Name != "" {
		t.Fatalf("outage: %+v", out.User)
	}
	up := newSwarm(t, nil, siwe.WithNameResolver(siwe.NameResolverFunc(func(context.Context, string, int64) (siwe.WalletName, error) {
		return siwe.WalletName{Name: "ada.eth", Avatar: "https://img.example/ada.png"}, nil
	})))
	if out, _ := up.signIn(t, up.key, mainnet); out.User.Name != "ada.eth" || out.User.Image != "https://img.example/ada.png" {
		t.Fatalf("resolved: %+v", out.User)
	}
}

// TestSIWE_AVerifierOutageIsNotABadSignature: an operational error from the
// app's Verifier (an RPC node that did not answer) comes back as it is, so
// the person is not told their signature was wrong.
func TestSIWE_AVerifierOutageIsNotABadSignature(t *testing.T) {
	errNode := errors.New("rpc node timeout")
	s := newSwarm(t, nil, siwe.WithVerifier(siwe.VerifierFunc(func(context.Context, siwe.SignedMessage) error { return errNode })))
	if _, err := s.p.Verify(s.Anonymous(context.Background()), s.signed(t, s.key, mainnet)); !errors.Is(err, errNode) || errors.Is(err, siwe.ErrSignatureInvalid) {
		t.Fatalf("verifier outage = %v", err)
	}
}

// TestSIWE_AFailedWalletIDLeavesNoUser: when the wallet row cannot get an id
// the sign-in fails whole and no user is left behind.
func TestSIWE_AFailedWalletIDLeavesNoUser(t *testing.T) {
	ids := auth.WithIDs(func(prefix string) (string, error) {
		if prefix == "wlt" {
			return "", errors.New("ids down")
		}
		return auth.NewID(prefix)
	})
	s := newSwarm(t, []auth.Option{ids})
	if _, err := s.p.Verify(s.Anonymous(context.Background()), s.signed(t, s.key, mainnet)); err == nil {
		t.Fatal("a wallet without an id signed in")
	}
}

// TestSIWE_RacingFirstSignInsOfOneWalletAreTold: two first sign-ins of one
// wallet race; the loser's insert hits the unique (address, chain) and is
// refused as a wallet that belongs to another account, not as a second user.
// The race is staged by a hook that inserts the winner's row between the
// loser's lookup and its own insert.
func TestSIWE_RacingFirstSignInsOfOneWalletAreTold(t *testing.T) {
	var addr string
	winner := auth.WithDataHooks(auth.DataHooks{User: auth.TableHooks[auth.User]{AfterCreate: func(ctx context.Context, tx sqlb.DBTX, u *auth.User) error {
		_, err := tx.ExecContext(ctx, "INSERT INTO auth_siwe_wallet (id, user_id, address, chain_id, is_primary, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			"wlt_winner", "usr_winner", strings.ToLower(addr), mainnet, true, time.Now())
		return err
	}}})
	s := newSwarm(t, []auth.Option{winner})
	addr = s.key.Address()
	if _, err := s.p.Verify(s.Anonymous(context.Background()), s.signed(t, s.key, mainnet)); !errors.Is(err, siwe.ErrWalletLinkedElsewhere) {
		t.Fatalf("the loser = %v, want %s", err, siwe.ErrWalletLinkedElsewhere.Code)
	}
}

// TestSIWE_OriginsReplaceTheCoresTrustedOrigins: with Origins naming another
// site, a message for the app's own base URL, which the core trusts, is
// refused: the option chooses the sites a message may name.
func TestSIWE_OriginsReplaceTheCoresTrustedOrigins(t *testing.T) {
	s := newSwarm(t, nil, siwe.Origins("https://login.example.org"))
	if _, err := s.p.Verify(s.Anonymous(context.Background()), s.signed(t, s.key, mainnet)); !errors.Is(err, siwe.ErrDomainInvalid) {
		t.Fatalf("a message for the base URL under Origins(other) = %v, want %s", err, siwe.ErrDomainInvalid.Code)
	}
}
