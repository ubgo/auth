// Package storetest checks an oauthprovider.Store against the contract
// every provider store must keep, so a custom store proves itself with one
// call rather than by finding out in production that a code worked twice or
// a stolen refresh token kept its family alive. The SQL store (on SQLite,
// Postgres and MySQL) and MemoryStore run it.
//
// Every security rule the provider leaves to its store has a case here:
// single-use codes and refresh tokens (with racing callers), reuse visible
// to the loser of a rotation race, family revocation counted once, the
// empty filter refused, updates that write only the fields named, consent
// replaced and never merged, sweeps that keep what can still be refreshed.
//
// It imports only the standard library and the provider, so a store's own
// tests can use it whatever else they depend on.
package storetest

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth/plugin/oauthprovider"
)

// Run checks the store that open returns. open is called once per case, so
// every case starts empty; a store backed by a shared server should return
// a store with a fresh key prefix or a cleared keyspace each time.
func Run(t *testing.T, open func(t *testing.T) oauthprovider.Store) {
	t.Helper()
	names := make([]string, 0, len(cases))
	for name := range cases {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		t.Run(name, func(t *testing.T) { cases[name](t, open(t)) })
	}
}

// T is the part of testing.T a case uses. An interface so the suite's own
// tests can run a case against a store that breaks a rule and read the
// failure, which is how the suite proves it would catch that rule.
type T interface {
	Fatal(args ...any)
	Fatalf(format string, args ...any)
}

// Racers is how many goroutines race on one code, one refresh token or one
// family: enough to interleave on any store, few enough for SQLite's single
// writer.
const Racers = 8

// now is the fixed instant every case reasons from, on a whole second so a
// store that keeps times to the second or the microsecond compares equal; a
// store must compare the times it is given, never read a clock of its own.
var now = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

// at is now moved by d, as a pointer.
func at(d time.Duration) *time.Time {
	t := now.Add(d)
	return &t
}

// str is s as a pointer.
func str(s string) *string { return &s }

// hash turns a label into a stored hash, the only form a store ever sees.
func hash(label string) []byte {
	h := sha256.Sum256([]byte(label))
	return h[:]
}

// The users and clients the cases file records under. Exported so a store
// on shared tables can clear exactly the suite's rows.
const (
	UserA   = "usr_storetest_a"
	UserB   = "usr_storetest_b"
	ClientA = "cl_storetest_a"
	ClientB = "cl_storetest_b"
)

// fullClient is a client with every field set, so a store that drops one is
// caught.
func fullClient(id, owner, ref string, created time.Time) oauthprovider.ClientRecord {
	return oauthprovider.ClientRecord{
		ID: id, SecretHash: hash("secret-" + id), SecretEncrypted: str("sealed-" + id), Name: "Name " + id,
		RedirectURIs: "https://app.example/cb\nhttps://app.example/cb2", Scopes: "openid email", GrantTypes: "authorization_code refresh_token",
		AuthMethod: "client_secret_basic", SkipConsent: true, RequirePKCE: true, IntrospectAny: true,
		OwnerID: str(owner), DisabledAt: at(-time.Minute), ClientURI: str("https://app.example"), LogoURI: str("https://app.example/logo.png"),
		Contacts: str("ops@app.example"), TosURI: str("https://app.example/tos"), PolicyURI: str("https://app.example/policy"),
		CreatedAt: created, UpdatedAt: created.Add(time.Second), PostLogoutRedirectURIs: str("https://app.example/bye"), EndSession: true,
		JWKS: str(`{"keys":[]}`), JWKSURI: str("https://app.example/jwks"), Discovery: str("cimd"), FetchedAt: at(-time.Hour),
		SubjectType: str("pairwise"), BackchannelLogoutURI: str("https://app.example/bc"), BackchannelLogoutSessionRequired: true,
		DPoPBound: true, ApplicationType: str("web"), ClientCredentialsScopes: str("api"), ReferenceID: str(ref),
		Metadata: str(`{"tier":"gold"}`), SecretExpiresAt: at(24 * time.Hour), SoftwareID: str("sw"), SoftwareVersion: str("1.2"),
		SoftwareStatement: str("eyJ.statement"), CIMDExpiresAt: at(time.Hour), CIMDETag: str(`"v1"`), CIMDLastModified: str("Wed, 30 Sep 2026 11:00:00 GMT"),
	}
}

// bareClient is a public client with every optional field unset.
func bareClient(id string, created time.Time) oauthprovider.ClientRecord {
	return oauthprovider.ClientRecord{ID: id, Name: id, RedirectURIs: "https://app.example/cb", Scopes: "openid", GrantTypes: "authorization_code", AuthMethod: "none", RequirePKCE: true, CreatedAt: created, UpdatedAt: created}
}

// code is a live, unspent code of user at client, stored under the hash of
// label.
func code(id, label, user, client string) oauthprovider.CodeRecord {
	return oauthprovider.CodeRecord{
		ID: id, Hash: hash(label), ClientID: client, UserID: user, SessionID: "ses_" + id, RedirectURI: "https://app.example/cb",
		Scopes: "openid offline_access", Challenge: str("challenge-" + id), ChallengeMethod: str("S256"), Nonce: str("nonce-" + id),
		AuthTime: now.Add(-time.Minute), ExpiresAt: now.Add(10 * time.Minute), CreatedAt: now, Resource: str("https://api.example"),
		Claims: str("email"), DPoPJKT: str("jkt-" + id), ReferenceID: str("org_1"),
	}
}

// token is a live issuance with a refresh token, every field set.
func token(id, family, user, client, session string) oauthprovider.TokenRecord {
	t := oauthprovider.TokenRecord{
		ID: id, AccessHash: hash("access-" + id), RefreshHash: hash("refresh-" + id), Family: family, ClientID: client,
		UserID: str(user), Scopes: "openid offline_access", AccessExpiresAt: now.Add(time.Hour), RefreshExpiresAt: at(30 * 24 * time.Hour),
		AuthTime: at(-time.Minute), CreatedAt: now, Resource: str("https://api.example"), Claims: str("email"), JKT: str("jkt-" + id),
		X5T: str("x5t-" + id), ReferenceID: str("org_1"),
	}
	if session != "" {
		t.SessionID = str(session)
	}
	return t
}

// consent is a consent of user to client.
func consent(id, user, client, scopes string, created time.Time) oauthprovider.ConsentRecord {
	return oauthprovider.ConsentRecord{ID: id, UserID: user, ClientID: client, Scopes: scopes, Claims: str("email"), ReferenceID: str("org_1"), Resources: str("https://api.example"), CreatedAt: created, UpdatedAt: created}
}

// diff names the first field where got and want differ, "" when they are
// the same. Times compare by instant (a database may hand them back in
// another zone), byte slices by content, nil and empty alike.
func diff(got, want any) string {
	g, w := reflect.ValueOf(got), reflect.ValueOf(want)
	for i := range g.NumField() {
		name := g.Type().Field(i).Name
		a, b := g.Field(i).Interface(), w.Field(i).Interface()
		switch av := a.(type) {
		case time.Time:
			if !av.Equal(b.(time.Time)) {
				return fmt.Sprintf("%s: got %v, want %v", name, av, b)
			}
		case *time.Time:
			bv := b.(*time.Time)
			if (av == nil) != (bv == nil) || (av != nil && !av.Equal(*bv)) {
				return fmt.Sprintf("%s: got %v, want %v", name, show(av), show(bv))
			}
		case []byte:
			// Hashes: compared in constant time like every secret, although
			// only test values pass here.
			if subtle.ConstantTimeCompare(av, b.([]byte)) != 1 {
				return fmt.Sprintf("%s: got %x, want %x", name, av, b)
			}
		default:
			if !reflect.DeepEqual(a, b) {
				return fmt.Sprintf("%s: got %v, want %v", name, deref(a), deref(b))
			}
		}
	}
	return ""
}

// show prints a time pointer readably.
func show(t *time.Time) string {
	if t == nil {
		return "nil"
	}
	return t.UTC().String()
}

// deref prints a string pointer's value rather than its address.
func deref(v any) any {
	if p, ok := v.(*string); ok {
		if p == nil {
			return "nil"
		}
		return fmt.Sprintf("%q", *p)
	}
	return v
}

// same fails t when got differs from want.
func same(t T, what string, got, want any) {
	if d := diff(got, want); d != "" {
		t.Fatalf("%s: %s", what, d)
	}
}

// must fails t on err.
func must(t T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

// notFound fails t unless err is ErrRecordNotFound.
func notFound(t T, what string, err error) {
	if !errors.Is(err, oauthprovider.ErrRecordNotFound) {
		t.Fatalf("%s = %v, want ErrRecordNotFound", what, err)
	}
}

// race runs fn in Racers goroutines released at once and returns every
// result; the first error other than those ok accepts fails t after all
// have finished.
func race[R any](t T, fn func() (R, error)) []R {
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		out  []R
		errs []error
	)
	start := make(chan struct{})
	for range Racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r, err := fn()
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			out = append(out, r)
		}()
	}
	close(start)
	wg.Wait()
	if len(errs) > 0 {
		t.Fatalf("racing callers failed: %v", errors.Join(errs...))
	}
	return out
}

// count is how many of bs are true.
func count(bs []bool) int {
	n := 0
	for _, b := range bs {
		if b {
			n++
		}
	}
	return n
}

// cases is every contract, by name, so a failure names the rule it broke.
var cases = map[string]func(t T, s oauthprovider.Store){
	"client: every field round-trips, unknown is not found": func(t T, s oauthprovider.Store) {
		ctx := context.Background()
		full, bare := fullClient(ClientA, UserA, "org_1", now), bareClient(ClientB, now)
		must(t, s.InsertClient(ctx, full))
		must(t, s.InsertClient(ctx, bare))
		got, err := s.Client(ctx, ClientA)
		must(t, err)
		same(t, "Client(full)", got, full)
		got, err = s.Client(ctx, ClientB)
		must(t, err)
		same(t, "Client(bare)", got, bare)
		_, err = s.Client(ctx, "cl_unknown")
		notFound(t, "Client(unknown)", err)
	},
	"client: a taken id is ErrRecordExists and changes nothing": func(t T, s oauthprovider.Store) {
		ctx := context.Background()
		first := fullClient(ClientA, UserA, "org_1", now)
		must(t, s.InsertClient(ctx, first))
		if err := s.InsertClient(ctx, bareClient(ClientA, now)); !errors.Is(err, oauthprovider.ErrRecordExists) {
			t.Fatalf("second InsertClient = %v, want ErrRecordExists", err)
		}
		got, err := s.Client(ctx, ClientA)
		must(t, err)
		same(t, "Client after a refused insert", got, first)
	},
	"client: of racing inserts of one id exactly one succeeds": func(t T, s oauthprovider.Store) {
		ctx := context.Background()
		won := race(t, func() (bool, error) {
			err := s.InsertClient(ctx, bareClient(ClientA, now))
			if errors.Is(err, oauthprovider.ErrRecordExists) {
				return false, nil
			}
			return err == nil, err
		})
		if n := count(won); n != 1 {
			t.Fatalf("%d of %d racing inserts succeeded, want exactly 1", n, Racers)
		}
	},
	"client: an update writes only the fields it names": func(t T, s oauthprovider.Store) {
		ctx := context.Background()
		c := fullClient(ClientA, UserA, "org_1", now)
		must(t, s.InsertClient(ctx, c))
		ok, err := s.UpdateClient(ctx, oauthprovider.ClientUpdate{ID: ClientA, Record: oauthprovider.ClientRecord{Name: "Renamed"}, Fields: []oauthprovider.ClientField{oauthprovider.ClientFieldName}})
		must(t, err)
		if !ok {
			t.Fatal("UpdateClient of a stored client reported no match")
		}
		want := c
		want.Name = "Renamed"
		got, err := s.Client(ctx, ClientA)
		must(t, err)
		same(t, "Client after a name update", got, want)
		// A rotated secret changes the secret fields alone.
		ok, err = s.UpdateClient(ctx, oauthprovider.ClientUpdate{ID: ClientA, Record: oauthprovider.ClientRecord{SecretHash: hash("rotated"), SecretEncrypted: str("sealed-rotated"), UpdatedAt: now.Add(time.Hour)},
			Fields: []oauthprovider.ClientField{oauthprovider.ClientFieldSecretHash, oauthprovider.ClientFieldSecretEncrypted, oauthprovider.ClientFieldUpdatedAt}})
		must(t, err)
		want.SecretHash, want.SecretEncrypted, want.UpdatedAt = hash("rotated"), str("sealed-rotated"), now.Add(time.Hour)
		got, err = s.Client(ctx, ClientA)
		must(t, err)
		if !ok {
			t.Fatal("secret rotation reported no match")
		}
		same(t, "Client after a secret rotation", got, want)
		// Every field can be written, each to the value given.
		all := fullClient(ClientA, UserB, "org_2", now)
		all.Name, all.Scopes, all.SkipConsent, all.DisabledAt, all.OwnerID = "All", "openid", false, nil, str(UserB)
		ok, err = s.UpdateClient(ctx, oauthprovider.ClientUpdate{ID: ClientA, Record: all, Fields: oauthprovider.ClientFields})
		must(t, err)
		got, err = s.Client(ctx, ClientA)
		must(t, err)
		if !ok {
			t.Fatal("full update reported no match")
		}
		same(t, "Client after updating every field", got, all)
	},
	"client: unknown ids, unknown fields and a discovery guard write nothing": func(t T, s oauthprovider.Store) {
		ctx := context.Background()
		c := fullClient(ClientA, UserA, "org_1", now) // Discovery "cimd"
		must(t, s.InsertClient(ctx, c))
		if ok, err := s.UpdateClient(ctx, oauthprovider.ClientUpdate{ID: "cl_unknown", Record: c, Fields: []oauthprovider.ClientField{oauthprovider.ClientFieldName}}); err != nil || ok {
			t.Fatalf("UpdateClient(unknown) = %v, %v; want false, nil", ok, err)
		}
		if _, err := s.UpdateClient(ctx, oauthprovider.ClientUpdate{ID: ClientA, Record: oauthprovider.ClientRecord{Name: "x"}, Fields: []oauthprovider.ClientField{oauthprovider.ClientFieldName, "no_such_field"}}); !errors.Is(err, oauthprovider.ErrBadClientField) {
			t.Fatalf("UpdateClient with an unknown field = %v, want ErrBadClientField", err)
		}
		if ok, err := s.UpdateClient(ctx, oauthprovider.ClientUpdate{ID: ClientA, Record: oauthprovider.ClientRecord{Name: "x"}, Fields: []oauthprovider.ClientField{oauthprovider.ClientFieldName}, IfDiscovery: str("other")}); err != nil || ok {
			t.Fatalf("UpdateClient with a discovery that does not match = %v, %v; want false, nil", ok, err)
		}
		got, err := s.Client(ctx, ClientA)
		must(t, err)
		same(t, "Client after refused updates", got, c)
		if ok, err := s.UpdateClient(ctx, oauthprovider.ClientUpdate{ID: ClientA, Record: oauthprovider.ClientRecord{Name: "Matched"}, Fields: []oauthprovider.ClientField{oauthprovider.ClientFieldName}, IfDiscovery: str("cimd")}); err != nil || !ok {
			t.Fatalf("UpdateClient with a matching discovery = %v, %v; want true, nil", ok, err)
		}
	},
	"client: racing updates of different fields both land": func(t T, s oauthprovider.Store) {
		ctx := context.Background()
		c := bareClient(ClientA, now)
		must(t, s.InsertClient(ctx, c))
		var turn sync.Mutex
		n := 0
		race(t, func() (bool, error) {
			turn.Lock()
			n++
			disable := n%2 == 0
			turn.Unlock()
			if disable {
				return s.UpdateClient(ctx, oauthprovider.ClientUpdate{ID: ClientA, Record: oauthprovider.ClientRecord{DisabledAt: at(0)}, Fields: []oauthprovider.ClientField{oauthprovider.ClientFieldDisabledAt}})
			}
			return s.UpdateClient(ctx, oauthprovider.ClientUpdate{ID: ClientA, Record: oauthprovider.ClientRecord{Name: "Edited"}, Fields: []oauthprovider.ClientField{oauthprovider.ClientFieldName}})
		})
		got, err := s.Client(ctx, ClientA)
		must(t, err)
		if got.DisabledAt == nil || got.Name != "Edited" {
			t.Fatalf("after racing updates: disabled %v, name %q; a metadata edit undid a disable or the reverse", show(got.DisabledAt), got.Name)
		}
	},
	"client: filters by owner and reference, oldest first, and counts": func(t T, s oauthprovider.Store) {
		ctx := context.Background()
		c1 := fullClient("cl_storetest_1", UserA, "org_1", now.Add(time.Minute))
		c2 := fullClient("cl_storetest_2", UserA, "org_2", now)
		c3 := fullClient("cl_storetest_3", UserB, "org_1", now)
		c0 := fullClient("cl_storetest_0", UserA, "org_1", now.Add(time.Minute)) // ties c1 on time; id orders
		for _, c := range []oauthprovider.ClientRecord{c1, c2, c3, c0} {
			must(t, s.InsertClient(ctx, c))
		}
		ids := func(f oauthprovider.ClientFilter) string {
			got, err := s.Clients(ctx, f)
			must(t, err)
			n, err := s.CountClients(ctx, f)
			must(t, err)
			if int(n) != len(got) {
				t.Fatalf("CountClients = %d, Clients returned %d", n, len(got))
			}
			out := make([]string, len(got))
			for i, c := range got {
				out[i] = c.ID
			}
			return strings.Join(out, ",")
		}
		if got, want := ids(oauthprovider.ClientFilter{OwnerID: str(UserA)}), "cl_storetest_2,cl_storetest_0,cl_storetest_1"; got != want {
			t.Fatalf("Clients(owner a) = %s, want %s", got, want)
		}
		if got, want := ids(oauthprovider.ClientFilter{ReferenceID: str("org_1")}), "cl_storetest_3,cl_storetest_0,cl_storetest_1"; got != want {
			t.Fatalf("Clients(reference org_1) = %s, want %s", got, want)
		}
		if got, want := ids(oauthprovider.ClientFilter{OwnerID: str(UserA), ReferenceID: str("org_1")}), "cl_storetest_0,cl_storetest_1"; got != want {
			t.Fatalf("Clients(owner a, reference org_1) = %s, want %s", got, want)
		}
		if got := ids(oauthprovider.ClientFilter{OwnerID: str("")}); got != "" {
			t.Fatalf("Clients(owner \"\") = %s, want none: an empty owner must never select every client", got)
		}
		if got, want := ids(oauthprovider.ClientFilter{}), "cl_storetest_2,cl_storetest_3,cl_storetest_0,cl_storetest_1"; got != want {
			t.Fatalf("Clients(all) = %s, want %s", got, want)
		}
	},
	"client: delete removes its codes, tokens and consents, and nobody else's": func(t T, s oauthprovider.Store) {
		ctx := context.Background()
		must(t, s.InsertClient(ctx, bareClient(ClientA, now)))
		must(t, s.InsertClient(ctx, bareClient(ClientB, now)))
		must(t, s.InsertCode(ctx, code("cod_a", "code-a", UserA, ClientA)))
		must(t, s.InsertCode(ctx, code("cod_b", "code-b", UserA, ClientB)))
		must(t, s.InsertToken(ctx, token("tok_a", "fam_a", UserA, ClientA, "ses_1")))
		must(t, s.InsertToken(ctx, token("tok_b", "fam_b", UserA, ClientB, "ses_1")))
		must(t, s.InsertConsent(ctx, consent("cns_a", UserA, ClientA, "openid", now)))
		must(t, s.InsertConsent(ctx, consent("cns_b", UserA, ClientB, "openid", now)))
		ok, err := s.DeleteClient(ctx, ClientA)
		must(t, err)
		if !ok {
			t.Fatal("DeleteClient of a stored client reported none")
		}
		_, err = s.Client(ctx, ClientA)
		notFound(t, "Client(deleted)", err)
		_, _, err = s.RedeemCode(ctx, hash("code-a"), now)
		notFound(t, "RedeemCode(deleted client's code)", err)
		_, err = s.TokenByAccessHash(ctx, hash("access-tok_a"))
		notFound(t, "TokenByAccessHash(deleted client's token)", err)
		_, err = s.TokenByRefreshHash(ctx, hash("refresh-tok_a"))
		notFound(t, "TokenByRefreshHash(deleted client's token)", err)
		_, err = s.Consent(ctx, UserA, ClientA)
		notFound(t, "Consent(deleted client)", err)
		_, err = s.Client(ctx, ClientB)
		must(t, err)
		_, err = s.TokenByAccessHash(ctx, hash("access-tok_b"))
		must(t, err)
		_, err = s.Consent(ctx, UserA, ClientB)
		must(t, err)
		if _, ok, err := s.RedeemCode(ctx, hash("code-b"), now); err != nil || !ok {
			t.Fatalf("the other client's code: %v, %v", ok, err)
		}
		if ok, err := s.DeleteClient(ctx, ClientA); err != nil || ok {
			t.Fatalf("second DeleteClient = %v, %v; want false, nil", ok, err)
		}
	},
	"code: every field round-trips and a code is redeemed once": func(t T, s oauthprovider.Store) {
		ctx := context.Background()
		c := code("cod_1", "code-1", UserA, ClientA)
		must(t, s.InsertCode(ctx, c))
		got, won, err := s.RedeemCode(ctx, hash("code-1"), now)
		must(t, err)
		if !won {
			t.Fatal("the first RedeemCode did not win")
		}
		want := c
		want.ConsumedAt = &now
		same(t, "RedeemCode", got, want)
		got, won, err = s.RedeemCode(ctx, hash("code-1"), now.Add(time.Second))
		must(t, err)
		if won {
			t.Fatal("a spent code was redeemed again")
		}
		same(t, "RedeemCode of a spent code (the record the replay revokes from)", got, want)
		_, _, err = s.RedeemCode(ctx, hash("never-issued"), now)
		notFound(t, "RedeemCode(unknown)", err)
	},
	"code: of racing redemptions exactly one wins": func(t T, s oauthprovider.Store) {
		ctx := context.Background()
		must(t, s.InsertCode(ctx, code("cod_1", "code-1", UserA, ClientA)))
		won := race(t, func() (bool, error) {
			_, ok, err := s.RedeemCode(ctx, hash("code-1"), now)
			return ok, err
		})
		if n := count(won); n != 1 {
			t.Fatalf("%d of %d racing redemptions of one code won, want exactly 1", n, Racers)
		}
	},
	"code: a refused exchange's code is burned once": func(t T, s oauthprovider.Store) {
		ctx := context.Background()
		must(t, s.InsertCode(ctx, code("cod_1", "code-1", UserA, ClientA)))
		if ok, err := s.BurnCode(ctx, hash("code-1"), now); err != nil || !ok {
			t.Fatalf("BurnCode = %v, %v; want true, nil", ok, err)
		}
		if ok, err := s.BurnCode(ctx, hash("code-1"), now); err != nil || ok {
			t.Fatalf("second BurnCode = %v, %v; want false, nil", ok, err)
		}
		if _, ok, err := s.RedeemCode(ctx, hash("code-1"), now); err != nil || ok {
			t.Fatalf("RedeemCode of a burned code = %v, %v; want false, nil", ok, err)
		}
		if ok, err := s.BurnCode(ctx, hash("never-issued"), now); err != nil || ok {
			t.Fatalf("BurnCode(unknown) = %v, %v; want false, nil", ok, err)
		}
	},
	"code: a failed request's redemption is put back": func(t T, s oauthprovider.Store) {
		ctx := context.Background()
		must(t, s.InsertCode(ctx, code("cod_1", "code-1", UserA, ClientA)))
		if ok, err := s.RestoreCode(ctx, hash("code-1")); err != nil || ok {
			t.Fatalf("RestoreCode of an unspent code = %v, %v; want false, nil", ok, err)
		}
		if _, ok, err := s.RedeemCode(ctx, hash("code-1"), now); err != nil || !ok {
			t.Fatalf("RedeemCode = %v, %v", ok, err)
		}
		if ok, err := s.RestoreCode(ctx, hash("code-1")); err != nil || !ok {
			t.Fatalf("RestoreCode of a redeemed code = %v, %v; want true, nil", ok, err)
		}
		got, ok, err := s.RedeemCode(ctx, hash("code-1"), now.Add(time.Second))
		must(t, err)
		if !ok || got.ConsumedAt == nil || !got.ConsumedAt.Equal(now.Add(time.Second)) {
			t.Fatalf("RedeemCode after a restore = %v, consumed %s; want a new redemption", ok, show(got.ConsumedAt))
		}
		if ok, err := s.RestoreCode(ctx, hash("never-issued")); err != nil || ok {
			t.Fatalf("RestoreCode(unknown) = %v, %v; want false, nil", ok, err)
		}
	},
	"code: deleting a user's open codes keeps spent ones and stays in scope": func(t T, s oauthprovider.Store) {
		ctx := context.Background()
		must(t, s.InsertCode(ctx, code("cod_open", "open", UserA, ClientA)))
		must(t, s.InsertCode(ctx, code("cod_spent", "spent", UserA, ClientA)))
		must(t, s.InsertCode(ctx, code("cod_other_client", "other-client", UserA, ClientB)))
		must(t, s.InsertCode(ctx, code("cod_other_user", "other-user", UserB, ClientA)))
		if _, _, err := s.RedeemCode(ctx, hash("spent"), now); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DeleteCodes(ctx, oauthprovider.CodeFilter{OnlyUnredeemed: true}); !errors.Is(err, oauthprovider.ErrEmptyFilter) {
			t.Fatalf("DeleteCodes with no user or client = %v, want ErrEmptyFilter", err)
		}
		n, err := s.DeleteCodes(ctx, oauthprovider.CodeFilter{UserID: UserA, ClientID: ClientA, OnlyUnredeemed: true})
		must(t, err)
		if n != 1 {
			t.Fatalf("DeleteCodes = %d, want 1", n)
		}
		_, _, err = s.RedeemCode(ctx, hash("open"), now)
		notFound(t, "RedeemCode(deleted open code)", err)
		if _, ok, err := s.RedeemCode(ctx, hash("spent"), now); err != nil || ok {
			t.Fatalf("the spent code after DeleteCodes: %v, %v; it must stay so a replay still revokes its family", ok, err)
		}
		for _, label := range []string{"other-client", "other-user"} {
			if _, ok, err := s.RedeemCode(ctx, hash(label), now); err != nil || !ok {
				t.Fatalf("code %s outside the filter: %v, %v", label, ok, err)
			}
		}
	},
	"token: every field round-trips by either hash": func(t T, s oauthprovider.Store) {
		ctx := context.Background()
		full := token("tok_1", "fam_1", UserA, ClientA, "ses_1")
		bare := oauthprovider.TokenRecord{ID: "tok_2", AccessHash: hash("access-tok_2"), Family: "fam_2", ClientID: ClientA, Scopes: "api", AccessExpiresAt: now.Add(time.Hour), CreatedAt: now}
		must(t, s.InsertToken(ctx, full))
		must(t, s.InsertToken(ctx, bare))
		got, err := s.TokenByAccessHash(ctx, full.AccessHash)
		must(t, err)
		same(t, "TokenByAccessHash", got, full)
		got, err = s.TokenByRefreshHash(ctx, full.RefreshHash)
		must(t, err)
		same(t, "TokenByRefreshHash", got, full)
		got, err = s.TokenByAccessHash(ctx, bare.AccessHash)
		must(t, err)
		same(t, "TokenByAccessHash(no refresh token)", got, bare)
		_, err = s.TokenByAccessHash(ctx, hash("never-issued"))
		notFound(t, "TokenByAccessHash(unknown)", err)
		_, err = s.TokenByRefreshHash(ctx, full.AccessHash)
		notFound(t, "TokenByRefreshHash(an access token's hash)", err)
	},
	"token: a refresh token rotates once, never when revoked": func(t T, s oauthprovider.Store) {
		ctx := context.Background()
		must(t, s.InsertToken(ctx, token("tok_1", "fam_1", UserA, ClientA, "ses_1")))
		must(t, s.InsertToken(ctx, token("tok_2", "fam_2", UserA, ClientA, "ses_1")))
		got, won, err := s.RotateRefresh(ctx, hash("refresh-tok_1"), now)
		must(t, err)
		if !won || got.RotatedAt == nil || !got.RotatedAt.Equal(now) {
			t.Fatalf("first RotateRefresh = %v, rotated %s; want true at now", won, show(got.RotatedAt))
		}
		got, won, err = s.RotateRefresh(ctx, hash("refresh-tok_1"), now.Add(time.Second))
		must(t, err)
		if won || got.RotatedAt == nil || !got.RotatedAt.Equal(now) {
			t.Fatalf("second RotateRefresh = %v, rotated %s; want false, showing the first rotation", won, show(got.RotatedAt))
		}
		if _, err := s.RevokeTokens(ctx, oauthprovider.TokenFilter{Family: "fam_2"}, now); err != nil {
			t.Fatal(err)
		}
		got, won, err = s.RotateRefresh(ctx, hash("refresh-tok_2"), now)
		must(t, err)
		if won || got.RevokedAt == nil {
			t.Fatalf("RotateRefresh of a revoked token = %v, revoked %s; want false with the revocation", won, show(got.RevokedAt))
		}
		_, _, err = s.RotateRefresh(ctx, hash("never-issued"), now)
		notFound(t, "RotateRefresh(unknown)", err)
	},
	"token: a failed request's rotation is put back, never a revoked one": func(t T, s oauthprovider.Store) {
		ctx := context.Background()
		must(t, s.InsertToken(ctx, token("tok_1", "fam_1", UserA, ClientA, "ses_1")))
		must(t, s.InsertToken(ctx, token("tok_2", "fam_2", UserA, ClientA, "ses_1")))
		if ok, err := s.RestoreRefresh(ctx, hash("refresh-tok_1")); err != nil || ok {
			t.Fatalf("RestoreRefresh of an unrotated token = %v, %v; want false, nil", ok, err)
		}
		for _, id := range []string{"tok_1", "tok_2"} {
			if _, ok, err := s.RotateRefresh(ctx, hash("refresh-"+id), now); err != nil || !ok {
				t.Fatalf("RotateRefresh(%s) = %v, %v", id, ok, err)
			}
		}
		if ok, err := s.RestoreRefresh(ctx, hash("refresh-tok_1")); err != nil || !ok {
			t.Fatalf("RestoreRefresh = %v, %v; want true, nil", ok, err)
		}
		if _, ok, err := s.RotateRefresh(ctx, hash("refresh-tok_1"), now); err != nil || !ok {
			t.Fatalf("RotateRefresh after a restore = %v, %v; want a new rotation", ok, err)
		}
		if _, err := s.RevokeTokens(ctx, oauthprovider.TokenFilter{Family: "fam_2"}, now); err != nil {
			t.Fatal(err)
		}
		if ok, err := s.RestoreRefresh(ctx, hash("refresh-tok_2")); err != nil || ok {
			t.Fatalf("RestoreRefresh of a revoked token = %v, %v; want false: a revoked family stays revoked", ok, err)
		}
		got, err := s.TokenByRefreshHash(ctx, hash("refresh-tok_2"))
		must(t, err)
		if got.RotatedAt == nil {
			t.Fatal("RestoreRefresh changed a revoked token")
		}
		if ok, err := s.RestoreRefresh(ctx, hash("never-issued")); err != nil || ok {
			t.Fatalf("RestoreRefresh(unknown) = %v, %v; want false, nil", ok, err)
		}
	},
	"token: of racing rotations exactly one wins and every loser sees it": func(t T, s oauthprovider.Store) {
		ctx := context.Background()
		must(t, s.InsertToken(ctx, token("tok_1", "fam_1", UserA, ClientA, "ses_1")))
		type result struct {
			won     bool
			rotated *time.Time
		}
		results := race(t, func() (result, error) {
			r, ok, err := s.RotateRefresh(ctx, hash("refresh-tok_1"), now)
			return result{ok, r.RotatedAt}, err
		})
		wins := 0
		for _, r := range results {
			if r.won {
				wins++
			} else if r.rotated == nil {
				t.Fatal("a racer that lost the rotation got a record without RotatedAt: the provider would judge the reuse window on a stale row")
			}
		}
		if wins != 1 {
			t.Fatalf("%d of %d racing rotations won, want exactly 1", wins, Racers)
		}
	},
	"token: a family revoke ends every token of the family and no other, once": func(t T, s oauthprovider.Store) {
		ctx := context.Background()
		for _, tk := range []oauthprovider.TokenRecord{
			token("tok_1", "fam_1", UserA, ClientA, "ses_1"), token("tok_2", "fam_1", UserA, ClientA, "ses_1"),
			token("tok_3", "fam_1", UserA, ClientA, "ses_1"), token("tok_4", "fam_2", UserA, ClientA, "ses_1"),
		} {
			must(t, s.InsertToken(ctx, tk))
		}
		if n, err := s.RevokeTokens(ctx, oauthprovider.TokenFilter{ID: "tok_3"}, now.Add(-time.Minute)); err != nil || n != 1 {
			t.Fatalf("RevokeTokens(one id) = %d, %v; want 1", n, err)
		}
		n, err := s.RevokeTokens(ctx, oauthprovider.TokenFilter{Family: "fam_1"}, now)
		must(t, err)
		if n != 2 {
			t.Fatalf("family revoke = %d, want 2 (one of three was revoked before)", n)
		}
		for id, want := range map[string]*time.Time{"tok_1": at(0), "tok_2": at(0), "tok_3": at(-time.Minute), "tok_4": nil} {
			got, err := s.TokenByAccessHash(ctx, hash("access-"+id))
			must(t, err)
			if d := diff(struct{ RevokedAt *time.Time }{got.RevokedAt}, struct{ RevokedAt *time.Time }{want}); d != "" {
				t.Fatalf("%s after the family revoke: %s", id, d)
			}
		}
		if n, err := s.RevokeTokens(ctx, oauthprovider.TokenFilter{Family: "fam_1"}, now.Add(time.Second)); err != nil || n != 0 {
			t.Fatalf("repeated family revoke = %d, %v; want 0, so nobody is notified twice", n, err)
		}
	},
	"token: racing family revokes count each token once": func(t T, s oauthprovider.Store) {
		ctx := context.Background()
		const size = 5
		for i := range size {
			must(t, s.InsertToken(ctx, token(fmt.Sprintf("tok_%d", i), "fam_1", UserA, ClientA, "ses_1")))
		}
		counts := race(t, func() (int64, error) { return s.RevokeTokens(ctx, oauthprovider.TokenFilter{Family: "fam_1"}, now) })
		var total int64
		for _, n := range counts {
			total += n
		}
		if total != size {
			t.Fatalf("racing family revokes counted %d tokens in total, want %d", total, size)
		}
	},
	"token: revoking stays in scope and refuses an empty filter": func(t T, s oauthprovider.Store) {
		ctx := context.Background()
		for _, tk := range []oauthprovider.TokenRecord{
			token("tok_aa", "fam_1", UserA, ClientA, "ses_1"), token("tok_ab", "fam_2", UserA, ClientB, "ses_1"),
			token("tok_ba", "fam_3", UserB, ClientA, "ses_2"),
		} {
			must(t, s.InsertToken(ctx, tk))
		}
		if _, err := s.RevokeTokens(ctx, oauthprovider.TokenFilter{OnlyUnrevoked: true}, now); !errors.Is(err, oauthprovider.ErrEmptyFilter) {
			t.Fatalf("RevokeTokens(empty filter) = %v, want ErrEmptyFilter", err)
		}
		if _, err := s.Tokens(ctx, oauthprovider.TokenFilter{}); !errors.Is(err, oauthprovider.ErrEmptyFilter) {
			t.Fatalf("Tokens(empty filter) = %v, want ErrEmptyFilter", err)
		}
		live := func() string {
			var out []string
			for _, id := range []string{"tok_aa", "tok_ab", "tok_ba"} {
				got, err := s.TokenByAccessHash(ctx, hash("access-"+id))
				must(t, err)
				if got.RevokedAt == nil {
					out = append(out, id)
				}
			}
			return strings.Join(out, ",")
		}
		if got := live(); got != "tok_aa,tok_ab,tok_ba" {
			t.Fatalf("live after a refused empty revoke = %s, want every token", got)
		}
		if n, err := s.RevokeTokens(ctx, oauthprovider.TokenFilter{UserID: UserA, Family: "fam_3"}, now); err != nil || n != 0 {
			t.Fatalf("RevokeTokens(user a, user b's family) = %d, %v; want 0", n, err)
		}
		if n, err := s.RevokeTokens(ctx, oauthprovider.TokenFilter{UserID: UserA, ClientID: ClientA}, now); err != nil || n != 1 {
			t.Fatalf("RevokeTokens(user a at client a) = %d, %v; want 1", n, err)
		}
		if got := live(); got != "tok_ab,tok_ba" {
			t.Fatalf("live after revoking user a at client a = %s, want tok_ab,tok_ba", got)
		}
	},
	"token: an access-only revoke keeps the refresh token": func(t T, s oauthprovider.Store) {
		ctx := context.Background()
		must(t, s.InsertToken(ctx, token("tok_1", "fam_1", UserA, ClientA, "ses_1")))
		if n, err := s.RevokeAccess(ctx, "tok_1", now); err != nil || n != 1 {
			t.Fatalf("RevokeAccess = %d, %v; want 1", n, err)
		}
		got, err := s.TokenByAccessHash(ctx, hash("access-tok_1"))
		must(t, err)
		if got.AccessRevokedAt == nil || !got.AccessRevokedAt.Equal(now) || got.RevokedAt != nil {
			t.Fatalf("after RevokeAccess: access revoked %s, revoked %s; want now and nil", show(got.AccessRevokedAt), show(got.RevokedAt))
		}
		if n, err := s.RevokeAccess(ctx, "tok_1", now); err != nil || n != 0 {
			t.Fatalf("second RevokeAccess = %d, %v; want 0", n, err)
		}
		if _, won, err := s.RotateRefresh(ctx, hash("refresh-tok_1"), now); err != nil || !won {
			t.Fatalf("the refresh token after an access-only revoke: %v, %v; want it still rotatable", won, err)
		}
	},
	"token: listing by session, any session but one, and unrevoked": func(t T, s oauthprovider.Store) {
		ctx := context.Background()
		for _, tk := range []oauthprovider.TokenRecord{
			token("tok_s1", "fam_1", UserA, ClientA, "ses_1"), token("tok_s2", "fam_2", UserA, ClientA, "ses_2"),
			token("tok_none", "fam_3", UserA, ClientA, ""), token("tok_b", "fam_4", UserB, ClientA, "ses_1"),
		} {
			must(t, s.InsertToken(ctx, tk))
		}
		ids := func(f oauthprovider.TokenFilter) string {
			got, err := s.Tokens(ctx, f)
			must(t, err)
			var out []string
			for _, tk := range got {
				out = append(out, tk.ID)
			}
			slices.Sort(out)
			return strings.Join(out, ",")
		}
		for _, c := range []struct {
			f    oauthprovider.TokenFilter
			want string
		}{
			{oauthprovider.TokenFilter{UserID: UserA, SessionID: "ses_1"}, "tok_s1"},
			{oauthprovider.TokenFilter{UserID: UserA, AnySession: true}, "tok_s1,tok_s2"},
			{oauthprovider.TokenFilter{UserID: UserA, AnySession: true, ExceptSession: "ses_1"}, "tok_s2"},
			{oauthprovider.TokenFilter{ClientID: ClientA, SessionID: "ses_1"}, "tok_b,tok_s1"},
			{oauthprovider.TokenFilter{Family: "fam_3"}, "tok_none"},
		} {
			if got := ids(c.f); got != c.want {
				t.Fatalf("Tokens(%+v) = %s, want %s", c.f, got, c.want)
			}
		}
		if _, err := s.RevokeTokens(ctx, oauthprovider.TokenFilter{ID: "tok_s2"}, now); err != nil {
			t.Fatal(err)
		}
		if got := ids(oauthprovider.TokenFilter{UserID: UserA, AnySession: true, OnlyUnrevoked: true}); got != "tok_s1" {
			t.Fatalf("Tokens(unrevoked) = %s, want tok_s1", got)
		}
	},
	"token: ending and moving a session": func(t T, s oauthprovider.Store) {
		ctx := context.Background()
		must(t, s.InsertToken(ctx, token("tok_1", "fam_1", UserA, ClientA, "ses_1")))
		must(t, s.InsertToken(ctx, token("tok_2", "fam_2", UserA, ClientA, "ses_1")))
		must(t, s.InsertToken(ctx, token("tok_3", "fam_3", UserA, ClientA, "ses_2")))
		must(t, s.EndTokenSession(ctx, "tok_1", now, false))
		must(t, s.EndTokenSession(ctx, "tok_2", now, true))
		one, err := s.TokenByAccessHash(ctx, hash("access-tok_1"))
		must(t, err)
		if !one.AccessExpiresAt.Equal(now) || one.RevokedAt != nil {
			t.Fatalf("offline token after its session ended: access expires %v, revoked %s; want now and nil", one.AccessExpiresAt, show(one.RevokedAt))
		}
		two, err := s.TokenByAccessHash(ctx, hash("access-tok_2"))
		must(t, err)
		if !two.AccessExpiresAt.Equal(now) || two.RevokedAt == nil || !two.RevokedAt.Equal(now) {
			t.Fatalf("token after its session ended: access expires %v, revoked %s; want both now", two.AccessExpiresAt, show(two.RevokedAt))
		}
		must(t, s.MoveSession(ctx, "ses_1", "ses_9"))
		moved, err := s.Tokens(ctx, oauthprovider.TokenFilter{SessionID: "ses_9"})
		must(t, err)
		left, err := s.Tokens(ctx, oauthprovider.TokenFilter{SessionID: "ses_1"})
		must(t, err)
		kept, err := s.Tokens(ctx, oauthprovider.TokenFilter{SessionID: "ses_2"})
		must(t, err)
		if len(moved) != 2 || len(left) != 0 || len(kept) != 1 {
			t.Fatalf("after MoveSession: %d on the new session, %d on the old, %d on another; want 2, 0, 1", len(moved), len(left), len(kept))
		}
	},
	"token: the replay record is kept and replaced": func(t T, s oauthprovider.Store) {
		ctx := context.Background()
		must(t, s.InsertToken(ctx, token("tok_1", "fam_1", UserA, ClientA, "ses_1")))
		if _, found, err := s.Replay(ctx, "tok_1"); err != nil || found {
			t.Fatalf("Replay before SetReplay = %v, %v; want none", found, err)
		}
		first := oauthprovider.ReplayRecord{Sealed: "sealed-1", ExpiresAt: now.Add(time.Minute)}
		must(t, s.SetReplay(ctx, "tok_1", first))
		got, found, err := s.Replay(ctx, "tok_1")
		must(t, err)
		if !found {
			t.Fatal("Replay after SetReplay found none")
		}
		same(t, "Replay", got, first)
		second := oauthprovider.ReplayRecord{Sealed: "sealed-2", ExpiresAt: now.Add(2 * time.Minute)}
		must(t, s.SetReplay(ctx, "tok_1", second))
		got, _, err = s.Replay(ctx, "tok_1")
		must(t, err)
		same(t, "Replay after a second SetReplay", got, second)
		_, _, err = s.Replay(ctx, "tok_unknown")
		notFound(t, "Replay(unknown token)", err)
	},
	"consent: every field round-trips, one per user and client": func(t T, s oauthprovider.Store) {
		ctx := context.Background()
		c := consent("cns_1", UserA, ClientA, "openid email", now)
		must(t, s.InsertConsent(ctx, c))
		got, err := s.Consent(ctx, UserA, ClientA)
		must(t, err)
		same(t, "Consent", got, c)
		got, err = s.ConsentByID(ctx, UserA, "cns_1")
		must(t, err)
		same(t, "ConsentByID", got, c)
		_, err = s.ConsentByID(ctx, UserB, "cns_1")
		notFound(t, "ConsentByID(another user's)", err)
		_, err = s.Consent(ctx, UserB, ClientA)
		notFound(t, "Consent(none)", err)
		if err := s.InsertConsent(ctx, consent("cns_2", UserA, ClientA, "openid", now)); !errors.Is(err, oauthprovider.ErrRecordExists) {
			t.Fatalf("a second consent of one user to one client = %v, want ErrRecordExists", err)
		}
	},
	"consent: an update replaces the grant, never merges it": func(t T, s oauthprovider.Store) {
		ctx := context.Background()
		must(t, s.InsertConsent(ctx, consent("cns_1", UserA, ClientA, "openid email profile", now)))
		narrowed := oauthprovider.ConsentRecord{ID: "cns_1", UserID: UserA, ClientID: ClientA, Scopes: "openid", ReferenceID: str("org_2"), UpdatedAt: now.Add(time.Hour), CreatedAt: now}
		ok, err := s.UpdateConsent(ctx, narrowed)
		must(t, err)
		if !ok {
			t.Fatal("UpdateConsent of a stored consent reported none")
		}
		got, err := s.Consent(ctx, UserA, ClientA)
		must(t, err)
		same(t, "Consent after a narrowing update", got, narrowed)
		if ok, err := s.UpdateConsent(ctx, consent("cns_unknown", UserA, ClientA, "openid", now)); err != nil || ok {
			t.Fatalf("UpdateConsent(unknown) = %v, %v; want false, nil", ok, err)
		}
	},
	"consent: a user's consents, oldest first, and delete": func(t T, s oauthprovider.Store) {
		ctx := context.Background()
		must(t, s.InsertConsent(ctx, consent("cns_2", UserA, ClientA, "openid", now)))
		must(t, s.InsertConsent(ctx, consent("cns_1", UserA, ClientB, "openid", now)))
		must(t, s.InsertConsent(ctx, consent("cns_0", UserA, "cl_storetest_c", "openid", now.Add(time.Minute))))
		must(t, s.InsertConsent(ctx, consent("cns_b", UserB, ClientA, "openid", now)))
		list, err := s.Consents(ctx, UserA)
		must(t, err)
		var ids []string
		for _, c := range list {
			ids = append(ids, c.ID)
		}
		if got := strings.Join(ids, ","); got != "cns_1,cns_2,cns_0" {
			t.Fatalf("Consents = %s, want cns_1,cns_2,cns_0", got)
		}
		if ok, err := s.DeleteConsent(ctx, UserA, ClientA); err != nil || !ok {
			t.Fatalf("DeleteConsent = %v, %v; want true", ok, err)
		}
		if ok, err := s.DeleteConsent(ctx, UserA, ClientA); err != nil || ok {
			t.Fatalf("second DeleteConsent = %v, %v; want false", ok, err)
		}
		if _, err := s.Consent(ctx, UserB, ClientA); err != nil {
			t.Fatalf("another user's consent after a delete: %v", err)
		}
	},
	"sweep: removes what is spent and keeps what can still be refreshed": func(t T, s oauthprovider.Store) {
		ctx := context.Background()
		cutoff := now
		oldCode, liveCode := code("cod_old", "old", UserA, ClientA), code("cod_live", "live", UserA, ClientA)
		oldCode.ExpiresAt = cutoff.Add(-time.Second)
		must(t, s.InsertCode(ctx, oldCode))
		must(t, s.InsertCode(ctx, liveCode))
		accessOnly := token("tok_access_only", "fam_1", UserA, ClientA, "ses_1")
		accessOnly.RefreshHash, accessOnly.RefreshExpiresAt, accessOnly.AccessExpiresAt = nil, nil, cutoff.Add(-time.Second)
		bothDone := token("tok_both_done", "fam_2", UserA, ClientA, "ses_1")
		bothDone.AccessExpiresAt, bothDone.RefreshExpiresAt = cutoff.Add(-time.Hour), at(-time.Second)
		refreshable := token("tok_refreshable", "fam_3", UserA, ClientA, "ses_1")
		refreshable.AccessExpiresAt = cutoff.Add(-time.Hour)
		rotated := token("tok_rotated", "fam_3", UserA, ClientA, "ses_1")
		rotated.AccessExpiresAt, rotated.RotatedAt = cutoff.Add(-time.Hour), at(-2*time.Hour)
		accessLive := token("tok_access_live", "fam_4", UserA, ClientA, "ses_1")
		accessLive.RefreshHash, accessLive.RefreshExpiresAt = nil, nil
		for _, tk := range []oauthprovider.TokenRecord{accessOnly, bothDone, refreshable, rotated, accessLive} {
			must(t, s.InsertToken(ctx, tk))
		}
		n, err := s.Sweep(ctx, cutoff)
		must(t, err)
		if n != 3 && n != 0 {
			t.Fatalf("Sweep = %d, want 3 (or 0 from a store that expires records itself)", n)
		}
		_, _, err = s.RedeemCode(ctx, hash("old"), now)
		notFound(t, "an expired code after Sweep", err)
		if _, ok, err := s.RedeemCode(ctx, hash("live"), now); err != nil || !ok {
			t.Fatalf("a live code after Sweep: %v, %v", ok, err)
		}
		for _, id := range []string{"tok_access_only", "tok_both_done"} {
			_, err := s.TokenByAccessHash(ctx, hash("access-"+id))
			notFound(t, id+" after Sweep", err)
		}
		for _, id := range []string{"tok_refreshable", "tok_rotated", "tok_access_live"} {
			if _, err := s.TokenByAccessHash(ctx, hash("access-"+id)); err != nil {
				t.Fatalf("%s after Sweep: %v; a token whose refresh token still lives (rotated or not) must stay, or its replay could no longer revoke the family", id, err)
			}
		}
	},
	"user: deleting a user removes their clients, codes, tokens and consents only": func(t T, s oauthprovider.Store) {
		ctx := context.Background()
		must(t, s.InsertClient(ctx, fullClient(ClientA, UserA, "org_1", now)))
		must(t, s.InsertClient(ctx, fullClient(ClientB, UserB, "org_1", now)))
		must(t, s.InsertCode(ctx, code("cod_a", "code-a", UserA, ClientB)))
		must(t, s.InsertCode(ctx, code("cod_b", "code-b", UserB, ClientB)))
		must(t, s.InsertToken(ctx, token("tok_a", "fam_a", UserA, ClientB, "ses_a")))
		must(t, s.InsertToken(ctx, token("tok_b", "fam_b", UserB, ClientB, "ses_b")))
		must(t, s.InsertConsent(ctx, consent("cns_a", UserA, ClientB, "openid", now)))
		must(t, s.InsertConsent(ctx, consent("cns_b", UserB, ClientB, "openid", now)))
		must(t, s.DeleteUser(ctx, UserA))
		_, err := s.Client(ctx, ClientA)
		notFound(t, "the deleted user's client", err)
		_, _, err = s.RedeemCode(ctx, hash("code-a"), now)
		notFound(t, "the deleted user's code", err)
		_, err = s.TokenByAccessHash(ctx, hash("access-tok_a"))
		notFound(t, "the deleted user's token", err)
		_, err = s.Consent(ctx, UserA, ClientB)
		notFound(t, "the deleted user's consent", err)
		if _, err := s.Client(ctx, ClientB); err != nil {
			t.Fatalf("another user's client: %v", err)
		}
		if _, err := s.TokenByAccessHash(ctx, hash("access-tok_b")); err != nil {
			t.Fatalf("another user's token: %v", err)
		}
		if _, err := s.Consent(ctx, UserB, ClientB); err != nil {
			t.Fatalf("another user's consent: %v", err)
		}
		if _, ok, err := s.RedeemCode(ctx, hash("code-b"), now); err != nil || !ok {
			t.Fatalf("another user's code: %v, %v", ok, err)
		}
	},
}
