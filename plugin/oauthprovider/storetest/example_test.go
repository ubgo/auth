package storetest_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/oauthprovider"
	"github.com/ubgo/auth/plugin/oauthprovider/storetest"
)

// TestMemoryStore_Conforms is how a store proves itself: one call, a fresh
// empty store per case. A store on a shared server returns one with a fresh
// key prefix each time.
//
//ds:def id=storetest-run-example-5kq2wn8d
func TestMemoryStore_Conforms(t *testing.T) {
	storetest.Run(t, func(*testing.T) oauthprovider.Store {
		return storetest.NewMemoryStore()
	})
}

// newProvider keeps the provider's clients, codes, tokens and consents in
// store instead of the plugin's tables. Every other option is unchanged.
//
//ds:def id=withstore-provider-example-8wm3qk5v
func newProvider(jw *jwt.Plugin, store oauthprovider.Store) *oauthprovider.Plugin {
	return oauthprovider.New(jw,
		oauthprovider.Issuer("https://app.example.com"),
		oauthprovider.LoginPage("/login"),
		oauthprovider.WithStore(store),
	)
}

// The wiring compiles and starts with no option error.
func ExampleNewMemoryStore() {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	jw := jwt.New(jwt.WithSigningKey(key), jwt.Issuer("https://app.example.com"))
	op := newProvider(jw, storetest.NewMemoryStore())
	fmt.Println(op.OptionErr() == nil)
	// Output: true
}
