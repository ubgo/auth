// Command sso-client is "the wiki": a small web app that signs people in
// through the login server of examples/sso-server with OpenID Connect, then
// keeps its own session. It uses only the standard library, so it shows
// every check an OIDC client makes; a real app can use any OIDC client
// library instead.
//
//	export SESSION_SECRET=$(openssl rand -base64 32)
//	export ISSUER=https://login.example.com WIKI_URL=https://wiki.example.com
//	export CLIENT_ID=... CLIENT_SECRET_FILE=wiki.secret
//	go run ./sso-client
package main

import (
	"cmp"
	"context"
	"encoding/base64"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// Environment and defaults.
const (
	// envSessionSecret is base64 of at least minSessionSecret random bytes.
	envSessionSecret = "SESSION_SECRET"
	// minSessionSecret is the shortest session secret accepted.
	minSessionSecret = 32
	// defaultSecretFile is where auth oauth-client create --secret-file
	// wrote the client secret.
	defaultSecretFile = "wiki.secret"
	// readHeaderTimeout bounds a slow client's headers.
	readHeaderTimeout = 10 * time.Second
)

// port is where the app listens, $PORT or 8081, behind the TLS proxy that
// serves WIKI_URL.
var port string

func main() {
	secret, err := base64.StdEncoding.DecodeString(os.Getenv(envSessionSecret))
	if err != nil || len(secret) < minSessionSecret {
		log.Fatalf("%s must be base64 of at least %d random bytes: openssl rand -base64 32", envSessionSecret, minSessionSecret)
	}
	// The client secret is read from a file, not the environment, so it
	// never shows in a process listing or a shell history.
	clientSecret, err := os.ReadFile(cmp.Or(os.Getenv("CLIENT_SECRET_FILE"), defaultSecretFile))
	if err != nil {
		log.Fatal(err)
	}
	// PORT defaults to 8081 like every example; set it when sso-server runs
	// on the same machine.
	port = cmp.Or(os.Getenv("PORT"), "8081")
	app, err := NewApp(context.Background(), Config{
		Issuer:        cmp.Or(os.Getenv("ISSUER"), "https://login.example.com"),
		BaseURL:       cmp.Or(os.Getenv("WIKI_URL"), "https://wiki.example.com"),
		ClientID:      os.Getenv("CLIENT_ID"),
		ClientSecret:  strings.TrimSpace(string(clientSecret)),
		SessionSecret: secret,
	})
	if err != nil {
		log.Fatal(err)
	}
	// Serve behind a TLS-terminating proxy at WIKI_URL: the login server
	// accepts only https redirect URIs for a web app.
	log.Printf("listening on localhost:%s", port)
	srv := &http.Server{Addr: "localhost:" + port, Handler: app.Handler(), ReadHeaderTimeout: readHeaderTimeout}
	log.Fatal(srv.ListenAndServe())
}
