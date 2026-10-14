//go:build ldapserver

package ldap_test

// The Client against a real directory: lldap, started by `task test:ldap`
// from compose.yml's ldap profile with LDAPS on a certificate made for the
// run. Built only with -tags ldapserver, so `go test ./...` and task check
// never need a container; under the tag a missing server fails the test
// rather than skipping it.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth/plugin/ldap"
)

// The throwaway directory compose.yml's ldap profile starts.
const (
	serverLDAPS    = "ldaps://localhost:36360"
	serverLDAP     = "ldap://127.0.0.1:33890"
	serverBaseDN   = "ou=people,dc=example,dc=com"
	serverAdmin    = "admin"
	serverAdminDN  = "uid=admin,ou=people,dc=example,dc=com"
	serverPassword = "test-admin-password"
)

// serverTLS trusts only the certificate the task made for this run, so the
// test proves certificate verification is on, not skipped.
func serverTLS(t *testing.T) *tls.Config {
	t.Helper()
	pem, err := os.ReadFile(os.Getenv("AUTH_TEST_LDAP_CA"))
	if err != nil {
		t.Fatalf("AUTH_TEST_LDAP_CA: %v (run task test:ldap)", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("AUTH_TEST_LDAP_CA holds no certificate")
	}
	return &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12}
}

func serverClient(t *testing.T, cfg ldap.Config) *ldap.Client {
	t.Helper()
	cfg.BaseDN, cfg.BindDN, cfg.BindPassword, cfg.Timeout = serverBaseDN, serverAdminDN, serverPassword, 5*time.Second
	c, err := ldap.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestServer_LDAPS: over verified LDAPS the right password returns the
// entry with its cn and entryUUID (lldap's admin has no mail); a wrong
// password and an unknown user return the same ErrInvalidCredentials.
func TestServer_LDAPS(t *testing.T) {
	c := serverClient(t, ldap.Config{URL: serverLDAPS, TLS: serverTLS(t)})
	ctx := context.Background()
	e, err := c.Authenticate(ctx, serverAdmin, serverPassword)
	if err != nil {
		t.Fatalf("right password: %v", err)
	}
	if !strings.EqualFold(e.DN, serverAdminDN) || e.Get("cn") == "" || e.Get("entryUUID") == "" {
		t.Fatalf("entry = %+v; want the admin's DN, cn and entryUUID", e)
	}
	_, wrong := c.Authenticate(ctx, serverAdmin, "not-the-password")
	_, unknown := c.Authenticate(ctx, "nobody-here", "not-the-password")
	if !errors.Is(wrong, ldap.ErrInvalidCredentials) || !errors.Is(unknown, ldap.ErrInvalidCredentials) {
		t.Fatalf("wrong password = %v, unknown user = %v; want ErrInvalidCredentials for both", wrong, unknown)
	}
	_, injected := c.Authenticate(ctx, "*", serverPassword)
	if !errors.Is(injected, ldap.ErrInvalidCredentials) {
		t.Fatalf(`username "*": %v`, injected)
	}
}

// TestServer_UntrustedCertificateFails: with the system roots, which do not
// hold the run's self-signed certificate, the connection fails as an
// operational error, never as a wrong password and never by connecting.
func TestServer_UntrustedCertificateFails(t *testing.T) {
	c := serverClient(t, ldap.Config{URL: serverLDAPS})
	_, err := c.Authenticate(context.Background(), serverAdmin, serverPassword)
	if err == nil || errors.Is(err, ldap.ErrInvalidCredentials) {
		t.Fatalf("err = %v, want a certificate failure", err)
	}
}

// TestServer_PlainLDAPNeedsAllowInsecure: the plain port works only when the
// app said AllowInsecure, which NewClient otherwise refuses.
func TestServer_PlainLDAPNeedsAllowInsecure(t *testing.T) {
	if _, err := ldap.NewClient(ldap.Config{URL: serverLDAP, BaseDN: serverBaseDN}); !errors.Is(err, ldap.ErrInsecure) {
		t.Fatalf("plain ldap:// = %v, want ErrInsecure", err)
	}
	c := serverClient(t, ldap.Config{URL: serverLDAP, AllowInsecure: true})
	if _, err := c.Authenticate(context.Background(), serverAdmin, serverPassword); err != nil {
		t.Fatalf("plain ldap:// with AllowInsecure: %v", err)
	}
}
