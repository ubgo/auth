package hibp

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ubgo/auth/plugin/password"
)

func TestBreached_MatchesTheSuffixAndSendsOnlyThePrefix(t *testing.T) {
	sum := sha1.Sum([]byte("password123"))
	full := strings.ToUpper(hex.EncodeToString(sum[:]))
	pad := sha1.Sum([]byte("not this one"))
	padSuffix := strings.ToUpper(hex.EncodeToString(pad[:]))[5:]
	var asked string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.Path
		if r.Header.Get("Add-Padding") != "true" {
			t.Error("padding not requested")
		}
		_, _ = w.Write([]byte(full[5:] + ":42\r\n" + padSuffix + ":0\r\n"))
	}))
	defer srv.Close()
	c := New(WithBaseURL(srv.URL+"/range/"), WithHTTPClient(srv.Client()))
	if bad, err := c.Breached(context.Background(), "password123"); err != nil || !bad {
		t.Fatalf("known breach = %v %v", bad, err)
	}
	if asked != "/range/"+full[:5] {
		t.Fatalf("asked %q, want only the 5-character prefix", asked)
	}
	if bad, _ := c.Breached(context.Background(), "not this one"); bad {
		t.Fatal("a padding row with count 0 is not a breach")
	}
}

func TestBreached_FailsClosedUnlessToldOtherwise(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer srv.Close()
	if _, err := New(WithBaseURL(srv.URL+"/"), WithHTTPClient(srv.Client())).Breached(context.Background(), "x"); err == nil {
		t.Fatal("an unreachable service must be an error by default")
	}
	if bad, err := New(WithBaseURL(srv.URL+"/"), WithHTTPClient(srv.Client()), FailOpen()).Breached(context.Background(), "x"); err != nil || bad {
		t.Fatalf("FailOpen = %v %v", bad, err)
	}
}

var _ password.BreachChecker = (*Checker)(nil)

// TestBreached_BadBaseURLIsAnError: a base URL that does not parse fails the
// lookup, closed, rather than reporting "not breached".
func TestBreached_BadBaseURLIsAnError(t *testing.T) {
	if bad, err := New(WithBaseURL("://no-scheme/")).Breached(context.Background(), "x"); err == nil || bad {
		t.Fatalf("Breached = %v, %v; want an error", bad, err)
	}
}

// TestBreached_TransportErrorFailsClosed: a server that is gone is an error by
// default, not a silent pass.
func TestBreached_TransportErrorFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url, hc := srv.URL+"/", srv.Client()
	srv.Close()
	if bad, err := New(WithBaseURL(url), WithHTTPClient(hc)).Breached(context.Background(), "x"); err == nil || bad {
		t.Fatalf("Breached = %v, %v; want an error", bad, err)
	}
}

// TestBreached_SkipsLinesWithoutACount: a line that is not SUFFIX:COUNT is
// ignored, and a real match after it is still found.
func TestBreached_SkipsLinesWithoutACount(t *testing.T) {
	sum := sha1.Sum([]byte("hunter2"))
	suffix := strings.ToUpper(hex.EncodeToString(sum[:]))[prefixLen:]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(suffix + "\r\n" + "garbage line\r\n" + suffix + ":7\r\n"))
	}))
	defer srv.Close()
	if bad, err := New(WithBaseURL(srv.URL+"/"), WithHTTPClient(srv.Client())).Breached(context.Background(), "hunter2"); err != nil || !bad {
		t.Fatalf("Breached = %v, %v; want true", bad, err)
	}
}

// TestWithMessage: the checker carries the refusal's wording for the
// password plugin; none by default.
func TestWithMessage(t *testing.T) {
	if got := New().BreachedMessage(); got != "" {
		t.Fatalf("default message = %q", got)
	}
	if got := New(WithMessage("leaked")).BreachedMessage(); got != "leaked" {
		t.Fatalf("message = %q", got)
	}
}
