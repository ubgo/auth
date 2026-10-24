package samlidp_test

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/samlidp"
)

// ecPair is a fresh P-256 key with a self-signed certificate.
func ecPair(t *testing.T, now time.Time) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "ec"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return key, cert
}

// signedRedirect builds an HTTP-Redirect URL whose query signature is made
// by sign over the octets SAML bindings 3.4.4.1 fixes, with extra appended
// to the query after the signature.
func (w *world) signedRedirect(alg string, sign func(octets []byte) []byte, extra string) string {
	w.t.Helper()
	w.sp.SignAuthnRequests = false
	doc, err := w.sp.BuildAuthRequestDocumentNoSig()
	if err != nil {
		w.t.Fatal(err)
	}
	raw, _ := doc.WriteToBytes()
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.BestCompression)
	_, _ = fw.Write(raw)
	_ = fw.Close()
	q := samlidp.ParamSAMLRequest + "=" + url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes())) +
		"&" + samlidp.ParamRelayState + "=" + url.QueryEscape(testRelay) + "&" + samlidp.ParamSigAlg + "=" + url.QueryEscape(alg)
	q += "&" + samlidp.ParamSignature + "=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sign([]byte(q)))) + extra
	return w.idp.SSOURL() + "?" + q
}

// accepted reports whether a page is the response form.
func accepted(p page) bool {
	return p.status == http.StatusOK && strings.Contains(p.body, samlidp.ParamSAMLResponse)
}

// Redirect signatures in every accepted algorithm verify against the SP's
// certificates; a signature that is not base64 is refused; a query with an
// unrelated repeated parameter falls back to the re-encoded octets.
func TestRedirectSignatureAlgorithms(t *testing.T) {
	now := time.Now()
	ecKey, ecCert := ecPair(t, now)
	w := newWorld(t, setup{spReg: func(sp *samlidp.ServiceProvider) {
		sp.RequireSignedRequests = true
		sp.Certificates = append(sp.Certificates, ecCert)
	}})
	w.env.Clock.Set(w.env.Clock.Now())
	rsaWith := func(h crypto.Hash, sum func([]byte) []byte) func([]byte) []byte {
		return func(b []byte) []byte {
			sig, err := rsa.SignPKCS1v15(rand.Reader, w.spKey, h, sum(b))
			if err != nil {
				t.Fatal(err)
			}
			return sig
		}
	}
	sha256Sum := func(b []byte) []byte { s := sha256.Sum256(b); return s[:] }
	sha512Sum := func(b []byte) []byte { s := sha512.Sum512(b); return s[:] }
	ecSign := func(b []byte) []byte {
		sig, err := ecdsa.SignASN1(rand.Reader, ecKey, sha256Sum(b))
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
	for name, u := range map[string]string{
		"rsa-sha256":       w.signedRedirect(samlidp.AlgRSASHA256, rsaWith(crypto.SHA256, sha256Sum), ""),
		"rsa-sha512":       w.signedRedirect(samlidp.AlgRSASHA512, rsaWith(crypto.SHA512, sha512Sum), ""),
		"ecdsa-sha256":     w.signedRedirect(samlidp.AlgECDSASHA256, ecSign, ""),
		"repeated unknown": w.signedRedirect(samlidp.AlgRSASHA256, rsaWith(crypto.SHA256, sha256Sum), "&x=1&x=2"),
	} {
		if p := w.get(u); !accepted(p) {
			t.Errorf("%s: %d %s", name, p.status, p.body)
		}
	}
	bad := w.signedRedirect(samlidp.AlgRSASHA256, func([]byte) []byte { return nil }, "")
	bad = strings.Replace(bad, samlidp.ParamSignature+"=&", samlidp.ParamSignature+"=%21%21%21&", 1)
	bad = strings.TrimSuffix(bad, samlidp.ParamSignature+"=") + samlidp.ParamSignature + "=%21%21%21"
	wantRefused(t, w.get(bad), samlidp.ErrInvalidSignature)

	// From Go, with a raw query that lacks SigAlg, the re-encoded values
	// are what is checked.
	u, _ := url.Parse(w.signedRedirect(samlidp.AlgRSASHA256, rsaWith(crypto.SHA256, sha256Sum), ""))
	q := u.Query()
	_, err := w.idp.SSO(w.env.Anonymous(context.Background()), samlidp.SSORequest{
		Binding: samlidp.BindingRedirect, SAMLRequest: q.Get(samlidp.ParamSAMLRequest), RelayState: q.Get(samlidp.ParamRelayState),
		SigAlg: q.Get(samlidp.ParamSigAlg), Signature: q.Get(samlidp.ParamSignature), RawQuery: "foo=bar",
	})
	if err != nil {
		t.Fatalf("re-encoded octets: %v", err)
	}
	if _, err := w.idp.SSO(w.env.Anonymous(context.Background()), samlidp.SSORequest{Binding: "urn:other", SAMLRequest: "x"}); !errors.Is(err, samlidp.ErrUnsupportedBinding) {
		t.Fatalf("unknown binding: %v", err)
	}
}

// An SP with no certificates cannot have its signature checked, so a signed
// request from it counts as unsigned and is accepted.
func TestSignedRequestWithoutCertificates(t *testing.T) {
	w := newWorld(t, setup{spReg: func(sp *samlidp.ServiceProvider) { sp.Certificates = nil }})
	u, _ := w.authnRedirect(true, nil)
	if p := w.get(u); !accepted(p) {
		t.Fatalf("signed redirect: %d %s", p.status, p.body)
	}
	v, _ := w.authnPOST(true, nil)
	if p := w.postForm(w.idp.SSOURL(), url.Values{samlidp.ParamSAMLRequest: {v}}); !accepted(p) {
		t.Fatalf("signed POST: %d %s", p.status, p.body)
	}
}

// Every malformed field of an AuthnRequest is refused.
func TestMalformedRequestFields(t *testing.T) {
	w := newWorld(t, setup{})
	for name, c := range map[string]struct {
		edit func(el *etree.Element)
		want *auth.Error
	}{
		"no issuer":   {func(el *etree.Element) { el.RemoveChildAt(el.FindElement("./Issuer").Index()) }, samlidp.ErrUnknownSP},
		"bad instant": {func(el *etree.Element) { el.CreateAttr("IssueInstant", "yesterday") }, samlidp.ErrInvalidRequest},
		"bad index": {func(el *etree.Element) {
			el.RemoveAttr("AssertionConsumerServiceURL")
			el.CreateAttr("AssertionConsumerServiceIndex", "x")
		}, samlidp.ErrInvalidRequest},
		"negative index": {func(el *etree.Element) {
			el.RemoveAttr("AssertionConsumerServiceURL")
			el.CreateAttr("AssertionConsumerServiceIndex", "-1")
		}, samlidp.ErrInvalidRequest},
		"bad is passive":  {func(el *etree.Element) { el.CreateAttr("IsPassive", "maybe") }, samlidp.ErrInvalidRequest},
		"id too long":     {func(el *etree.Element) { el.CreateAttr("ID", "_"+strings.Repeat("a", 300)) }, samlidp.ErrInvalidRequest},
		"passive numeric": {func(el *etree.Element) { el.CreateAttr("IsPassive", "0") }, nil},
	} {
		u, _ := w.authnRedirect(false, c.edit)
		p := w.get(u)
		if c.want == nil {
			if !accepted(p) {
				t.Errorf("%s: %d %s", name, p.status, p.body)
			}
			continue
		}
		wantRefused(t, p, c.want)
	}
	post := func(v string) page { return w.postForm(w.idp.SSOURL(), url.Values{samlidp.ParamSAMLRequest: {v}}) }
	wantRefused(t, post("!!!"), samlidp.ErrInvalidRequest)
	wantRefused(t, post(base64.StdEncoding.EncodeToString([]byte(`<Root><::Child/></Root>`))), samlidp.ErrInvalidRequest)
}

// A pending row the IdP cannot read, or for an SP since removed, is
// refused at the continue step.
func TestContinue_UnreadablePending(t *testing.T) {
	w := newWorld(t, setup{})
	ctx := context.Background()
	for meta, want := range map[string]error{
		"not json":              samlidp.ErrRequestNotFound,
		`{"sp":"https://gone"}`: samlidp.ErrUnknownSP,
	} {
		tok := auth.NewToken()
		if err := w.env.Auth.IssueVerificationToken(ctx, samlidp.PurposePending, "x", tok, time.Minute, meta); err != nil {
			t.Fatal(err)
		}
		if _, err := w.idp.Continue(w.env.SignIn(w.user.ID).Context(ctx), samlidp.ContinueRequest{Request: string(tok)}); !errors.Is(err, want) {
			t.Errorf("%s: got %v, want %v", meta, err, want)
		}
	}
}

// An Access refusal that is already an *auth.Error is answered as itself.
func TestAccess_KeepsItsOwnError(t *testing.T) {
	own := auth.NewError("samlidp_test.not_licensed", http.StatusPaymentRequired, "No seat left for this service.")
	w := newWorld(t, setup{opts: []samlidp.Option{samlidp.Access(func(context.Context, auth.User, samlidp.ServiceProvider) error { return own })}})
	u, _ := w.authnRedirect(false, nil)
	wantRefused(t, w.get(u), own)
}

// The initiate form refuses an oversized body and a repeated field.
func TestInitiate_FormRefusals(t *testing.T) {
	w := newWorld(t, setup{spReg: func(sp *samlidp.ServiceProvider) { sp.AllowIdPInitiated = true }})
	initURL := strings.TrimSuffix(w.idp.SSOURL(), "/sso") + "/initiate"
	post := func(body string) page {
		req, _ := http.NewRequest(http.MethodPost, initURL, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", w.idpSrv.URL)
		return w.do(req)
	}
	wantRefused(t, post("sp="+strings.Repeat("a", 200<<10)), samlidp.ErrInvalidRequest)
	wantRefused(t, post("sp=a&sp=b"), samlidp.ErrInvalidRequest)
}

// flakySigner is an RSA key whose failAt-th signature fails (0: never).
type flakySigner struct {
	key    *rsa.PrivateKey
	failAt int64
	n      atomic.Int64
}

func (s *flakySigner) Public() crypto.PublicKey { return s.key.Public() }

func (s *flakySigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s.n.Add(1) == s.failAt {
		return nil, errors.New("kms unavailable")
	}
	return s.key.Sign(r, digest, opts)
}

// A signer failure (a KMS outage) fails the request with no response: on
// the assertion, on the response envelope, and on a NoPassive answer.
func TestSignerFailure(t *testing.T) {
	for name, c := range map[string]struct {
		failAt  int64
		passive bool
	}{
		"assertion": {1, false},
		"envelope":  {2, false},
		"nopassive": {1, true},
	} {
		t.Run(name, func(t *testing.T) {
			var fs *flakySigner
			w := newWorld(t, setup{idpKey: func(t *testing.T, now time.Time) (crypto.Signer, *x509.Certificate) {
				key, cert := keyPair(t, "idp", now)
				fs = &flakySigner{key: key, failAt: c.failAt}
				return fs, cert
			}})
			if !c.passive {
				w.noLogin = false
			}
			u, _ := w.authnRedirect(false, func(el *etree.Element) {
				if c.passive {
					el.CreateAttr("IsPassive", "true")
				}
			})
			if p := w.get(u); p.status != http.StatusInternalServerError || strings.Contains(p.body, samlidp.ParamSAMLResponse) {
				t.Fatalf("%d %s", p.status, p.body)
			}
		})
	}
}

// Every database failure on the way to an answer reaches the caller:
// accepting a request, answering it signed in, and filing it again signed
// out; and the handler shows a failing session lookup as an error page.
func TestDatabaseFailuresSurface(t *testing.T) {
	fresh := func() (*world, *authtest.Faults) {
		f := authtest.NewFaults()
		return newWorld(t, setup{faults: f}), f
	}
	start := func(w *world) string {
		v, _ := w.authnPOST(false, nil)
		res, err := w.idp.SSO(w.env.Anonymous(context.Background()), samlidp.SSORequest{Binding: samlidp.BindingPOST, SAMLRequest: v})
		if err != nil {
			t.Fatal(err)
		}
		return res.RedirectTo[strings.Index(res.RedirectTo, "request=")+len("request="):]
	}
	authtest.SweepFaults(t, fresh, func(w *world) func(context.Context) error {
		v, _ := w.authnPOST(false, nil)
		return func(ctx context.Context) error {
			_, err := w.idp.SSO(w.env.Anonymous(ctx), samlidp.SSORequest{Binding: samlidp.BindingPOST, SAMLRequest: v})
			return err
		}
	})
	authtest.SweepFaults(t, fresh, func(w *world) func(context.Context) error {
		h := start(w)
		s := w.env.SignIn(w.user.ID)
		return func(ctx context.Context) error {
			_, err := w.idp.Continue(s.Context(ctx), samlidp.ContinueRequest{Request: h})
			return err
		}
	})
	authtest.SweepFaults(t, fresh, func(w *world) func(context.Context) error {
		h := start(w)
		return func(ctx context.Context) error {
			_, err := w.idp.Continue(w.env.Anonymous(ctx), samlidp.ContinueRequest{Request: h})
			return err
		}
	})

	w, f := fresh()
	h := start(w)
	req, _ := http.NewRequest(http.MethodGet, w.idp.ContinueURL(h), nil)
	req.AddCookie(w.env.SignIn(w.user.ID).Cookie())
	f.Arm(1)
	p := w.do(req)
	f.Disarm()
	if p.status < http.StatusInternalServerError || strings.Contains(p.body, samlidp.ParamSAMLResponse) {
		t.Fatalf("session lookup failure: %d %s", p.status, p.body)
	}
}
