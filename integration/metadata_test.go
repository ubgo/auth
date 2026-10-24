package integration

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/magiclink"
	"github.com/ubgo/auth/plugin/phone"
)

// metaSMS is an SMSSender that also takes metadata, recording what it got.
type metaSMS struct {
	mu    sync.Mutex
	texts []string
	metas []map[string]string
}

func (s *metaSMS) Send(_ context.Context, _, text string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.texts = append(s.texts, text)
	s.metas = append(s.metas, nil)
	return nil
}

func (s *metaSMS) SendWithMetadata(_ context.Context, _, text string, m map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.texts = append(s.texts, text)
	s.metas = append(s.metas, m)
	return nil
}

// lastMailMeta returns the metadata of the newest mail to addr.
func lastMailMeta(t *testing.T, e *env, a *auth.Auth, addr string) map[string]string {
	t.Helper()
	list := e.mail.To(a, addr)
	if len(list) == 0 {
		t.Fatalf("no mail to %s", addr)
	}
	return list[len(list)-1].Metadata
}

// TestMetadata_ReachesTheSender: metadata on a magic-link or sign-in-code
// request reaches the Mailer with the message, an SMS sender that takes it
// gets it, one that does not gets the text alone, and an oversized map is
// refused before anything is sent.
func TestMetadata_ReachesTheSender(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, ml := e.emailPlugin(email.SignInWithCode()), magiclink.New()
		a := e.newAuth(t, nil, em, e.passwordPlugin(), ml)
		identUser(t, a, alice)
		meta := map[string]string{"invite": "inv_42", "return": "/boards/7"}
		if err := ml.SendWithMetadata(anon(a), alice, meta); err != nil {
			t.Fatal(err)
		}
		if got := lastMailMeta(t, e, a, alice); got["invite"] != "inv_42" || got["return"] != "/boards/7" {
			t.Fatalf("magic link mail metadata = %v", got)
		}
		if err := em.SendCodeWithMetadata(anon(a), alice, map[string]string{"campaign": "spring"}); err != nil {
			t.Fatal(err)
		}
		if got := lastMailMeta(t, e, a, alice); got["campaign"] != "spring" {
			t.Fatalf("sign-in code mail metadata = %v", got)
		}
		if err := ml.Send(anon(a), alice); err != nil {
			t.Fatal(err)
		}
		if got := lastMailMeta(t, e, a, alice); got != nil {
			t.Fatalf("a plain send carries metadata: %v", got)
		}
		// Bounds: too many entries, and a value too long.
		big := map[string]string{}
		for i := range email.MaxMetadataEntries + 1 {
			big[string(rune('a'+i))] = "x"
		}
		before := len(e.mail.To(a, alice))
		if err := ml.SendWithMetadata(anon(a), alice, big); !errors.Is(err, auth.ErrBadRequest) {
			t.Fatalf("too many entries = %v", err)
		}
		if err := em.SendCodeWithMetadata(anon(a), alice, map[string]string{"k": strings.Repeat("v", email.MaxMetadataLength+1)}); !errors.Is(err, auth.ErrBadRequest) {
			t.Fatalf("a value too long = %v", err)
		}
		if n := len(e.mail.To(a, alice)); n != before {
			t.Fatal("a refused request must send nothing")
		}
	})
	eachEngine(t, func(t *testing.T, e *env) {
		sms := &metaSMS{}
		ph := phone.New(phone.Login(), phone.WithSMS(sms))
		ml := magiclink.New()
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), ph, ml)
		uid, _ := identUser(t, a, alice)
		// The number is created verified through the core, so the sender
		// sees exactly two texts: a plain link, then one with metadata.
		must[auth.Identity](t)(a.CreateIdentity(context.Background(), auth.NewIdentity{UserID: uid, Kind: phone.KindPhone, Raw: phoneOld, Verified: true, Primary: true}))
		if err := ml.Send(anon(a), phoneOld); err != nil {
			t.Fatal(err)
		}
		if err := ml.SendWithMetadata(anon(a), phoneOld, map[string]string{"invite": "inv_42"}); err != nil {
			t.Fatal(err)
		}
		a.WaitDeliveries()
		sms.mu.Lock()
		defer sms.mu.Unlock()
		if len(sms.texts) != 2 || !strings.Contains(sms.texts[0], magiclink.DefaultPage) || !strings.Contains(sms.texts[1], magiclink.DefaultPage) {
			t.Fatalf("texts = %q", sms.texts)
		}
		// Deliveries run concurrently, so the order of the two is not fixed:
		// exactly one carried the metadata, the other none.
		with, without := 0, 0
		for _, m := range sms.metas {
			if m == nil {
				without++
			} else if m["invite"] == "inv_42" {
				with++
			}
		}
		if with != 1 || without != 1 {
			t.Fatalf("sms metadata = %v", sms.metas)
		}
	})
}
