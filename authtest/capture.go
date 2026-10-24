package authtest

import (
	"context"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
)

// Mailbox records mail instead of sending it. It is an email.Mailer; build
// the email plugin with email.WithMailer(env.Mail). Every reader waits for
// the deliveries in flight first, because a message goes out after the
// transaction commits, in the background, and a test that read the box
// right after the request would race it.
//
//ds:def id=authtest-mailbox-8wn4kq2p owner=@khanakia stability=stable
type Mailbox struct {
	env  *Env
	mu   sync.Mutex
	sent []email.Mail
}

// Send records m.
func (m *Mailbox) Send(_ context.Context, mail email.Mail) error {
	m.mu.Lock()
	m.sent = append(m.sent, mail)
	m.mu.Unlock()
	return nil
}

// wait blocks until every delivery in flight finished. Before New finished
// there is no Auth and nothing in flight.
func (e *Env) wait() {
	if e != nil && e.Auth != nil {
		e.Auth.WaitDeliveries()
	}
}

// Sent returns every mail recorded so far, oldest first.
func (m *Mailbox) Sent() []email.Mail {
	m.env.wait()
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]email.Mail(nil), m.sent...)
}

// To returns the mail sent to addr, oldest first. addr is compared with the
// normalized address the plugin sends to, which is lower case.
func (m *Mailbox) To(addr string) []email.Mail {
	var out []email.Mail
	for _, x := range m.Sent() {
		if x.To == addr {
			out = append(out, x)
		}
	}
	return out
}

// Last returns the newest mail sent to addr, and false when there is none.
func (m *Mailbox) Last(addr string) (email.Mail, bool) {
	list := m.To(addr)
	if len(list) == 0 {
		return email.Mail{}, false
	}
	return list[len(list)-1], true
}

// LastLink returns the first URL in the newest mail to addr that carries a
// "token" query parameter: the verify, reset, sign-in or confirmation link.
// It fails the test when there is none.
//
//ds:def id=authtest-lastlink-2qm7xv9r owner=@khanakia stability=stable
func (m *Mailbox) LastLink(addr string) *url.URL {
	m.env.T.Helper()
	list := m.To(addr)
	for i := len(list) - 1; i >= 0; i-- {
		if u := linkWithToken(list[i].Text); u != nil {
			return u
		}
	}
	m.env.T.Fatalf("authtest: no link mailed to %s (%d mails)", addr, len(list))
	return nil
}

// LastToken returns the token of LastLink(addr).
func (m *Mailbox) LastToken(addr string) auth.Token {
	m.env.T.Helper()
	return auth.Token(m.LastLink(addr).Query().Get(tokenParam))
}

// LastCode returns the one-time code in the newest mail to addr, for the
// email plugin's codes. It fails the test when no mail carries one.
func (m *Mailbox) LastCode(addr string) string {
	m.env.T.Helper()
	list := m.To(addr)
	for i := len(list) - 1; i >= 0; i-- {
		if c := codeIn(list[i].Text); c != "" {
			return c
		}
	}
	m.env.T.Fatalf("authtest: no code mailed to %s (%d mails)", addr, len(list))
	return ""
}

// Reset forgets every recorded mail, so a test can assert on what one step
// sends.
func (m *Mailbox) Reset() {
	m.env.wait()
	m.mu.Lock()
	m.sent = nil
	m.mu.Unlock()
}

// tokenParam is the query parameter every link the library sends carries.
const tokenParam = "token"

// linkWithToken returns the first URL in text whose query has a token.
func linkWithToken(text string) *url.URL {
	for _, field := range strings.Fields(text) {
		u, err := url.Parse(field)
		if err != nil || u.Scheme == "" || u.Query().Get(tokenParam) == "" {
			continue
		}
		return u
	}
	return nil
}

// codePattern matches a one-time code: a run of digits of a length the core
// allows (MinCodeLength to MaxCodeLength), on its own.
var codePattern = regexp.MustCompile(`\b\d{` + strconv.Itoa(auth.MinCodeLength) + `,` + strconv.Itoa(auth.MaxCodeLength) + `}\b`)

// codeIn returns the first one-time code in text, or "".
func codeIn(text string) string { return codePattern.FindString(text) }

// SMSBox records text messages instead of sending them. It is a
// phone.SMSSender; build the phone plugin with phone.WithSMS(env.SMS).
//
//ds:def id=authtest-smsbox-4vk9tn3m owner=@khanakia stability=stable
type SMSBox struct {
	env  *Env
	mu   sync.Mutex
	sent map[string][]string
}

// Send records text for number.
func (s *SMSBox) Send(_ context.Context, number, text string) error {
	s.mu.Lock()
	if s.sent == nil {
		s.sent = map[string][]string{}
	}
	s.sent[number] = append(s.sent[number], text)
	s.mu.Unlock()
	return nil
}

// To returns the texts sent to number, oldest first, after every delivery
// in flight finished. number is the normalized E.164 form the plugin sends
// to.
func (s *SMSBox) To(number string) []string {
	s.env.wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.sent[number]...)
}

// LastCode returns the one-time code in the newest text to number. It fails
// the test when there is none.
//
//ds:def id=authtest-smslastcode-6yx2wq8h owner=@khanakia stability=stable
func (s *SMSBox) LastCode(number string) string {
	s.env.T.Helper()
	list := s.To(number)
	for i := len(list) - 1; i >= 0; i-- {
		if c := codeIn(list[i]); c != "" {
			return c
		}
	}
	s.env.T.Fatalf("authtest: no code texted to %s (%d texts)", number, len(list))
	return ""
}

// Reset forgets every recorded text.
func (s *SMSBox) Reset() {
	s.env.wait()
	s.mu.Lock()
	s.sent = nil
	s.mu.Unlock()
}
