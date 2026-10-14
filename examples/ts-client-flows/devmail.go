package main

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"sync"

	"github.com/ubgo/auth/plugin/email"
)

// EXAMPLE ONLY. The inbox keeps every message in memory and serves it over
// HTTP so web/flows.ts can read its links and codes. A real app gives
// email.WithMailer an SMTP or email-API sender and never serves mail.

// devMailPath lists the messages sent to one address: GET /dev/mail?to=…
const devMailPath = "/dev/mail"

// toParam is the query parameter naming the recipient.
const toParam = "to"

var (
	// linkPattern finds the URL in a message (verification, reset, magic link, invitation).
	linkPattern = regexp.MustCompile(`https?://[^\s<>"]+`)
	// codePattern finds a typed code: the core's codes are six digits (auth.DefaultCodeLength).
	codePattern = regexp.MustCompile(`\b[0-9]{6}\b`)
)

// devMessage is one sent message as the script reads it: the first link
// and the first code in the text, "" when there is none.
type devMessage struct {
	Subject string `json:"subject"`
	Link    string `json:"link"`
	Code    string `json:"code"`
}

// devMailbox is an email.Mailer that keeps every message by recipient.
type devMailbox struct {
	mu   sync.Mutex
	sent map[string][]devMessage
}

// Send keeps the message under its recipient.
func (b *devMailbox) Send(_ context.Context, m email.Mail) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sent == nil {
		b.sent = map[string][]devMessage{}
	}
	b.sent[m.To] = append(b.sent[m.To], devMessage{Subject: m.Subject, Link: linkPattern.FindString(m.Text), Code: codePattern.FindString(m.Text)})
	return nil
}

// devMailResponse is what GET /dev/mail answers, oldest message first.
type devMailResponse struct {
	Messages []devMessage `json:"messages"`
}

// ServeHTTP answers the messages sent to ?to=, oldest first.
func (b *devMailbox) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	b.mu.Lock()
	msgs := append([]devMessage{}, b.sent[r.URL.Query().Get(toParam)]...)
	b.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(devMailResponse{Messages: msgs}) // a client that hung up cannot be told
}
