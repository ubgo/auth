package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/ubgo/auth/plugin/email"
)

// DEMO ONLY. The demo keeps mail in memory and shows it in the React app's
// Inbox page, so every mailed flow (verification, password reset, magic link)
// can be tried with no mail server. A real app gives email.WithMailer an
// SMTP or email-API sender and never serves its mail over HTTP.

// mailboxSize is how many messages the inbox keeps; older ones fall off.
const mailboxSize = 50

// devMailPath is the demo-only route that lists the inbox (GET) and empties it (DELETE).
const devMailPath = "/dev/mail"

// linkPattern finds the URLs in a message's text, so the Inbox can show them as buttons.
var linkPattern = regexp.MustCompile(`https?://[^\s<>"]+`)

// devMessage is one sent message as the Inbox page reads it.
type devMessage struct {
	ID      string    `json:"id"`
	To      string    `json:"to"`
	Subject string    `json:"subject"`
	Text    string    `json:"text"`
	Links   []string  `json:"links"`
	SentAt  time.Time `json:"sentAt"`
}

// devMailbox is an email.Mailer that keeps the last mailboxSize messages.
type devMailbox struct {
	mu   sync.Mutex
	next int
	msgs []devMessage
}

// Send keeps the message and logs it, so the API session's log shows mail too.
func (b *devMailbox) Send(_ context.Context, m email.Mail) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.next++
	links := linkPattern.FindAllString(m.Text, -1)
	if links == nil {
		links = []string{}
	}
	b.msgs = append(b.msgs, devMessage{ID: strconv.Itoa(b.next), To: m.To, Subject: m.Subject, Text: m.Text, Links: links, SentAt: time.Now().UTC()})
	if len(b.msgs) > mailboxSize {
		b.msgs = b.msgs[len(b.msgs)-mailboxSize:]
	}
	log.Printf("mail to=%s subject=%q (shown in the demo Inbox)", m.To, m.Subject)
	return nil
}

// list returns the messages, newest first.
func (b *devMailbox) list() []devMessage {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]devMessage, len(b.msgs))
	for i, m := range b.msgs {
		out[len(b.msgs)-1-i] = m
	}
	return out
}

// clear empties the inbox.
func (b *devMailbox) clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.msgs = nil
}

// devMailResponse is what GET /dev/mail answers.
type devMailResponse struct {
	Messages []devMessage `json:"messages"`
}

// ServeHTTP serves the demo-only inbox route.
func (b *devMailbox) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(devMailResponse{Messages: b.list()}) // a client that hung up cannot be told
	case http.MethodDelete:
		b.clear()
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
