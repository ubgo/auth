package magiclink_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/magiclink"
	"github.com/ubgo/auth/plugin/username"
)

var noMail = email.MailerFunc(func(context.Context, email.Mail) error { return nil })

func TestValidate(t *testing.T) {
	base := auth.WithBaseURL("https://app.example.com")
	// A handle has no verification flow: nothing can carry a link.
	if _, err := auth.New(base, auth.WithPlugins(username.New(username.Login()), magiclink.New())); !errors.Is(err, magiclink.ErrNoKinds) {
		t.Fatalf("handles only: %v", err)
	}
	if _, err := auth.New(base, auth.WithPlugins(email.New(email.Login(), email.WithMailer(noMail)), magiclink.New(magiclink.Kinds(username.KindUsername)))); !errors.Is(err, magiclink.ErrBadKinds) {
		t.Fatalf("an unusable kind: %v", err)
	}
	if _, err := auth.New(auth.WithPlugins(email.New(email.Login(), email.WithMailer(noMail), email.Links(func(auth.Purpose, auth.Token) string { return "x" })), magiclink.New())); !errors.Is(err, magiclink.ErrNoBase) {
		t.Fatalf("no base URL: %v", err)
	}
	// Email alone plus magic links is a complete app: the link is the way in.
	if _, err := auth.New(base, auth.WithPlugins(email.New(email.Login(), email.WithMailer(noMail)), magiclink.New())); err != nil {
		t.Fatalf("email + magic link: %v", err)
	}
}

func TestSendRequest_RateIdentifierFolds(t *testing.T) {
	if (magiclink.SendRequest{Identifier: " A@B.co "}).RateIdentifier() != "a@b.co" || !strings.HasPrefix(magiclink.DefaultPage, "/") {
		t.Fatal("rate key must fold like the normalizer")
	}
}
