package lastlogin_test

import (
	"context"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/lastlogin"
)

var noMail = email.MailerFunc(func(context.Context, email.Mail) error { return nil })

// TestWiring: the plugin adds its two columns, owns their migrations, serves
// no route, and is no sign-in method by itself.
func TestWiring(t *testing.T) {
	if _, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(lastlogin.New())); err == nil {
		t.Fatal("last-login alone must not be a complete app")
	}
	a, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(email.New(email.Login(), email.SignInWithCode(), email.WithMailer(noMail)), lastlogin.New()))
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range a.Operations() {
		if op.Plugin() == lastlogin.PluginName {
			t.Fatalf("unexpected route %s", op.Route())
		}
	}
	cols := lastlogin.New().Columns()
	if len(cols) != 2 || cols[0].Name != lastlogin.ColMethod || cols[0].Type != auth.ColumnText || cols[1].Name != lastlogin.ColAt || !cols[1].Nullable {
		t.Fatalf("columns = %+v", cols)
	}
	ms, err := a.Migrations()
	if err != nil {
		t.Fatal(err)
	}
	owned := 0
	for _, m := range ms {
		if m.Owner == lastlogin.PluginName {
			owned++
		}
	}
	if owned != 2 {
		t.Fatalf("%d migrations owned by the plugin, want 2", owned)
	}
}

// TestDefaultResolver names the plugin from the operation id.
func TestDefaultResolver(t *testing.T) {
	for id, want := range map[auth.EndpointID]string{"password.sign-in": "password", "oauth.callback": "oauth", "bare": "bare"} {
		if got := lastlogin.DefaultResolver(context.Background(), auth.OpInfo{ID: id}, auth.Session{}); got != want {
			t.Fatalf("%s = %q, want %q", id, got, want)
		}
	}
}
