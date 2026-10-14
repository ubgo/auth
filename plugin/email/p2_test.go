package email_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
)

// ChangeWithoutVerification is warned about at every start, only when on.
func TestChangeWithoutVerification_Warns(t *testing.T) {
	for _, on := range []bool{false, true} {
		var buf bytes.Buffer
		var opts []email.Option
		if on {
			opts = append(opts, email.ChangeWithoutVerification())
		}
		opts = append(opts, email.WithMailer(noMail))
		if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithLogger(slog.New(slog.NewTextHandler(&buf, nil))), auth.WithPlugins(email.New(opts...), signIn{})); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(buf.String(), email.WarnChangeWithoutVerification) != on {
			t.Fatalf("on=%v: %q", on, buf.String())
		}
	}
}
