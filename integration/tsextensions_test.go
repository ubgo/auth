package integration

import (
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/anonymous"
	"github.com/ubgo/auth/plugin/oauthproxy/oauthpopup"
)

// TestTypeScriptExtensions_PopupSpeaksTheWire: the TypeScript client's
// oauthPopup() names the message type, the default mount and every error
// code exactly as plugin/oauthproxy/oauthpopup does, so renaming one in Go
// fails here instead of making every popup sign-in time out. It lives in
// this module because oauthpopup is a module of its own, which the core's
// authhttp tests cannot import.
func TestTypeScriptExtensions_PopupSpeaksTheWire(t *testing.T) {
	a, err := auth.New(auth.WithBaseURL("https://auth.example.com"), auth.WithPlugins(anonymous.New()))
	if err != nil {
		t.Fatal(err)
	}
	files, err := authhttp.TypeScriptClient(a)
	if err != nil {
		t.Fatal(err)
	}
	ext := string(files[authhttp.TSFileExtensions])
	for _, want := range []string{
		`const OAUTH_POPUP_MESSAGE_TYPE = "` + oauthpopup.MessageType + `";`,
		`const OAUTH_POPUP_DEFAULT_MOUNT = "` + oauthpopup.DefaultMount + `";`,
	} {
		if !strings.Contains(ext, want) {
			t.Errorf("extensions.ts lacks %s", want)
		}
	}
	start := strings.Index(ext, "const OAUTH_POPUP_SERVER_CODES = [")
	end := strings.Index(ext[start:], "] as const;")
	if start < 0 || end < 0 {
		t.Fatal("extensions.ts lacks OAUTH_POPUP_SERVER_CODES")
	}
	list := ext[start : start+end]
	codes := []string{oauthpopup.ErrorSignInFailed, oauthpopup.ErrorBadCallback, oauthpopup.ErrorBadErrorURL, oauthpopup.ErrorBadNewUser, oauthpopup.ErrorNoProvider}
	for _, c := range codes {
		if !strings.Contains(list, `"`+c+`"`) {
			t.Errorf("OAUTH_POPUP_SERVER_CODES lacks %q", c)
		}
	}
	if n := strings.Count(list, `"`); n != 2*len(codes) {
		t.Errorf("OAUTH_POPUP_SERVER_CODES lists %d codes, oauthpopup declares %d", n/2, len(codes))
	}
}
