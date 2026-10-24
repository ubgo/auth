package authui

import (
	"io/fs"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/magiclink"
)

// readTemplates returns every page template's source by file name.
func readTemplates(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := fs.WalkDir(files, "templates", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".html") {
			return err
		}
		b, err := files.ReadFile(path)
		out[path] = string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Patterns that strip a template down to the text it shows.
var (
	templateAction = regexp.MustCompile(`(?s)\{\{.*?\}\}`)
	htmlTag        = regexp.MustCompile(`(?s)<[^>]*>`)
	textKeyInUse   = regexp.MustCompile(`"(authui\.[a-z_]+)"`)
	letters        = regexp.MustCompile(`\p{L}+`)
)

// untranslatedWords are the only words a template may show outside a text
// key: the time zone of a session's start time, which is not language.
var untranslatedWords = map[string]bool{"UTC": true}

// TestTexts_EveryKeyHasEnglish: every key a template names and every key the
// Go code shows has an English default, and no template shows a word that
// does not go through a key, so a translation covers the whole page.
func TestTexts_EveryKeyHasEnglish(t *testing.T) {
	ids := map[TextKey]bool{TextSignInIdentifier: true, TextSignUpIdentifier: true, TextForgotIdentifier: true}
	for path, src := range readTemplates(t) {
		for _, m := range textKeyInUse.FindAllStringSubmatch(src, -1) {
			if _, ok := englishTexts[TextKey(m[1])]; !ok {
				t.Errorf("%s names %s, which has no English", path, m[1])
			}
		}
		shown := htmlTag.ReplaceAllString(templateAction.ReplaceAllString(src, " "), " ")
		for _, w := range letters.FindAllString(shown, -1) {
			if !untranslatedWords[w] {
				t.Errorf("%s shows %q outside a text key", path, w)
			}
		}
	}
	for _, k := range notices {
		if _, ok := englishTexts[k]; !ok {
			t.Errorf("notice %s has no English", k)
		}
	}
	for k := range englishTexts {
		if ids[k] {
			t.Errorf("%s is built from the kinds and must not have fixed English", k)
		}
	}
	d := DefaultTexts()
	if len(d) != len(englishTexts) || d[string(TextSignIn)] != "Sign in" {
		t.Fatalf("DefaultTexts = %d entries, sign in %q", len(d), d[string(TextSignIn)])
	}
	d[string(TextSignIn)] = "changed"
	if englishTexts[TextSignIn] != "Sign in" {
		t.Fatal("DefaultTexts must return a copy")
	}
}

// TestTexts_PagesFollowTheRequestLocale: with a German catalogue a German
// request gets German headings, labels, buttons, the identifier label and
// notices, and lang="de"; a key the catalogue lacks stays English; an
// English request and a page without Texts stay English with lang="en";
// the origin refusal stays in the default locale.
func TestTexts_PagesFollowTheRequestLocale(t *testing.T) {
	german := auth.Messages{"de": {
		string(TextSignIn):           "Anmelden",
		string(TextPassword):         "Passwort",
		string(TextSignInIdentifier): "E-Mail-Adresse",
		string(TextNoticeSignedOut):  "Sie sind abgemeldet.",
		string(TextRefusedTitle):     "Abgelehnt",
	}}
	a := uiAuth(t, nil, uiEmail(), uiPassword(), magiclink.New())
	h := Handler(a, Texts(german))
	de := func(r *http.Request) { r.Header.Set("Accept-Language", "de-AT") }

	body := serve(h, http.MethodGet, PathLogin+"?"+queryNotice+"="+noticeSignedOut, nil, de).Body.String()
	for _, want := range []string{`lang="de-AT"`, "<h1>Anmelden</h1>", "Passwort<input", "E-Mail-Adresse<input", "Sie sind abgemeldet.", englishTexts[TextRemember]} {
		if !strings.Contains(body, want) {
			t.Errorf("German login lacks %q", want)
		}
	}
	body = serve(h, http.MethodGet, PathLogin, nil).Body.String()
	for _, want := range []string{`lang="en"`, "<h1>Sign in</h1>", "Email<input"} {
		if !strings.Contains(body, want) {
			t.Errorf("English login lacks %q", want)
		}
	}
	body = serve(Handler(a), http.MethodGet, PathLogin, nil, de).Body.String()
	if !strings.Contains(body, "<h1>Sign in</h1>") {
		t.Error("without Texts a German request must still get English")
	}
	rec := serve(h, http.MethodPost, PathLogin, url.Values{}, de, func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") })
	if body := rec.Body.String(); rec.Code != http.StatusForbidden || !strings.Contains(body, "<h1>Refused</h1>") || !strings.Contains(body, `lang="en"`) {
		t.Fatalf("the origin refusal must use the default locale:\n%s", body)
	}
	b, err := auth.New(auth.WithBaseURL(uiBase), auth.WithPlugins(uiEmail(), uiPassword()), auth.WithRateStore(auth.NewMemoryRateStore(time.Now)), auth.WithDefaultLocale("de"))
	if err != nil {
		t.Fatal(err)
	}
	if body := serve(Handler(b, Texts(german)), http.MethodGet, PathLogin, nil).Body.String(); !strings.Contains(body, "<h1>Anmelden</h1>") || !strings.Contains(body, `lang="de"`) {
		t.Fatalf("WithDefaultLocale must pick the German page:\n%s", body)
	}
}
