package i18n

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/ubgo/auth"
)

// errorCodesFile is the generated list of every declared error, the English
// source the locale files translate.
const errorCodesFile = "../docs/reference/error-codes.json"

// declaredCodes reads every error code the library declares.
func declaredCodes(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(errorCodesFile)
	if err != nil {
		t.Fatal(err)
	}
	var list []struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	codes := map[string]bool{}
	for _, e := range list {
		codes[e.Code] = true
	}
	return codes
}

// The embedded files and Locales name the same languages, so a file added
// without its tag, or a tag without its file, fails here.
func TestLocales_MatchTheEmbeddedFiles(t *testing.T) {
	names, err := fs.Glob(files, localeDir+"/*"+localeExt)
	if err != nil {
		t.Fatal(err)
	}
	var tags []string
	for _, n := range names {
		tags = append(tags, strings.TrimSuffix(strings.TrimPrefix(n, localeDir+"/"), localeExt))
	}
	if !slices.Equal(tags, Locales) {
		t.Fatalf("files %v, Locales %v", tags, Locales)
	}
	if len(Locales) != 21 {
		t.Fatalf("21 locales beside English are expected; we have %d", len(Locales))
	}
}

// Every translation is for a code that exists, is not empty, and every
// locale translates the same codes: a renamed code leaves no stale key
// behind, and no language silently misses a message the others have.
func TestMessages_TranslateDeclaredCodesOnly(t *testing.T) {
	codes := declaredCodes(t)
	m := Messages()
	first := m[Locales[0]]
	for _, tag := range Locales {
		byCode := m[tag]
		if len(byCode) != len(first) {
			t.Errorf("%s has %d messages, %s has %d", tag, len(byCode), Locales[0], len(first))
		}
		for code, msg := range byCode {
			if !codes[code] {
				t.Errorf("%s translates %q, which no error declares", tag, code)
			}
			if strings.TrimSpace(msg) == "" {
				t.Errorf("%s: %q is empty", tag, code)
			}
			if _, ok := first[code]; !ok {
				t.Errorf("%s translates %q, %s does not", tag, code, Locales[0])
			}
		}
	}
	missing := 0
	for code := range codes {
		if _, ok := first[code]; !ok {
			missing++
		}
	}
	// A code declared after the translations falls back to English; the
	// count says how many are waiting for a translator.
	t.Logf("%d of %d declared codes untranslated", missing, len(codes))
}

// Wired into auth.New, a German request gets the German message with the
// same code and status, a regional tag finds its base language, and an
// English request keeps the declared message.
func TestMessages_WithAuth(t *testing.T) {
	a, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(signsIn{}), auth.WithMessages(Messages()))
	if err != nil {
		t.Fatal(err)
	}
	de := m(t, "de")
	for _, tc := range []struct{ locale, want string }{
		{"de-CH", de[auth.ErrSignedOut.Code]},
		{"de", de[auth.ErrSignedOut.Code]},
		{"en", auth.ErrSignedOut.Message},
	} {
		ctx := a.WithRequest(context.Background(), auth.Request{Client: auth.Client{Locale: tc.locale}})
		info := a.ErrorInfo(ctx, auth.ErrSignedOut)
		if info.Message != tc.want || info.Code != auth.ErrSignedOut.Code || info.Status != auth.ErrSignedOut.Status {
			t.Errorf("%s: %+v, want message %q", tc.locale, info, tc.want)
		}
	}
	if de[auth.ErrSignedOut.Code] == auth.ErrSignedOut.Message {
		t.Fatal("the German message is the English one")
	}
}

// signsIn is the smallest plugin auth.New accepts: a way in, no operations.
type signsIn struct{}

func (signsIn) Name() string                 { return "signsin" }
func (signsIn) SignsIn() bool                { return true }
func (signsIn) Operations() []auth.Operation { return nil }

// m reads one locale through MessagesFor.
func m(t *testing.T, tag string) map[string]string {
	t.Helper()
	cat, err := MessagesFor(tag)
	if err != nil {
		t.Fatal(err)
	}
	if len(cat) != 1 {
		t.Fatalf("MessagesFor(%q) loaded %d locales", tag, len(cat))
	}
	return cat[tag]
}

// A tag that is not shipped is an error naming the shipped ones, so a typo
// does not drop a language silently.
func TestMessagesFor_RefusesUnknownTag(t *testing.T) {
	_, err := MessagesFor("de", "klingon")
	if err == nil || !strings.Contains(err.Error(), "klingon") || !strings.Contains(err.Error(), "zh") {
		t.Fatalf("err = %v", err)
	}
}

// Messages returns a fresh map each call: editing one leaves the next intact.
func TestMessages_FreshCopy(t *testing.T) {
	one := Messages()
	one["de"][auth.ErrSignedOut.Code] = "changed"
	if Messages()["de"][auth.ErrSignedOut.Code] == "changed" {
		t.Fatal("Messages shares its maps between calls")
	}
}

// A missing or unparsable file is an error from load and a panic from
// mustLoad, the broken-build path.
func TestLoad_Failures(t *testing.T) {
	if _, err := load(fstest.MapFS{}, []string{"de"}); err == nil {
		t.Fatal("a missing file loaded")
	}
	bad := fstest.MapFS{localeDir + "/de" + localeExt: {Data: []byte("{")}}
	if _, err := load(bad, []string{"de"}); err == nil {
		t.Fatal("bad JSON loaded")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("mustLoad did not panic")
		}
	}()
	mustLoad(bad, []string{"de"})
}
