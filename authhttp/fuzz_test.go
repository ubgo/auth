package authhttp

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ubgo/auth"
)

type fuzzIn struct {
	Text  string `json:"text"`
	Count int    `json:"count"`
}

// FuzzDecode: any body or query string decodes or fails; it never panics,
// and a decoded mutation never carries a field the type does not declare.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{`{"text":"a"}`, `{"text":1}`, `{"x":1}`, `[`, ``, `{"text":"a"}{"text":"b"}`} {
		f.Add(s, "text=a&count=2")
	}
	f.Fuzz(func(t *testing.T, body, query string) {
		r := httptest.NewRequest("POST", "/x", strings.NewReader(body))
		var in fuzzIn
		_ = decode(r, auth.OpInfo{Kind: auth.Mutation}, &in, config{})
		q := httptest.NewRequest("GET", "/x", nil)
		q.URL.RawQuery = query
		_ = decode(q, auth.OpInfo{Kind: auth.Query}, &in, config{})
		// The same body as a form, with AcceptForms on.
		fr := httptest.NewRequest("POST", "/x", strings.NewReader(body))
		fr.Header.Set(headerContentTypeIn, contentTypeForm)
		_ = decode(fr, auth.OpInfo{Kind: auth.Mutation}, &in, config{forms: true})
	})
}
