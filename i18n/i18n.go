// Package i18n ships ready translations of every error message the library
// and its plugins declare, in 21 languages beside English, as an
// auth.Messages catalogue:
//
//	a, err := auth.New(..., auth.WithMessages(i18n.Messages()))
//
// The catalogue only changes the message: the code and the status of an
// error never change, so a client that matches codes sees no difference, and
// a code a locale does not translate (a plugin added after the translation)
// keeps its declared English message rather than an empty one. An app that
// wants its own voice merges or replaces entries: Messages returns a fresh
// map on every call, so editing it changes nothing anyone else holds.
//
// The translations live in locales/<tag>.json, one object of code to message
// per language, the same shape as docs/reference/error-codes.json lists the
// English ones in, so a file can be corrected or added without touching Go.
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/ubgo/auth"
)

// localeDir is the embedded directory the translation files live in.
const localeDir = "locales"

// localeExt is the extension of a translation file; the name before it is
// the locale tag.
const localeExt = ".json"

//go:embed locales/*.json
var files embed.FS

// Locales lists the tags Messages translates into, sorted: Arabic, Bengali,
// German, Spanish, Persian, French, Hindi, Indonesian, Italian, Japanese,
// Korean, Dutch, Polish, Portuguese, Russian, Swedish, Thai, Turkish,
// Ukrainian, Vietnamese and Chinese (Simplified). English is not in it: the
// declared messages are English, and a request in English gets them.
//
//ds:def id=i18n-locales-4tq8nw2k owner=@khanakia stability=stable
var Locales = []string{"ar", "bn", "de", "es", "fa", "fr", "hi", "id", "it", "ja", "ko", "nl", "pl", "pt", "ru", "sv", "th", "tr", "uk", "vi", "zh"}

// Messages returns the catalogue of every shipped locale, for
// auth.WithMessages. The lookup is auth.Messages': the request's exact tag,
// then its base language, so "pt-BR" and "zh-CN" find "pt" and "zh".
//
// It panics if an embedded file does not parse, which only a broken build
// can cause: the files are compiled in and a test parses every one.
func Messages() auth.Messages { return mustLoad(files, Locales) }

// MessagesFor is Messages restricted to the named locales, for an app that
// serves a few languages and wants no other in memory. A tag that is not in
// Locales is an error, so a typo does not silently leave a language out.
func MessagesFor(tags ...string) (auth.Messages, error) {
	for _, tag := range tags {
		if !slices.Contains(Locales, tag) {
			return nil, fmt.Errorf("i18n: no translation for locale %q; the shipped ones are %s", tag, strings.Join(Locales, ", "))
		}
	}
	return load(files, tags)
}

// mustLoad is load for the embedded files, whose failure is a broken build.
func mustLoad(fsys fs.FS, tags []string) auth.Messages {
	m, err := load(fsys, tags)
	if err != nil {
		panic(err)
	}
	return m
}

// load reads the named locales' files from fsys into one catalogue.
func load(fsys fs.FS, tags []string) (auth.Messages, error) {
	m := make(auth.Messages, len(tags))
	for _, tag := range tags {
		raw, err := fs.ReadFile(fsys, path.Join(localeDir, tag+localeExt))
		if err != nil {
			return nil, fmt.Errorf("i18n: locale %q: %w", tag, err)
		}
		byCode := map[string]string{}
		if err := json.Unmarshal(raw, &byCode); err != nil {
			return nil, fmt.Errorf("i18n: locale %q: %w", tag, err)
		}
		m[tag] = byCode
	}
	return m, nil
}
