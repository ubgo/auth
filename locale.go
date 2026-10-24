package auth

import "strings"

// PickLocale returns the entry of byLocale that best fits locale: the exact
// tag, then its base language ("de-CH" falls back to "de"), compared without
// regard to case. It is the one lookup rule every delivering plugin uses, so
// an app's translations are found the same way for mail and for SMS.
func PickLocale[T any](byLocale map[string]T, locale string) (T, bool) {
	var zero T
	if locale == "" || len(byLocale) == 0 {
		return zero, false
	}
	for k, v := range byLocale {
		if strings.EqualFold(k, locale) {
			return v, true
		}
	}
	base, _, _ := strings.Cut(locale, "-")
	for k, v := range byLocale {
		if strings.EqualFold(k, base) {
			return v, true
		}
	}
	return zero, false
}

// TruncateRunes cuts s to at most n characters, never inside a multi-byte
// character: a byte slice such as s[:n] can end halfway through "é" and store
// invalid UTF-8, which Postgres refuses outright. Plugins bound user-typed
// labels with it.
func TruncateRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	count := 0
	for i := range s {
		if count == n {
			return s[:i]
		}
		count++
	}
	return s
}
