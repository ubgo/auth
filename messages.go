package auth

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/ubgo/sqlb"
)

// MessageCatalog translates an error message for a locale. Message returns
// the text for code in locale, or false when the catalogue has none, in which
// case the error's declared (English) message is used, so a half-translated
// catalogue never produces an empty message.
//
// Why a catalogue and not translated errors: an Error is declared once at
// package level and its code is the contract; the message is presentation,
// chosen per request. A plugin never knows about languages, and an app can
// translate a plugin's codes without the plugin's help.
//
//ds:def id=core-messagecatalog-7qf3bn2x owner=@khanakia stability=stable
type MessageCatalog interface {
	Message(locale, code string) (string, bool)
}

// Messages is a MessageCatalog held in memory: locale tag, then error code,
// then the message. The lookup is the one PickLocale applies to templates:
// the exact tag, then its base language ("de-CH" falls back to "de"), both
// compared without regard to case, so a catalogue with "de" serves every
// German-speaking region, and a "de-CH" entry overrides it for one code only.
//
// Its JSON form is {"de": {"auth.signed_out": "..."}}, so a translation
// file unmarshals straight into it; docs/reference/error-codes.json lists
// every code with its English message as the template to translate.
//
//ds:def id=core-messages-2hv8kr4m owner=@khanakia stability=stable
type Messages map[string]map[string]string

// Message implements MessageCatalog; see Messages for the lookup order.
func (m Messages) Message(locale, code string) (string, bool) {
	if locale == "" || len(m) == 0 {
		return "", false
	}
	base, _, _ := strings.Cut(locale, "-")
	for _, want := range []string{locale, base} {
		for tag, byCode := range m {
			if !strings.EqualFold(tag, want) {
				continue
			}
			if msg, ok := byCode[code]; ok && msg != "" {
				return msg, true
			}
		}
	}
	return "", false
}

// WithMessages sets the catalogue every transport renders error messages
// from, in the request's locale (Client.Locale, then WithDefaultLocale).
// Without one, or for a locale or code the catalogue lacks, the message is
// the declared English one; the code and the status never change, so a
// client matching codes sees no difference. New refuses a Messages map
// whose locale keys are not language tags, since a typo there would hide a
// whole language silently.
//
//ds:def id=opt-withmessages-9kd4ht7p owner=@khanakia stability=stable
func WithMessages(c MessageCatalog) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithMessages", c) {
			return
		}
		s.messages = c
	}
}

// checkMessages refuses a Messages catalogue with a locale key that is not a
// plausible language tag or is empty. Any other MessageCatalog is the app's
// own and is trusted.
func checkMessages(c MessageCatalog) error {
	m, ok := c.(Messages)
	if !ok {
		return nil
	}
	for tag := range m {
		if tag == "" {
			return fmt.Errorf("%w: message catalogue has an empty locale", ErrBadOperation)
		}
		if err := checkLocaleTag(tag); err != nil {
			return fmt.Errorf("message catalogue: %w", err)
		}
	}
	return nil
}

// Locale is the language of the request in ctx: the client's (Client.Locale)
// when it sent one, else WithDefaultLocale, else "". It is the one rule for
// messages sent and errors answered during the request, so a template and an
// error response never disagree about the user's language.
//
//ds:def id=core-locale-5mz7wq3n owner=@khanakia stability=stable
func (a *Auth) Locale(ctx context.Context) string {
	st := stateFrom(ctx)
	if l := a.storedLocale(ctx, st); l != "" {
		return l
	}
	if st != nil && st.req.Client.Locale != "" {
		return st.req.Client.Locale
	}
	return a.defaultLocale
}

// WithUserLocale names a text column of auth_user (one WithUserColumns
// declared) holding the user's chosen locale: for a signed-in request it wins
// over the client's Accept-Language and locale cookie, so a user who picked
// German in settings gets German mails and errors on any device. It is read
// lazily, once per request and only when a message or Locale needs it, and
// only once the session is resolved: an error answered before that (the
// session lookup's own) is in the client's locale. An empty or malformed
// value is ignored.
//
//ds:def id=opt-withuserlocale-6kq2wn8x owner=@khanakia stability=stable
func WithUserLocale(column string) Option { return func(s *settings) { s.userLocale = column } }

// resolveUserLocale checks WithUserLocale's column against the declared
// columns: it must be a text column on auth_user.
func (a *Auth) resolveUserLocale(name string) error {
	if name == "" {
		return nil
	}
	i := slices.IndexFunc(a.columns, func(c ColumnExtension) bool { return c.Name == name })
	if i < 0 || a.columns[i].Type != ColumnText {
		return fmt.Errorf("%w: WithUserLocale names %q, which is not a text column added to auth_user", ErrBadOperation, name)
	}
	a.localeColumn = name
	return nil
}

// storedLocale is the signed-in user's WithUserLocale value, or "".
func (a *Auth) storedLocale(ctx context.Context, st *requestState) string {
	if a.localeColumn == "" || st == nil || st.user == nil {
		return ""
	}
	st.localeOnce.Do(func() {
		var v *string
		col := sqlb.Col[*string](TableUser, a.localeColumn)
		if err := a.LoadUserColumns(ctx, st.user.ID, sqlb.Bind(col, &v)); err != nil {
			a.logger.Warn("auth: user locale", "error", err)
			return
		}
		if v != nil && *v != "" && checkLocaleTag(*v) == nil {
			st.userLocale = *v
		}
	})
	return st.userLocale
}

// ErrorInfo is ErrorOf in the request's language: the same code and status,
// with the message from the WithMessages catalogue when it has one for
// Locale(ctx) and the code, and then the declared message in
// OriginalMessage. A transport answers errors through it; a Go
// caller that shows errors to a person may too.
//
//ds:def id=core-auth-errorinfo-3xn6pv8q owner=@khanakia stability=stable
func (a *Auth) ErrorInfo(ctx context.Context, err error) ErrorInfo {
	info := ErrorOf(err)
	if a.messages == nil {
		return info
	}
	if msg, ok := a.messages.Message(a.Locale(ctx), info.Code); ok && msg != info.Message {
		info.OriginalMessage, info.Message = info.Message, msg
	}
	return info
}

// Translate returns the catalogue's text for code in the request's locale
// (Locale) and true, or "" and false when there is no catalogue or it lacks
// the code for that locale. It is ErrorInfo's lookup for text that is not an
// error: the fixed strings of a page the library renders itself, such as
// authhttp's error page, each keyed by a code that page documents, so one
// WithMessages catalogue translates the page and its errors together. A
// caller that gets false shows its English text and labels the page "en".
func (a *Auth) Translate(ctx context.Context, code string) (string, bool) {
	if a.messages == nil {
		return "", false
	}
	return a.messages.Message(a.Locale(ctx), code)
}

// ErrorInfoFor is Auth.ErrorInfo for a transport that holds only the request
// context: the request attached by WithRequest knows its Auth. With no
// request in ctx it is ErrorOf, the declared message.
//
//ds:def id=core-errorinfofor-8tq2wm5c owner=@khanakia stability=stable
func ErrorInfoFor(ctx context.Context, err error) ErrorInfo {
	if st := stateFrom(ctx); st != nil && st.a != nil {
		return st.a.ErrorInfo(ctx, err)
	}
	return ErrorOf(err)
}
