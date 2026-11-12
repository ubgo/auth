package social

import (
	"net/http"
	"strings"

	"github.com/ubgo/auth/authhttp"
)

// TextKey names one piece of page text: a heading, a sentence, a button.
// The keys share the "social." prefix so one auth.Messages map can hold an
// app's error translations, authui's page texts and these without a
// collision; the value of each key is the English text DefaultTexts returns.
type TextKey string

// Page text keys. Every string a page shows that is not the user's or the
// client's own data, or an error message (errors follow auth.WithMessages),
// is one of these; TestTexts_EveryKeyHasEnglish pins that each has English.
// A text with {name} has the client's or the provider's name put in its
// place, so a translation can move it where its language needs it.
const (
	TextSignInTitle        TextKey = "social.sign_in_title"
	TextContinueWith       TextKey = "social.continue_with"
	TextOpenApp            TextKey = "social.open_app"
	TextUnavailable        TextKey = "social.unavailable"
	TextNoAccessTitle      TextKey = "social.no_access_title"
	TextNoAccess           TextKey = "social.no_access"
	TextSignedInAs         TextKey = "social.signed_in_as"
	TextNoAccessHelp       TextKey = "social.no_access_help"
	TextThisApp            TextKey = "social.this_app"
	TextConsentTitle       TextKey = "social.consent_title"
	TextConsentWants       TextKey = "social.consent_wants"
	TextConsentNoScopes    TextKey = "social.consent_no_scopes"
	TextAllow              TextKey = "social.allow"
	TextDeny               TextKey = "social.deny"
	TextProblemTitle       TextKey = "social.problem_title"
	TextRequestExpired     TextKey = "social.request_expired"
	TextRefusedTitle       TextKey = "social.refused_title"
	TextScopeOpenID        TextKey = "social.scope.openid"
	TextScopeProfile       TextKey = "social.scope.profile"
	TextScopeEmail         TextKey = "social.scope.email"
	TextScopePhone         TextKey = "social.scope.phone"
	TextScopeAddress       TextKey = "social.scope.address"
	TextScopeOfflineAccess TextKey = "social.scope.offline_access"
)

// scopeTextPrefix starts the text key of a scope's description: the consent
// page shows scope s as the text of "social.scope.<s>", so an app describes
// its own scopes through Texts, and a scope with no text shows its name.
const scopeTextPrefix = "social.scope."

// ScopeText is the text key that describes scope on the consent page,
// "social.scope.<scope>". It exists so an app can word its own scopes
// ("Read your invoices" for "invoices:read") in the same catalogue as the
// rest of the page; a scope no catalogue describes is shown by its name.
//
//ds:def id=social-scopetext-qqq98pzv owner=@khanakia stability=stable
func ScopeText(scope string) TextKey { return TextKey(scopeTextPrefix + scope) }

// namePlaceholder is replaced by the client's or the provider's name in a
// text that has one.
const namePlaceholder = "{name}"

// englishTexts is the text of every key in English, the pages' own words.
var englishTexts = map[TextKey]string{
	TextSignInTitle:        "Sign in",
	TextContinueWith:       "Continue with {name}",
	TextOpenApp:            "Open the app you want to use. It brings you here to sign in.",
	TextUnavailable:        "Sign-in is not available right now.",
	TextNoAccessTitle:      "No access",
	TextNoAccess:           "Your account does not have access to {name}.",
	TextSignedInAs:         "Signed in as",
	TextNoAccessHelp:       "Ask the app's administrator if you think this is a mistake.",
	TextThisApp:            "this app",
	TextConsentTitle:       "Allow access",
	TextConsentWants:       "{name} would like to:",
	TextConsentNoScopes:    "Sign you in with your account.",
	TextAllow:              "Allow",
	TextDeny:               "Deny",
	TextProblemTitle:       "Something went wrong",
	TextRequestExpired:     "This request has expired or was changed. Go back to the app and start again.",
	TextRefusedTitle:       "Refused",
	TextScopeOpenID:        "Confirm who you are",
	TextScopeProfile:       "See your name and picture",
	TextScopeEmail:         "See your email address",
	TextScopePhone:         "See your phone number",
	TextScopeAddress:       "See your postal address",
	TextScopeOfflineAccess: "Stay connected when you are not using it",
}

// DefaultTexts returns the English text of every key, as a translator's
// template: {"social.sign_in_title": "Sign in", …}. Translate the values,
// put them under a locale in an auth.Messages map, and pass it to Texts. It
// is a copy, so changing it changes nothing.
//
//ds:def id=social-defaulttexts-f7b2mrpc owner=@khanakia stability=stable
func DefaultTexts() map[string]string {
	out := make(map[string]string, len(englishTexts))
	for k, v := range englishTexts {
		out[string(k)] = v
	}
	return out
}

// defaultLang is the lang attribute of a page with no request locale.
const defaultLang = "en"

// locale is the language of a page request: the one authhttp reads from the
// request, else the one the core resolved (auth.WithDefaultLocale at the
// least). The same rule authui and the errors follow.
func (p *Pages) locale(r *http.Request) string {
	if l := authhttp.RequestOf(r, p.cfg.httpOpts...).Client.Locale; l != "" {
		return l
	}
	return p.a.Locale(r.Context())
}

// translator returns the text lookup for locale: the app's catalogue first,
// then English. A key neither has is shown as itself without the scope
// prefix, which for a scope the app did not describe is the scope's name.
func (p *Pages) translator(locale string) func(TextKey) string {
	return func(k TextKey) string {
		if p.cfg.texts != nil {
			if s, ok := p.cfg.texts.Message(locale, string(k)); ok {
				return s
			}
		}
		if s, ok := englishTexts[k]; ok {
			return s
		}
		return strings.TrimPrefix(string(k), scopeTextPrefix)
	}
}
