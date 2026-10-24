package authui

import (
	"net/http"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

// TextKey names one piece of page text: a heading, a label, a button, a
// notice. The keys share the "authui." prefix so a single auth.Messages map
// can hold an app's error translations and its page translations without a
// collision; the value of each key is the English text in DefaultTexts.
type TextKey string

// Page text keys. Every string a page shows that is not the user's own data
// or an error message (errors follow auth.WithMessages) is one of these;
// TestTexts_EveryKeyHasEnglish pins that each has an English default.
const (
	TextSignIn          TextKey = "authui.sign_in"
	TextCreateAccount   TextKey = "authui.create_account"
	TextPassword        TextKey = "authui.password"
	TextName            TextKey = "authui.name"
	TextRemember        TextKey = "authui.remember"
	TextForgotLink      TextKey = "authui.forgot_link"
	TextMagicLabel      TextKey = "authui.magic_label"
	TextMagicButton     TextKey = "authui.magic_button"
	TextNoAccount       TextKey = "authui.no_account"
	TextSignUpLink      TextKey = "authui.sign_up_link"
	TextAcceptTerms     TextKey = "authui.accept_terms"
	TextTerms           TextKey = "authui.terms"
	TextHaveAccount     TextKey = "authui.have_account"
	TextForgotTitle     TextKey = "authui.forgot_title"
	TextSendReset       TextKey = "authui.send_reset"
	TextBackToSignIn    TextKey = "authui.back_to_sign_in"
	TextResetTitle      TextKey = "authui.reset_title"
	TextNewPassword     TextKey = "authui.new_password"
	TextSetPassword     TextKey = "authui.set_password"
	TextCode            TextKey = "authui.code"
	TextVerifyTitle     TextKey = "authui.verify_title"
	TextVerifyPrompt    TextKey = "authui.verify_prompt"
	TextVerifyButton    TextKey = "authui.verify_button"
	TextMagicPrompt     TextKey = "authui.magic_prompt"
	TextTwoFactorTitle  TextKey = "authui.two_factor_title"
	TextTwoFactorPrompt TextKey = "authui.two_factor_prompt"
	TextContinue        TextKey = "authui.continue"
	TextAccountTitle    TextKey = "authui.account_title"
	TextSignedInAs      TextKey = "authui.signed_in_as"
	TextProfile         TextKey = "authui.profile"
	TextSave            TextKey = "authui.save"
	TextCurrentPassword TextKey = "authui.current_password"
	TextChangePassword  TextKey = "authui.change_password"
	TextSessions        TextKey = "authui.sessions"
	TextUnknownDevice   TextKey = "authui.unknown_device"
	TextThisSession     TextKey = "authui.this_session"
	TextImpersonated    TextKey = "authui.impersonated"
	TextSince           TextKey = "authui.since"
	TextEndSession      TextKey = "authui.end_session"
	TextSignOut         TextKey = "authui.sign_out"
	TextSignOutAll      TextKey = "authui.sign_out_all"
	TextRefusedTitle    TextKey = "authui.refused_title"

	// The identifier field of each form. The English default is built from
	// the configured kinds ("Email or username"); a translation replaces the
	// whole label, because word order and capitals differ by language.
	TextSignInIdentifier TextKey = "authui.sign_in_identifier"
	TextSignUpIdentifier TextKey = "authui.sign_up_identifier"
	TextForgotIdentifier TextKey = "authui.forgot_identifier"

	// Notices, the fixed texts a ?notice= key selects.
	TextNoticeReset     TextKey = "authui.notice_reset"
	TextNoticeCheck     TextKey = "authui.notice_check"
	TextNoticeVerified  TextKey = "authui.notice_verified"
	TextNoticeSaved     TextKey = "authui.notice_saved"
	TextNoticeSignedOut TextKey = "authui.notice_signed_out"
	TextNoticePassword  TextKey = "authui.notice_password"
)

// englishTexts is the text of every key in English, the pages' own words.
// The identifier keys are absent: their English is built from the kinds.
var englishTexts = map[TextKey]string{
	TextSignIn:          "Sign in",
	TextCreateAccount:   "Create account",
	TextPassword:        "Password",
	TextName:            "Name",
	TextRemember:        "Keep me signed in",
	TextForgotLink:      "Forgot your password?",
	TextMagicLabel:      "Or get a sign-in link",
	TextMagicButton:     "Email me a link",
	TextNoAccount:       "No account?",
	TextSignUpLink:      "Sign up",
	TextAcceptTerms:     "I accept the",
	TextTerms:           "terms",
	TextHaveAccount:     "Have an account?",
	TextForgotTitle:     "Reset your password",
	TextSendReset:       "Send a reset link",
	TextBackToSignIn:    "Back to sign in",
	TextResetTitle:      "Choose a new password",
	TextNewPassword:     "New password",
	TextSetPassword:     "Set the new password",
	TextCode:            "Code",
	TextVerifyTitle:     "Verify your email",
	TextVerifyPrompt:    "Confirm this is your address.",
	TextVerifyButton:    "Verify",
	TextMagicPrompt:     "Continue to sign in.",
	TextTwoFactorTitle:  "Two-factor code",
	TextTwoFactorPrompt: "Enter the code from your authenticator app, or a recovery code.",
	TextContinue:        "Continue",
	TextAccountTitle:    "Account",
	TextSignedInAs:      "Signed in as",
	TextProfile:         "Profile",
	TextSave:            "Save",
	TextCurrentPassword: "Current password",
	TextChangePassword:  "Change password",
	TextSessions:        "Sessions",
	TextUnknownDevice:   "Unknown device",
	TextThisSession:     "(this one)",
	TextImpersonated:    "(an administrator)",
	TextSince:           "since",
	TextEndSession:      "End",
	TextSignOut:         "Sign out",
	TextSignOutAll:      "Sign out everywhere",
	TextRefusedTitle:    "Refused",
	TextNoticeReset:     "Your password was changed. Sign in with the new one.",
	TextNoticeCheck:     "If the account exists, a message is on its way.",
	TextNoticeVerified:  "Your address is verified.",
	TextNoticeSaved:     "Saved.",
	TextNoticeSignedOut: "You are signed out.",
	TextNoticePassword:  "Your password was changed. Other sessions were signed out.",
}

// DefaultTexts returns the English text of every key, as a translator's
// template: {"authui.sign_in": "Sign in", …}. Translate the values, put them
// under a locale in an auth.Messages map, and pass it to Texts (and, with
// the error codes, to auth.WithMessages). The identifier labels are not in
// it, because their English depends on the configured kinds; add
// TextSignInIdentifier and its siblings to translate them. It is a copy, so
// changing it changes nothing.
//
//ds:def id=authui-defaulttexts-r25ui01 owner=@khanakia stability=stable
func DefaultTexts() map[string]string {
	out := make(map[string]string, len(englishTexts))
	for k, v := range englishTexts {
		out[string(k)] = v
	}
	return out
}

// Texts translates the pages: every heading, label, button and notice is
// looked up in c by its TextKey in the request's locale (auth.Auth.Locale:
// the client's language, then auth.WithDefaultLocale), and a key c lacks
// shows its English text, so a half-done translation never shows a blank.
// An auth.Messages map works, the same one that translates the errors, and
// so does any auth.MessageCatalog. The page's lang attribute is the
// request's locale. Without Texts every page is in English.
//
//ds:def id=authui-texts-option-r25ui02 owner=@khanakia stability=stable
func Texts(c auth.MessageCatalog) Option { return func(cfg *config) { cfg.texts = c } }

// defaultLang is the lang attribute of a page with no request locale.
const defaultLang = "en"

// locale is the language of a page request: the one the core resolved when
// the request was attached (a form post), else the one authhttp reads from
// the request (a GET page, which attaches nothing), else
// auth.WithDefaultLocale. The same rule as the errors, so a page and its
// error never disagree.
func (h *handler) locale(r *http.Request) string {
	if l := authhttp.RequestOf(r, h.cfg.httpOpts...).Client.Locale; l != "" {
		return l
	}
	return h.a.Locale(r.Context())
}

// translator returns the text lookup for locale. fallback supplies the
// English of a key englishTexts lacks (the identifier labels).
func (h *handler) translator(locale string, fallback map[TextKey]string) func(TextKey) string {
	return func(k TextKey) string {
		if h.cfg.texts != nil {
			if s, ok := h.cfg.texts.Message(locale, string(k)); ok {
				return s
			}
		}
		if s, ok := englishTexts[k]; ok {
			return s
		}
		return fallback[k]
	}
}

// identifierTexts is the English of the three identifier labels, built from
// the configured kinds at start-up.
func (h *handler) identifierTexts() map[TextKey]string {
	return map[TextKey]string{
		TextSignInIdentifier: h.signIn.Label,
		TextSignUpIdentifier: h.signUp.Label,
		TextForgotIdentifier: h.forgot.Label,
	}
}
