package authhttp

import "github.com/ubgo/auth"

// SignInMethod is one way to sign in that a page can offer as a button or a
// link: "Continue with GitHub", "Sign in with your company". It names an
// operation route, not a URL, because only the app knows where it mounted
// Handler; a page joins the route to that prefix (authui's APIPrefix).
//
// It is a browser navigation, a GET, on purpose: the route it names is a
// Query that answers with a redirect (an OAuth start, an SSO start), so a
// page offering it posts nothing and needs no origin check of its own. A
// method that needs JavaScript (a passkey ceremony) cannot be expressed as
// one and belongs in an app's own template.
//
//ds:def id=authhttp-signinmethod-7mx2qd9w owner=@khanakia stability=stable
type SignInMethod struct {
	// ID is unique among the methods, such as "oauth.github". A page keys
	// its translation on it ("authui.method." + ID) and a template may key
	// an icon on it.
	ID string
	// Kind groups methods for styling: "oauth", "sso", "passkey". A page
	// adds it as a class.
	Kind string
	// Label is the English button text, such as "Continue with GitHub".
	Label string
	// Route is the operation's route under the Handler prefix, such as
	// "/oauth/github/start" (auth.Operation.Route). It must start with one
	// "/": a page refuses anything else at start-up, so no method can
	// become a link to another site.
	Route string
	// Field, when set, makes the method a one-input GET form instead of a
	// link: the input's name, sent as a query parameter to Route, such as
	// "email" for an SSO start that finds the company by the address.
	Field string
	// FieldLabel is the English label of that input.
	FieldLabel string
}

// UIMethod is a plugin that offers sign-in methods to the pages an app
// renders, the ready-made authui pages included: an OAuth plugin lists one
// button per provider, an SSO plugin a "company sign-in" form. It is
// optional and read once, when the page handler is built.
//
// It lives here rather than in authui so a plugin can implement it without
// importing authui, which is a module of its own.
//
//ds:def id=authhttp-uimethod-3fn8vk2p owner=@khanakia stability=stable
type UIMethod interface {
	auth.Plugin
	SignInMethods() []SignInMethod
}

// SignInMethods collects every UIMethod plugin's methods, in plugin order,
// for a page that renders its own sign-in screen.
func SignInMethods(a *auth.Auth) []SignInMethod {
	var out []SignInMethod
	for _, p := range a.Plugins() {
		if m, ok := p.(UIMethod); ok {
			out = append(out, m.SignInMethods()...)
		}
	}
	return out
}
