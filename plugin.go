package auth

import (
	"fmt"
	"regexp"

	"github.com/ubgo/sqlb"
)

// Plugin is the only interface a plugin must satisfy.
//
// Every other capability is an optional interface that New type-asserts for.
// An absent capability is then simply absent, instead of an empty method that
// looks the same as a forgotten one in a review.
//
// Invariant: Name is stable, unique and matches KindNamePattern. It is the
// route prefix and the migration owner, so renaming a plugin orphans its
// recorded migrations in every deployment.
//
//ds:def id=core-plugin-ccn7kdrp owner=@khanakia stability=stable
type Plugin interface {
	Name() string
}

// Initializer receives the core handle once, during New.
//
//ds:def id=core-initializer-uv2s5atr owner=@khanakia stability=stable
type Initializer interface {
	Init(*Auth) error
}

// Validator checks what a plugin needs from the rest of the configuration.
//
//ds:def id=core-validator-mrnuqybj owner=@khanakia stability=stable
type Validator interface {
	Validate(*Config) error
}

// Dependent names plugins that must also be registered.
//
//ds:def id=core-dependent-c92t3h3e owner=@khanakia stability=stable
type Dependent interface {
	Requires() []string
}

// TableOwner declares the tables a plugin brings into statements, so New can
// detect an alias collision between plugins whose authors never met.
//
//ds:def id=core-tableowner-pwddjxec owner=@khanakia stability=stable
type TableOwner interface {
	Tables() []sqlb.Table
}

// SignInMethod is a plugin that can sign a user in. New refuses a plugin list
// in which none reports true, because such an app has no way for anyone to get
// in. A method rather than a marker so a plugin whose sign-in is optional, such
// as phone codes, can say that this configuration does not sign anyone in.
type SignInMethod interface {
	SignsIn() bool
}

// SessionChecker adds conditions every session must meet, such as "the user is
// not banned". The predicates join the one session lookup query, so they may
// use only auth_user and auth_session columns.
//
//ds:def id=core-sessionchecker-kuv234ty owner=@khanakia stability=stable
type SessionChecker interface {
	SessionPredicates() []sqlb.Predicate
}

// Closer releases resources when the app shuts down.
type Closer interface {
	Close() error
}

// PluginOf returns the registered plugin of type T. Generic so a caller gets
// its concrete type without an unchecked assertion that could panic.
//
//ds:def id=core-pluginof-9ydc98rf owner=@khanakia stability=stable
func PluginOf[T Plugin](a *Auth) (T, error) {
	var zero T
	for _, p := range a.plugins {
		if typed, ok := p.(T); ok {
			return typed, nil
		}
	}
	return zero, ErrPluginNotRegistered
}

// OriginTruster adds origins allowed to send cookie-authenticated mutations,
// such as an OAuth provider's form-post callback. New reads TrustedOrigins
// before any plugin's Init, so the list must not depend on Init's state.
type OriginTruster interface {
	TrustedOrigins() []string
}

// Close waits for messages in flight, then calls Close on every plugin that
// implements Closer, in reverse wiring order, and returns the first error.
func (a *Auth) Close() error {
	a.deliveries.Wait()
	a.closeSecurity()
	var first error
	for i := len(a.plugins) - 1; i >= 0; i-- {
		if c, ok := a.plugins[i].(Closer); ok {
			if err := c.Close(); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}

// qualifiedAlias finds each table alias a rendered Postgres statement
// qualifies a column with: "s"."id" yields s.
var qualifiedAlias = regexp.MustCompile(`"([^"]+)"\.`)

// checkSessionPredicates renders every plugin's session conditions into the
// session lookup, once, at New. A condition that fails to build, or that
// names a table other than auth_session and auth_user, would break every
// request's session lookup — found here, it names the plugin instead.
//
// The check reads the aliases the rendered SQL qualifies columns with. A raw
// SQL fragment that names a table without qualifying it is invisible to it;
// such a fragment is the plugin author's own risk.
//
// Only auth_user is in the lookup when the session store is not a
// SessionUserFinder, or when sessions are stateless: the user is then loaded
// alone, so a condition on auth_session has nothing to run against and is
// refused here rather than failing every request.
func (a *Auth) checkSessionPredicates() error {
	allowed := map[string]bool{TableAliasUser: true}
	if a.finder != nil {
		allowed[TableAliasSession] = true
	}
	for _, p := range a.plugins {
		sc, ok := p.(SessionChecker)
		if !ok {
			continue
		}
		// The statement is shaped like the lookup the store will run, so the
		// aliases the rendered SQL qualifies are exactly the predicates' own
		// plus the ones that lookup has.
		var id string
		stmt := sqlb.NewSelect(sqlb.PostgresDialect{}).Columns(sqlb.Bind(UserID, &id)).From(TableUser)
		if a.finder != nil {
			stmt = stmt.Join(sqlb.Join{Type: sqlb.JoinInner, Table: TableSession, On: []sqlb.Predicate{sqlb.EqExpr(SessionUserID, UserID)}})
		}
		q, err := stmt.Where(sc.SessionPredicates()...).Build()
		if err != nil {
			return fmt.Errorf("%w: plugin %q session check does not build: %v", ErrBadSessionCheck, p.Name(), err)
		}
		for _, m := range qualifiedAlias.FindAllStringSubmatch(q.SQL, -1) {
			if !allowed[m[1]] {
				return fmt.Errorf("%w: plugin %q names table alias %q; the session lookup has only %s",
					ErrBadSessionCheck, p.Name(), m[1], allowedAliases(allowed))
			}
		}
	}
	return nil
}

// sessionPredicates collects every plugin's session conditions.
func (a *Auth) sessionPredicates() []sqlb.Predicate {
	var out []sqlb.Predicate
	for _, p := range a.plugins {
		if sc, ok := p.(SessionChecker); ok {
			out = append(out, sc.SessionPredicates()...)
		}
	}
	return out
}

// OperationProvider contributes operations. Every transport exposes them, and
// every call to them goes through the pipeline.
//
//ds:def id=core-operationprovider-7ve9nf64 owner=@khanakia stability=stable
type OperationProvider interface {
	Operations() []Operation
}

// OperationHooker contributes hooks that run before and after chosen
// operations, on every transport.
//
//ds:def id=core-operationhooker-wv2ebtda owner=@khanakia stability=stable
type OperationHooker interface {
	OperationHooks() []OperationHook
}

// allowedAliases words the aliases a session check may use, for the refusal.
func allowedAliases(allowed map[string]bool) string {
	if allowed[TableAliasSession] {
		return "auth_session (" + TableAliasSession + ") and auth_user (" + TableAliasUser + ")"
	}
	return "auth_user (" + TableAliasUser + "): the session store does not join it"
}
