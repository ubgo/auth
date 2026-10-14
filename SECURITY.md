# Security Policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Report them privately:

- Use **[GitHub Security Advisories](https://github.com/ubgo/auth/security/advisories/new)** (preferred), or
- Email **khanakia@gmail.com** with the details.

Please include a description of the vulnerability and its impact, steps to reproduce (a failing test is ideal), and the affected version and configuration (engine, plugins, transport).

We will acknowledge your report within a few days and keep you updated on the fix. Please give us a reasonable window to release a fix before any public disclosure; we are happy to credit you in the advisory. Every fixed vulnerability is listed in [CHANGELOG.md](CHANGELOG.md) under a **[security]** tag.

## Supported versions

| Version | Supported |
|---|---|
| latest `v0.x` | ✅ |
| any earlier `v0.x` | ❌ |

The module is pre-GA. Under SemVer a `v0.x` release may break, so the only supported version is the newest one; fixes are not backported.

## Scope

This is an authentication library, so almost every defect in how it decides who a caller is counts as a vulnerability. In scope, among others:

- Signing in, or acting, as a user without that user's credential: a token, code or link accepted when it should not be, accepted twice, accepted after expiry, or accepted for another account or tenant.
- An unverified identity (email, phone) matching a person where a verified one is required, or taking over an existing account.
- Timing or response differences that reveal whether an account exists, on any route that promises not to.
- A comparison of a secret that is not constant-time.
- A route or Go call that skips the pipeline's checks: rate limit, origin check, session requirement, fresh sign-in, second factor.
- A secret (password, token, code, sealed provider token) written to a log, an error, a JSON body or the database in plain form.
- Request data reaching SQL text rather than a bound parameter.

Out of scope: weaknesses that need the attacker to control the application's configuration or its database, denial of service by volume alone (the rate limits are the mitigation and their numbers are configuration), and bugs in the application's own queries over the auth tables.
