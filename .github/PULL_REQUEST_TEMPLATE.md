<!-- Thanks for contributing to auth! -->

## What & why

<!-- What does this change and why? Link the issue it closes. -->
Closes #

## Type of change

- [ ] Bug fix
- [ ] Security fix (tagged **[security]** in CHANGELOG.md)
- [ ] New feature or plugin
- [ ] Refactor / internal
- [ ] Docs

## Checklist

- [ ] `task check` is green; a change touching SQL is also green on `task test:engines`.
- [ ] New logic has a test that fails without it. Database error paths are covered with `sweepFaults`.
- [ ] Every comparison of a secret is constant-time, and every error path is enumeration-safe in message and timing.
- [ ] No new third-party dependency in the core module; a package that needs one is its own module.
- [ ] Every new closed-set value is a named constant; every new export has a doc comment saying why it exists and what stays true.
- [ ] No suppressed diagnostics: no `//nolint`, no skipped test, no loosened assertion.
- [ ] README, example READMEs and CHANGELOG.md updated for anything user-facing.
