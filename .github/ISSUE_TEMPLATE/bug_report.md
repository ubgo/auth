---
name: Bug report
about: A sign-in, session, plugin or adapter did the wrong thing
title: "[bug] "
labels: bug
---

**Security issue?** Stop here and report it privately instead: see SECURITY.md.

**What happened**

A clear description of the bug, and what you expected instead.

**How to reproduce**

The `auth.New` options and plugins you use, reduced as far as it still reproduces, and the call or request that misbehaves:

```go
a, err := auth.New(
	auth.WithDB(db, sqlb.PostgresDialect{}),
	auth.WithPlugins(email.New(email.Login()), password.New()),
)
```

**Environment**

- auth version:
- Database engine and version:
- Transport (net/http, gin, echo, fiber, gqlgen, Go API):
- Go version:
