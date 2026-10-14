# Audit redaction: ranked events, and no raw personal data in the log

A security log where every event has a severity and the rows hold no raw address or email. The app ranks sign-ups `warn` with `audit.Severities`, keeps its own monitoring account's failed sign-ins at `info` with `audit.SeverityFunc`, and masks personal data before each row is written with `audit.Redact(audit.MaskPIIRedactor)`: the IP becomes its /24 (IPv4) or /48 (IPv6) network and an email keeps only its first character and its domain.

## Run it

```sh
cd examples
go run ./audit-redaction
```

It creates `audit-redaction.db` (SQLite) and listens on `http://localhost:8081` (`PORT` changes it). Mail is printed to the log instead of sent. Run the tests with `go test ./audit-redaction`.

## What the test proves

`TestAuditRedaction` signs a user up, fails one sign-in for her and one for the monitoring account, then reads the stored rows with SQL, not through the plugin. The rows hold `203.0.113.0/24` and `a***@example.com`, never the address or the email typed; the sign-up and Alice's failed sign-in are `warn`, the monitor's failure is `info`; and `audit.Query{MinSeverity: audit.SeverityWarn}` finds the two `warn` rows.

## Notes

- The severity is decided from the whole event before redaction, so a rule that reads the real address or email (like the monitoring account here) still works.
- Redaction is lossy: a masked identifier no longer matches `audit.Query{Identifier: ...}` for the address that was typed.
- Phone numbers, usernames and the user agent are not touched by the default helper; write an `audit.RedactorFunc` if your policy counts them.
- The guide is [docs/plugins/audit.md](../../docs/plugins/audit.md), Step 5.
