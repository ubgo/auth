# Your own data beside each organization

The app keeps a `project` table of its own, keyed by the organization's id the way a user's rows are keyed by the user's id. Every new organization starts with a "General" project, written by an organization hook inside the transaction that creates the organization; deleting the organization removes its projects in the same transaction; and an import creates an organization and its projects with `a.Tx`, so a failed import leaves nothing behind. The tests build organizations with the `orgtest` fixtures instead of the HTTP flow.

## Run it

```sh
cd examples
go run ./org-workspace
```

It creates `org-workspace.db` (SQLite) and listens on `http://localhost:8081`. Mail is printed to the log instead of sent. Run the tests with `go test ./org-workspace`.

## Walkthrough

Alice signs up and creates an organization through the library's own route. The hook has already given it a project:

```sh
curl -s -c alice.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
curl -s -b alice.txt -X POST localhost:8081/auth/organization/create -H 'Origin: http://localhost:8081' -d '{"name":"Acme","slug":"acme"}'
curl -s -b alice.txt localhost:8081/orgs/org_jzvh7nimq3wewbk76cqil6bq/projects
```

```json
{"user":{"id":"usr_dezcv77fqlh6vnrcwmxds2fp","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"id":"org_jzvh7nimq3wewbk76cqil6bq","slug":"acme","name":"Acme","createdAt":"2026-10-09T10:20:08.213795Z"}
{"orgId":"org_jzvh7nimq3wewbk76cqil6bq","projects":[{"id":"prj_kfkjxpw7wg7wxvegd4skpot5","name":"General"}]}
```

As the owner she adds a project. A second one with the same name is the app's own error, and a POST from another site is refused before anything is written, because the app's route checks the origin itself:

```sh
curl -s -b alice.txt -X POST localhost:8081/orgs/org_jzvh7nimq3wewbk76cqil6bq/projects -H 'Origin: http://localhost:8081' -d '{"name":"Roadmap"}'
curl -s -b alice.txt -X POST localhost:8081/orgs/org_jzvh7nimq3wewbk76cqil6bq/projects -H 'Origin: http://localhost:8081' -d '{"name":"Roadmap"}'
curl -s -b alice.txt -X POST localhost:8081/orgs/org_jzvh7nimq3wewbk76cqil6bq/projects -H 'Origin: https://evil.example' -d '{"name":"Evil"}'
```

```json
{"id":"prj_4njz7fuxgdk277wslom4uyuq","name":"Roadmap"}
{"error":{"code":"project.name_taken","message":"A project with this name already exists."}}
{"error":{"code":"auth.origin_not_trusted","message":"This request came from a site that is not trusted."}}
```

Eve, signed in but not a member, cannot tell the organization exists:

```sh
curl -s -c eve.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' -d '{"identifier":"eve@example.com","password":"correct horse battery staple","name":"Eve"}' > /dev/null
curl -s -b eve.txt localhost:8081/orgs/org_jzvh7nimq3wewbk76cqil6bq/projects
```

```json
{"error":{"code":"organization.not_member","message":"Not found."}}
```

Alice deletes the organization; its projects go with it:

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/organization/delete -H 'Origin: http://localhost:8081' -d '{"orgId":"org_jzvh7nimq3wewbk76cqil6bq"}'
sqlite3 org-workspace.db 'SELECT COUNT(*) FROM project'
```

```text
{"ok":true}
0
```

## How it works

- `hooks(a)` returns `organization.Hooks` with `AfterCreateOrg` (insert the default project) and `BeforeDeleteOrg` (delete the organization's projects). It is passed as `organization.WithHooksFrom(hooks)`, so the plugin calls it with the `*auth.Auth` once `auth.New` has built it. The hooks write through `a.Conn(ctx)`, which is the operation's open transaction, so an error in either rolls the whole operation back.
- `importWorkspace` wraps `organization.CreateFor` and the project inserts in one `a.Tx`. `CreateFor` joins it; a project that collides (the default "General", for example) rolls back the organization too.
- Reading the table is the app's business (`listProjects`); the routes are guarded by `RequireRole`: members read, admins and owners create.
- The test harness is `authtest` plus `plugin/organization/orgtest`: `orgtest.New(env)`, `NewOrganization`, `SaveOrganization` and `AddMember` create organizations through the plugin's Go API, so the hook runs for fixtures as well.

## Tests

`main_test.go` covers the create hook over HTTP, the duplicate and blank names, the cross-site POST, member, stranger and admin access on fixture organizations, deletion of one organization leaving another's projects, and an import that succeeds and one that rolls back.
