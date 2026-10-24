// /admin: AdminUsersTable, and AdminUserDetail for the user named by ?user=.
// The demo user is an admin (seed.go grants it) and the server seeds 64
// directory users plus Linus, so the table has pages to turn and someone
// with sessions to revoke. Signed out, a link to sign in.

import { SignedIn, SignedOut } from "@ubgo/auth-react"
import { useRouterState } from "@tanstack/react-router"

import { AdminUserDetail, type AdminUserDetailSlot } from "@/components/auth/admin-user-detail"
import { AdminUsersTable, type AdminUsersTableSlot } from "@/components/auth/admin-users-table"
import { DemoPage } from "@/components/demo-page"
import { RouterLink } from "@/components/demo-shell"
import { useDemoCustomise } from "@/demo/customise"
import { DEMO_USER, SECOND_USER } from "@/demo-user"

/** The classNames the Custom appearance applies, shown verbatim in the panel. */
const CUSTOM_TABLE: Partial<Record<AdminUsersTableSlot, string>> = {
  root: "rounded-2xl shadow-lg",
  badge: "rounded-md",
  pageButton: "rounded-full",
}
const CUSTOM_DETAIL: Partial<Record<AdminUserDetailSlot, string>> = {
  root: "rounded-2xl shadow-lg",
  badge: "rounded-md",
}

const CUSTOM_CODE = `<AdminUsersTable
  classNames={${JSON.stringify(CUSTOM_TABLE, null, 2).replace(/\n/g, "\n  ")}}
/>
<AdminUserDetail
  classNames={${JSON.stringify(CUSTOM_DETAIL, null, 2).replace(/\n/g, "\n  ")}}
/>`

/** The page's own path, where a row and "All users" lead. */
const ADMIN_PATH = "/admin"

function userHref(userId: string): string {
  return `${ADMIN_PATH}?user=${encodeURIComponent(userId)}`
}

export function AdminPage() {
  const { custom } = useDemoCustomise()
  const userId = useRouterState({ select: (s) => new URLSearchParams(s.location.searchStr).get("user") ?? "" })
  return (
    <DemoPage
      title="Admin dashboard"
      description="Every user a page at a time, and one user's sessions, ban, role, second factor and password, for callers the server lets manage users."
      customCode={CUSTOM_CODE}
      tryThis={[
        <>
          <RouterLink href={`/sign-in?redirectTo=${ADMIN_PATH}`}>Sign in</RouterLink> as <code>{DEMO_USER.email}</code>, an admin in this demo, within a few minutes of opening this page: changes need a recent sign-in.
        </>,
        <>
          Press <kbd>/</kbd> and type <code>turing</code>, switch the search to name, then filter by status <b>Banned</b>. Use <kbd>←</kbd> and <kbd>→</kbd> to turn pages, or pick 10 rows per page.
        </>,
        <>
          In another browser, sign in as <code>{SECOND_USER.email}</code> with the same password. Open Linus here: the session is listed, revoke it.
        </>,
        <>Ban Linus for an hour with a reason, then try signing in as him: the reason is the message. Unban him.</>,
        <>Impersonate a user: the banner at the top says so, and Stop impersonating brings your admin session back.</>,
        <>Switch Appearance to Custom in the panel below.</>,
      ]}
    >
      <SignedIn>
        {userId === "" ? (
          <AdminUsersTable classNames={custom ? CUSTOM_TABLE : undefined} userHref={userHref} headingLevel={2} />
        ) : (
          <AdminUserDetail key={userId} userId={userId} backHref={ADMIN_PATH} classNames={custom ? CUSTOM_DETAIL : undefined} headingLevel={2} />
        )}
      </SignedIn>
      <SignedOut>
        <p className="text-[13px] text-muted-foreground">
          <RouterLink href={`/sign-in?redirectTo=${ADMIN_PATH}`} className="text-foreground underline underline-offset-3">
            Sign in
          </RouterLink>{" "}
          as an admin to manage users.
        </p>
      </SignedOut>
    </DemoPage>
  )
}
