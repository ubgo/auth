import type { AdminUserSummary } from "@ubgo/auth-client"
import {
  ADMIN_DEFAULT_PAGE_SIZE,
  ADMIN_PAGE_SIZES,
  lastPage,
  pageItems,
  pageRange,
  useAdminPermissions,
  useAdminUsers,
  useAuth,
  useErrorMessage,
  useLocalization,
  usePluginClient,
  useSession,
  type AdminSearchField,
  type AdminUserSort,
  type AuthComponentProps,
} from "@ubgo/auth-react"
import { useEffect, useState } from "react"

import {
  ADMIN_USERS_TABLE_TEXT,
  AdminUsersTableView,
  type AdminRoleFilter,
  type AdminStatusFilter,
  type AdminUsersTableSlot,
  type AdminUsersTableText,
} from "@/components/auth/admin-users-table-view"

// AdminUsersTable: every user of the app a page at a time, for an admin.
// A search box (email or name fragment, debounced, "/" focuses it, Esc
// clears it), role and status filters, a sort, and a numbered pager with a
// page-size choice ("←" and "→" turn pages when focus is not in a field).
// Each row opens the user: onSuccess with the row when given, else a link
// to userHref(id). Shown only to callers the server lets list users
// (admin.has-permission); the server checks again on every read.
//
// The table itself is AdminUsersTableView (admin-users-table-view.tsx): this
// file owns the query state, the debounce, the paging maths and the fetch.

export {
  ADMIN_PAGER_GAP,
  ADMIN_ROLE_FILTERS,
  ADMIN_STATUS_FILTERS,
  ADMIN_USERS_TABLE_SEARCH_FIELDS,
  ADMIN_USERS_TABLE_SORTS,
  ADMIN_USERS_TABLE_TEXT,
  AdminUsersTableView,
  type AdminPagerItem,
  type AdminRoleFilter,
  type AdminStatusFilter,
  type AdminUsersTableSearchField,
  type AdminUsersTableSlot,
  type AdminUsersTableSort,
  type AdminUsersTableText,
  type AdminUsersTableViewProps,
} from "@/components/auth/admin-users-table-view"

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    adminUsersTable: AdminUsersTableText
  }
}

export type AdminUsersTableProps = AuthComponentProps<AdminUsersTableSlot, "adminUsersTable", AdminUserSummary> & {
  /** Where a row links to when there is no onSuccess. `/admin/users/<id>` by default. */
  readonly userHref?: (userId: string) => string
  /** The page sizes the pager offers. */
  readonly pageSizes?: readonly number[]
  /** The page size at first render; ADMIN_DEFAULT_PAGE_SIZE (the server's default, 50) by default. */
  readonly defaultPageSize?: number
  /** The keyboard shortcuts ("/" search, "←"/"→" pages, Esc clears the search). On by default; turn off when the page has its own. */
  readonly shortcuts?: boolean
}

/** How long typing must pause before a search is sent: the server rate-limits fragment searches. */
const SEARCH_DEBOUNCE_MS = 300

/** A filter value as the request's flag: undefined for "all". */
const ROLE_FLAG: Record<AdminRoleFilter, boolean | undefined> = { all: undefined, admins: true, others: false }
const STATUS_FLAG: Record<AdminStatusFilter, boolean | undefined> = { all: undefined, banned: true, active: false }

function defaultUserHref(userId: string): string {
  return `/admin/users/${encodeURIComponent(userId)}`
}

export function AdminUsersTable({
  className,
  classNames,
  localization,
  onSuccess,
  userHref = defaultUserHref,
  pageSizes = ADMIN_PAGE_SIZES,
  defaultPageSize = ADMIN_DEFAULT_PAGE_SIZE,
  shortcuts = true,
  headingLevel = 1,
}: AdminUsersTableProps) {
  const t = useLocalization("adminUsersTable", ADMIN_USERS_TABLE_TEXT, localization)
  const plugin = usePluginClient("admin")
  const { user } = useSession()
  const { Link } = useAuth()
  const { can, isPending: permissionsPending } = useAdminPermissions()
  const messageFor = useErrorMessage()

  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(defaultPageSize)
  const [searchText, setSearchText] = useState("")
  const [search, setSearch] = useState("")
  const [searchField, setSearchField] = useState<AdminSearchField>("email")
  const [role, setRole] = useState<AdminRoleFilter>("all")
  const [status, setStatus] = useState<AdminStatusFilter>("all")
  const [sort, setSort] = useState<AdminUserSort>("created_desc")

  // The typed text becomes the query once typing pauses; a new query starts
  // at page 1. Text that trims to the query already shown changes nothing,
  // so the first render and a trailing space do not reset the page.
  useEffect(() => {
    const next = searchText.trim()
    if (next === search) return
    const timer = setTimeout(() => {
      setSearch(next)
      setPage(1)
    }, SEARCH_DEBOUNCE_MS)
    return () => clearTimeout(timer)
  }, [searchText, search])

  const users = useAdminUsers({
    page,
    pageSize,
    search,
    searchField,
    sort,
    ...(ROLE_FLAG[role] === undefined ? {} : { admin: ROLE_FLAG[role] }),
    ...(STATUS_FLAG[status] === undefined ? {} : { banned: STATUS_FLAG[status] }),
  })
  const last = lastPage(users.total, users.pageSize)

  if (plugin === null || user === null) return null

  const { from, to } = pageRange(users.page, users.pageSize, users.total)

  return (
    <AdminUsersTableView
      className={className}
      classNames={classNames}
      text={t}
      headingLevel={headingLevel}
      forbidden={!permissionsPending && !can.listUsers}
      loading={users.isPending || permissionsPending}
      fetching={users.isFetching}
      error={users.error === null ? null : messageFor(users.error)}
      users={users.users}
      selfId={user.id}
      page={page}
      lastPage={last}
      pageItems={pageItems(page, last)}
      from={from}
      to={to}
      total={users.total}
      pageSize={pageSize}
      pageSizes={pageSizes}
      searchText={searchText}
      searchField={searchField}
      role={role}
      status={status}
      sort={sort}
      shortcuts={shortcuts}
      userHref={userHref}
      Link={Link}
      onOpen={onSuccess}
      onSearchTextChange={setSearchText}
      onSearchFieldChange={setSearchField}
      onRoleChange={(v) => {
        setRole(v)
        setPage(1)
      }}
      onStatusChange={(v) => {
        setStatus(v)
        setPage(1)
      }}
      onSortChange={(v) => {
        setSort(v)
        setPage(1)
      }}
      onPageChange={setPage}
      onPageSizeChange={(size) => {
        setPageSize(size)
        setPage(1)
      }}
    />
  )
}
