import type { AdminUserSummary } from "@ubgo/auth-client"
import {
  ADMIN_DEFAULT_PAGE_SIZE,
  ADMIN_PAGE_SIZES,
  PAGE_GAP,
  format,
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
import {
  ChevronDownIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  ChevronsLeftIcon,
  ChevronsRightIcon,
  CircleAlertIcon,
  SearchIcon,
  ShieldIcon,
  UsersRoundIcon,
  XIcon,
} from "lucide-react"
import { useEffect, useId, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from "react"

import { Alert, AlertDescription } from "@/components/ui/alert"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { Spinner } from "@/components/ui/spinner"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { cn } from "@/lib/utils"

// AdminUsersTable: every user of the app a page at a time, for an admin.
// A search box (email or name fragment, debounced, "/" focuses it, Esc
// clears it), role and status filters, a sort, and a numbered pager with a
// page-size choice ("←" and "→" turn pages when focus is not in a field).
// Each row opens the user: onSuccess with the row when given, else a link
// to userHref(id). Shown only to callers the server lets list users
// (admin.has-permission); the server checks again on every read.

/** Every string AdminUsersTable shows. */
export type AdminUsersTableText = {
  title: string
  description: string
  forbidden: string
  searchLabel: string
  /** `{field}` is the field searched, from fieldEmail / fieldName. */
  searchPlaceholder: string
  clearSearch: string
  fieldLabel: string
  fieldEmail: string
  fieldName: string
  roleLabel: string
  roleAll: string
  roleAdmins: string
  roleOthers: string
  statusLabel: string
  statusAll: string
  statusBanned: string
  statusActive: string
  sortLabel: string
  sortNewest: string
  sortOldest: string
  sortNameAsc: string
  sortNameDesc: string
  columnUser: string
  columnStatus: string
  columnCreated: string
  columnLastActive: string
  admin: string
  banned: string
  you: string
  unnamed: string
  never: string
  empty: string
  /** `{from}`, `{to}` and `{total}` describe the rows shown. */
  range: string
  /** `{size}` is the page size. */
  perPage: string
  pageSizeLabel: string
  first: string
  previous: string
  next: string
  last: string
  /** `{page}` is the page number. */
  pageLabel: string
  /** The pager's accessible name. */
  pagination: string
  /** `{name}` is the user's name. */
  openUser: string
}

declare module "@ubgo/auth-react" {
  interface ComponentLocalizations {
    adminUsersTable: AdminUsersTableText
  }
}

/** The English defaults. Override per app (AuthProvider localization.adminUsersTable) or per use (localization prop). */
export const ADMIN_USERS_TABLE_TEXT: AdminUsersTableText = {
  title: "Users",
  description: "Everyone with an account. Open a user to manage their sessions, ban them or act as them.",
  forbidden: "You do not have access to the user list.",
  searchLabel: "Search users",
  searchPlaceholder: "Search by {field}…",
  clearSearch: "Clear search",
  fieldLabel: "Search in",
  fieldEmail: "email",
  fieldName: "name",
  roleLabel: "Role",
  roleAll: "All roles",
  roleAdmins: "Admins",
  roleOthers: "Not admins",
  statusLabel: "Status",
  statusAll: "Any status",
  statusBanned: "Banned",
  statusActive: "Not banned",
  sortLabel: "Sort",
  sortNewest: "Newest first",
  sortOldest: "Oldest first",
  sortNameAsc: "Name A–Z",
  sortNameDesc: "Name Z–A",
  columnUser: "User",
  columnStatus: "Status",
  columnCreated: "Created",
  columnLastActive: "Last active",
  admin: "Admin",
  banned: "Banned",
  you: "You",
  unnamed: "Unnamed",
  never: "Never",
  empty: "No users match.",
  range: "{from}–{to} of {total}",
  perPage: "{size} / page",
  pageSizeLabel: "Rows per page",
  first: "First page",
  previous: "Previous page",
  next: "Next page",
  last: "Last page",
  pageLabel: "Page {page}",
  pagination: "Users pages",
  openUser: "Open {name}",
}

/** The named parts classNames can style. */
export type AdminUsersTableSlot =
  | "root"
  | "header"
  | "title"
  | "description"
  | "content"
  | "toolbar"
  | "search"
  | "filter"
  | "table"
  | "row"
  | "badge"
  | "pagination"
  | "pageButton"
  | "formError"

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

/** The role filter's values: everyone, only admins, only the rest. */
const ROLE_FILTERS = ["all", "admins", "others"] as const
type RoleFilter = (typeof ROLE_FILTERS)[number]

/** The status filter's values: everyone, only banned, only not banned. */
const STATUS_FILTERS = ["all", "banned", "active"] as const
type StatusFilter = (typeof STATUS_FILTERS)[number]

/** A filter value as the request's flag: undefined for "all". */
const ROLE_FLAG: Record<RoleFilter, boolean | undefined> = { all: undefined, admins: true, others: false }
const STATUS_FLAG: Record<StatusFilter, boolean | undefined> = { all: undefined, banned: true, active: false }

/**
 * The admin plugin's built-in roles (plugin/admin RoleUser, RoleAdmin): the
 * Admin badge already says the one, and the other is everyone, so only an
 * app's own roles get a badge of their own.
 */
const BUILT_IN_ROLES: ReadonlySet<string> = new Set(["user", "admin"])

/** The skeleton rows while the first page loads. */
const SKELETON_ROWS = 5

function defaultUserHref(userId: string): string {
  return `/admin/users/${encodeURIComponent(userId)}`
}

/** Whether a key press came from a place that takes text, where shortcuts must not fire. */
function typingIn(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false
  return target.isContentEditable || target.closest("input, textarea, select, [role=menu], [role=dialog]") !== null
}

function formatDate(iso: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(new Date(iso))
}

/** The relative-time steps, largest first, each with its length in seconds. */
const RELATIVE_STEPS: readonly (readonly [Intl.RelativeTimeFormatUnit, number])[] = [
  ["year", 31_536_000],
  ["month", 2_592_000],
  ["week", 604_800],
  ["day", 86_400],
  ["hour", 3_600],
  ["minute", 60],
]

/** "3 minutes ago", "yesterday": a time relative to now in the reader's locale. */
function formatRelative(iso: string): string {
  const seconds = (new Date(iso).getTime() - Date.now()) / 1000
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" })
  for (const [unit, size] of RELATIVE_STEPS) {
    if (Math.abs(seconds) >= size) return rtf.format(Math.round(seconds / size), unit)
  }
  return rtf.format(0, "minute")
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
  const { can, isPending: permissionsPending } = useAdminPermissions()
  const messageFor = useErrorMessage()
  const searchId = useId()
  const searchRef = useRef<HTMLInputElement>(null)

  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(defaultPageSize)
  const [searchText, setSearchText] = useState("")
  const [search, setSearch] = useState("")
  const [searchField, setSearchField] = useState<AdminSearchField>("email")
  const [role, setRole] = useState<RoleFilter>("all")
  const [status, setStatus] = useState<StatusFilter>("all")
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

  // "/" focuses the search, "←" and "→" turn pages, wherever focus is but a field or a menu.
  useEffect(() => {
    if (!shortcuts) return
    const onKey = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey || typingIn(e.target)) return
      if (e.key === "/") {
        e.preventDefault()
        searchRef.current?.focus()
      } else if (e.key === "ArrowLeft") {
        setPage((p) => Math.max(1, p - 1))
      } else if (e.key === "ArrowRight") {
        setPage((p) => Math.min(last, p + 1))
      }
    }
    document.addEventListener("keydown", onKey)
    return () => document.removeEventListener("keydown", onKey)
  }, [shortcuts, last])

  if (plugin === null || user === null) return null

  const { from, to } = pageRange(users.page, users.pageSize, users.total)
  const sortText: Record<AdminUserSort, string> = {
    created_desc: t.sortNewest,
    created_asc: t.sortOldest,
    name_asc: t.sortNameAsc,
    name_desc: t.sortNameDesc,
  }
  const roleText: Record<RoleFilter, string> = { all: t.roleAll, admins: t.roleAdmins, others: t.roleOthers }
  const statusText: Record<StatusFilter, string> = { all: t.statusAll, banned: t.statusBanned, active: t.statusActive }
  const fieldText: Record<AdminSearchField, string> = { email: t.fieldEmail, name: t.fieldName }

  const onSearchKey = (e: ReactKeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Escape" && searchText !== "") {
      e.preventDefault()
      setSearchText("")
    }
  }
  const goTo = (next: number) => setPage(Math.min(last, Math.max(1, next)))

  return (
    <Card className={cn("w-full max-w-5xl", className, classNames?.root)}>
      <CardHeader className={classNames?.header}>
        <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
          <UsersRoundIcon aria-hidden className="size-4 text-muted-foreground" />
          {t.title}
          {users.isFetching && !users.isPending && <Spinner className="size-3 text-muted-foreground" />}
        </CardTitle>
        <CardDescription className={classNames?.description}>{t.description}</CardDescription>
      </CardHeader>
      <CardContent className={cn("flex flex-col gap-2", classNames?.content)}>
        {!permissionsPending && !can.listUsers ? (
          <p className="text-[13px] text-muted-foreground">{t.forbidden}</p>
        ) : (
          <>
            <div className={cn("flex flex-wrap items-center gap-1.5", classNames?.toolbar)}>
              <div className="relative min-w-48 flex-1">
                <SearchIcon aria-hidden className="pointer-events-none absolute top-1/2 left-2 size-3.5 -translate-y-1/2 text-muted-foreground" />
                <label htmlFor={searchId} className="sr-only">
                  {t.searchLabel}
                </label>
                <Input
                  id={searchId}
                  ref={searchRef}
                  type="search"
                  autoComplete="off"
                  spellCheck={false}
                  value={searchText}
                  onChange={(e) => setSearchText(e.target.value)}
                  onKeyDown={onSearchKey}
                  placeholder={format(t.searchPlaceholder, { field: fieldText[searchField] })}
                  className={cn("pr-14 pl-7 [&::-webkit-search-cancel-button]:hidden", classNames?.search)}
                />
                <span className="absolute top-1/2 right-1.5 flex -translate-y-1/2 items-center gap-1">
                  {searchText !== "" ? (
                    <Button type="button" variant="ghost" size="icon-xs" aria-label={t.clearSearch} onClick={() => setSearchText("")}>
                      <XIcon aria-hidden />
                    </Button>
                  ) : (
                    shortcuts && (
                      <kbd aria-hidden className="rounded border bg-muted px-1 font-mono text-[10px] text-muted-foreground">
                        /
                      </kbd>
                    )
                  )}
                </span>
              </div>
              <FilterMenu
                label={t.fieldLabel}
                value={searchField}
                options={["email", "name"] as const}
                text={fieldText}
                onChange={setSearchField}
                className={classNames?.filter}
              />
              <FilterMenu
                label={t.roleLabel}
                value={role}
                options={ROLE_FILTERS}
                text={roleText}
                onChange={(v) => {
                  setRole(v)
                  setPage(1)
                }}
                className={classNames?.filter}
              />
              <FilterMenu
                label={t.statusLabel}
                value={status}
                options={STATUS_FILTERS}
                text={statusText}
                onChange={(v) => {
                  setStatus(v)
                  setPage(1)
                }}
                className={classNames?.filter}
              />
              <FilterMenu
                label={t.sortLabel}
                value={sort}
                options={["created_desc", "created_asc", "name_asc", "name_desc"] as const}
                text={sortText}
                onChange={(v) => {
                  setSort(v)
                  setPage(1)
                }}
                className={classNames?.filter}
              />
            </div>

            {users.error !== null && (
              <Alert variant="destructive" className={classNames?.formError}>
                <CircleAlertIcon aria-hidden />
                <AlertDescription>{messageFor(users.error)}</AlertDescription>
              </Alert>
            )}

            <div className="rounded-lg border">
              <Table className={classNames?.table} aria-busy={users.isFetching}>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead>{t.columnUser}</TableHead>
                    <TableHead>{t.columnStatus}</TableHead>
                    <TableHead className="hidden sm:table-cell">{t.columnCreated}</TableHead>
                    <TableHead className="hidden sm:table-cell">{t.columnLastActive}</TableHead>
                    <TableHead className="w-8">
                      <span className="sr-only">{t.columnUser}</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody className={cn(users.isFetching && !users.isPending && "opacity-60 transition-opacity")}>
                  {users.isPending || permissionsPending ? (
                    Array.from({ length: SKELETON_ROWS }, (_, i) => (
                      <TableRow key={i} aria-hidden>
                        <TableCell colSpan={5}>
                          <Skeleton className="h-6 w-full" />
                        </TableCell>
                      </TableRow>
                    ))
                  ) : users.users.length === 0 ? (
                    <TableRow className="hover:bg-transparent">
                      <TableCell colSpan={5} className="py-6 text-center text-muted-foreground">
                        {t.empty}
                      </TableCell>
                    </TableRow>
                  ) : (
                    users.users.map((u) => (
                      <UserRow
                        key={u.id}
                        row={u}
                        self={u.id === user.id}
                        href={userHref(u.id)}
                        onOpen={onSuccess}
                        t={t}
                        classNames={classNames}
                      />
                    ))
                  )}
                </TableBody>
              </Table>
            </div>

            <div className={cn("flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground tabular-nums", classNames?.pagination)}>
              <div className="flex items-center gap-2">
                <span aria-live="polite">{format(t.range, { from, to, total: users.total })}</span>
                <DropdownMenu>
                  <DropdownMenuTrigger
                    render={<Button type="button" variant="ghost" size="sm" aria-label={`${t.pageSizeLabel}: ${users.pageSize}`} />}
                  >
                    {format(t.perPage, { size: pageSize })}
                    <ChevronDownIcon aria-hidden />
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="start" className="w-32">
                    <DropdownMenuGroup>
                      <DropdownMenuLabel>{t.pageSizeLabel}</DropdownMenuLabel>
                      <DropdownMenuRadioGroup
                        value={String(pageSize)}
                        onValueChange={(next: string) => {
                          setPageSize(Number(next))
                          setPage(1)
                        }}
                      >
                        {pageSizes.map((size) => (
                          <DropdownMenuRadioItem key={size} value={String(size)} closeOnClick>
                            {size}
                          </DropdownMenuRadioItem>
                        ))}
                      </DropdownMenuRadioGroup>
                    </DropdownMenuGroup>
                  </DropdownMenuContent>
                </DropdownMenu>
              </div>
              <nav aria-label={t.pagination} className="flex items-center gap-0.5">
                <Button type="button" variant="ghost" size="icon-sm" aria-label={t.first} disabled={page <= 1} onClick={() => goTo(1)}>
                  <ChevronsLeftIcon aria-hidden />
                </Button>
                <Button type="button" variant="ghost" size="icon-sm" aria-label={t.previous} disabled={page <= 1} onClick={() => goTo(page - 1)}>
                  <ChevronLeftIcon aria-hidden />
                </Button>
                {pageItems(page, last).map((item, i) =>
                  item === PAGE_GAP ? (
                    <span key={`gap-${i}`} aria-hidden className="px-1">
                      …
                    </span>
                  ) : (
                    <Button
                      key={item}
                      type="button"
                      variant={item === page ? "outline" : "ghost"}
                      size="sm"
                      className={cn("min-w-6 tabular-nums", classNames?.pageButton)}
                      aria-label={format(t.pageLabel, { page: item })}
                      aria-current={item === page ? "page" : undefined}
                      onClick={() => goTo(item)}
                    >
                      {item}
                    </Button>
                  ),
                )}
                <Button type="button" variant="ghost" size="icon-sm" aria-label={t.next} disabled={page >= last} onClick={() => goTo(page + 1)}>
                  <ChevronRightIcon aria-hidden />
                </Button>
                <Button type="button" variant="ghost" size="icon-sm" aria-label={t.last} disabled={page >= last} onClick={() => goTo(last)}>
                  <ChevronsRightIcon aria-hidden />
                </Button>
              </nav>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  )
}

/** A compact menu that picks one of `options`; its trigger shows the choice, and names the filter to assistive tech and in the menu. */
function FilterMenu<V extends string>({
  label,
  value,
  options,
  text,
  onChange,
  className,
}: {
  label: string
  value: V
  options: readonly V[]
  text: Record<V, string>
  onChange: (next: V) => void
  className: string | undefined
}) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger render={<Button type="button" variant="outline" className={cn("justify-between gap-1", className)} aria-label={`${label}: ${text[value]}`} />}>
        {text[value]}
        <ChevronDownIcon aria-hidden className="text-muted-foreground" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-40">
        <DropdownMenuGroup>
          <DropdownMenuLabel>{label}</DropdownMenuLabel>
          <DropdownMenuRadioGroup
            value={value}
            onValueChange={(next: string) => {
              const picked = options.find((o) => o === next)
              if (picked !== undefined) onChange(picked)
            }}
          >
            {options.map((o) => (
              <DropdownMenuRadioItem key={o} value={o} closeOnClick>
                {text[o]}
              </DropdownMenuRadioItem>
            ))}
          </DropdownMenuRadioGroup>
        </DropdownMenuGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

/** One user: avatar and name (a link to them, or a button when onOpen is set), their badges, and when they joined and were last seen. */
function UserRow({
  row,
  self,
  href,
  onOpen,
  t,
  classNames,
}: {
  row: AdminUserSummary
  self: boolean
  href: string
  onOpen: ((row: AdminUserSummary) => void) | undefined
  t: AdminUsersTableText
  classNames: AdminUsersTableProps["classNames"]
}) {
  const { Link } = useAuth()
  const name = row.name.trim()
  const shown = name === "" ? t.unnamed : name
  const label = format(t.openUser, { name: shown })
  const nameNode = (
    <span className="flex min-w-0 items-center gap-2">
      <Avatar size="sm">
        <AvatarFallback className="text-[10px] font-medium text-foreground/80">{(name === "" ? "?" : name.slice(0, 1)).toUpperCase()}</AvatarFallback>
      </Avatar>
      <span className="flex min-w-0 flex-col text-left">
        <span className="flex items-center gap-1.5 truncate font-medium">
          {shown}
          {self && (
            <Badge variant="outline" className={classNames?.badge}>
              {t.you}
            </Badge>
          )}
        </span>
        <span className="truncate text-xs text-muted-foreground" title={row.id}>
          {row.email === "" ? <span className="font-mono text-[11px]">{row.id}</span> : row.email}
        </span>
      </span>
    </span>
  )
  return (
    <TableRow className={cn("relative", classNames?.row)}>
      <TableCell className="max-w-64">
        {onOpen === undefined ? (
          <Link href={href} className="block rounded-sm outline-none after:absolute after:inset-0 focus-visible:ring-2 focus-visible:ring-ring/50">
            {nameNode}
            <span className="sr-only">{label}</span>
          </Link>
        ) : (
          <button
            type="button"
            aria-label={label}
            className="block rounded-sm outline-none after:absolute after:inset-0 focus-visible:ring-2 focus-visible:ring-ring/50"
            onClick={() => onOpen(row)}
          >
            {nameNode}
          </button>
        )}
      </TableCell>
      <TableCell>
        <span className="flex gap-1">
          {row.admin && (
            <Badge variant="secondary" className={classNames?.badge}>
              <ShieldIcon aria-hidden data-icon="inline-start" />
              {t.admin}
            </Badge>
          )}
          {(row.roles ?? [])
            .filter((r) => !BUILT_IN_ROLES.has(r))
            .map((r) => (
              <Badge key={r} variant="outline" className={cn("capitalize", classNames?.badge)}>
                {r}
              </Badge>
            ))}
          {row.banned && (
            <Badge variant="destructive" className={classNames?.badge}>
              {t.banned}
            </Badge>
          )}
        </span>
      </TableCell>
      <TableCell className="hidden text-muted-foreground sm:table-cell">{formatDate(row.createdAt)}</TableCell>
      <TableCell className="hidden text-muted-foreground sm:table-cell">{row.lastActiveAt === null ? t.never : formatRelative(row.lastActiveAt)}</TableCell>
      <TableCell className="text-muted-foreground">
        <ChevronRightIcon aria-hidden className="size-3.5" />
      </TableCell>
    </TableRow>
  )
}
