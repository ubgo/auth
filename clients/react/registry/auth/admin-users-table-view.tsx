import type { AdminUserSummary } from "@ubgo/auth-client"
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
import { useEffect, useId, useRef, type KeyboardEvent as ReactKeyboardEvent } from "react"

import { AnchorLink, fillText, type ViewHeadingLevel, type ViewLinkComponent } from "@/components/auth/auth-view"
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

// AdminUsersTableView: the admin's users table with no data layer. It is
// fully controlled: the rows, the search text, the filters, the sort and the
// page come in as props, and every change goes out through a callback, so the
// caller decides what each state fetches. The pager's buttons arrive already
// computed (pageItems), so the view holds no paging logic. It keeps the "/"
// and arrow-key shortcuts, which only focus the search or ask for a page.
// AdminUsersTable (admin-users-table.tsx) is this view wired to
// @ubgo/auth-react.

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

/** A date in the reader's locale, medium style. */
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

/**
 * The orders the sort menu offers, the same closed set as ADMIN_USER_SORTS in
 * @ubgo/auth-react, repeated so the view needs nothing from that package. The
 * wired component hands its own sort state in and takes this union back out,
 * so the two sets drifting apart fails its type check.
 */
export const ADMIN_USERS_TABLE_SORTS = ["created_desc", "created_asc", "name_asc", "name_desc"] as const

/** One of ADMIN_USERS_TABLE_SORTS. */
export type AdminUsersTableSort = (typeof ADMIN_USERS_TABLE_SORTS)[number]

/** The fields the search can read, the same closed set as ADMIN_SEARCH_FIELDS in @ubgo/auth-react (see ADMIN_USERS_TABLE_SORTS). */
export const ADMIN_USERS_TABLE_SEARCH_FIELDS = ["email", "name"] as const

/** One of ADMIN_USERS_TABLE_SEARCH_FIELDS. */
export type AdminUsersTableSearchField = (typeof ADMIN_USERS_TABLE_SEARCH_FIELDS)[number]

/** The role filter's values: everyone, only admins, only the rest. */
export const ADMIN_ROLE_FILTERS = ["all", "admins", "others"] as const

/** One of ADMIN_ROLE_FILTERS. */
export type AdminRoleFilter = (typeof ADMIN_ROLE_FILTERS)[number]

/** The status filter's values: everyone, only banned, only not banned. */
export const ADMIN_STATUS_FILTERS = ["all", "banned", "active"] as const

/** One of ADMIN_STATUS_FILTERS. */
export type AdminStatusFilter = (typeof ADMIN_STATUS_FILTERS)[number]

/** The pager item standing for skipped pages, the same value as PAGE_GAP in @ubgo/auth-react. */
export const ADMIN_PAGER_GAP = "gap"

/** A pager button: a page number, or ADMIN_PAGER_GAP for the pages it skips. */
export type AdminPagerItem = number | typeof ADMIN_PAGER_GAP

/**
 * The admin plugin's built-in roles (plugin/admin RoleUser, RoleAdmin): the
 * Admin badge already says the one, and the other is everyone, so only an
 * app's own roles get a badge of their own.
 */
const BUILT_IN_ROLES: ReadonlySet<string> = new Set(["user", "admin"])

/** The skeleton rows while the first page loads. */
const SKELETON_ROWS = 5

/** The page sizes offered when the caller names none, the same as ADMIN_PAGE_SIZES in @ubgo/auth-react. */
const DEFAULT_PAGE_SIZES: readonly number[] = [10, 25, 50, 100]

/** The page size shown when the caller names none, the server's default (ADMIN_DEFAULT_PAGE_SIZE in @ubgo/auth-react). */
const DEFAULT_PAGE_SIZE = 50

/** Where a row links to when the caller names no userHref. */
function defaultUserHref(userId: string): string {
  return `/admin/users/${encodeURIComponent(userId)}`
}

/** Whether a key press came from a place that takes text, where shortcuts must not fire. */
function typingIn(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false
  return target.isContentEditable || target.closest("input, textarea, select, [role=menu], [role=dialog]") !== null
}

/** The table's props: the page of rows and where it sits, the controls' current values, and a callback per change. */
export type AdminUsersTableViewProps = {
  /** Classes for the root, merged after the defaults. */
  readonly className?: string
  /** Classes per named part. */
  readonly classNames?: Partial<Record<AdminUsersTableSlot, string>>
  /** Text overrides, merged over ADMIN_USERS_TABLE_TEXT. */
  readonly text?: Partial<AdminUsersTableText>
  /** The level of the title, 1 by default. */
  readonly headingLevel?: ViewHeadingLevel
  /** The caller may not list users: the card says so instead of the table. */
  readonly forbidden?: boolean
  /** The first page is loading: skeleton rows show. */
  readonly loading?: boolean
  /** A page is being fetched over the one shown: a small spinner shows and the rows dim. */
  readonly fetching?: boolean
  /** An already-translated message for a failed load. */
  readonly error?: string | null
  /** The rows of the current page. */
  readonly users?: readonly AdminUserSummary[]
  /** The signed-in user's id, so their row says "You". */
  readonly selfId?: string
  /** The current page, 1-based. */
  readonly page?: number
  /** The last page there is; Next and Last are disabled on it. */
  readonly lastPage?: number
  /** The pager's buttons, already computed (pageItems in @ubgo/auth-react). Just the current page when left out. */
  readonly pageItems?: readonly AdminPagerItem[]
  /** The first row shown, for the "from–to of total" line. */
  readonly from?: number
  /** The last row shown. */
  readonly to?: number
  /** The number of rows over every page. */
  readonly total?: number
  /** The rows per page. */
  readonly pageSize?: number
  /** The page sizes the size menu offers. */
  readonly pageSizes?: readonly number[]
  /** The search box's text as typed. */
  readonly searchText?: string
  /** The field the search reads. */
  readonly searchField?: AdminUsersTableSearchField
  /** The role filter. */
  readonly role?: AdminRoleFilter
  /** The status filter. */
  readonly status?: AdminStatusFilter
  /** The order. */
  readonly sort?: AdminUsersTableSort
  /** The keyboard shortcuts ("/" search, "←"/"→" pages, Esc clears the search). On by default. */
  readonly shortcuts?: boolean
  /** Where a row links to when there is no onOpen. `/admin/users/<id>` by default. */
  readonly userHref?: (userId: string) => string
  /** The link component, a plain anchor by default. */
  readonly Link?: ViewLinkComponent
  /** A row was opened. When set, rows are buttons instead of links. */
  readonly onOpen?: (row: AdminUserSummary) => void
  /** The search text was edited or cleared. */
  readonly onSearchTextChange?: (text: string) => void
  /** Another search field was picked. */
  readonly onSearchFieldChange?: (field: AdminUsersTableSearchField) => void
  /** Another role filter was picked. */
  readonly onRoleChange?: (role: AdminRoleFilter) => void
  /** Another status filter was picked. */
  readonly onStatusChange?: (status: AdminStatusFilter) => void
  /** Another order was picked. */
  readonly onSortChange?: (sort: AdminUsersTableSort) => void
  /** A page was asked for, already clamped to 1..lastPage. */
  readonly onPageChange?: (page: number) => void
  /** Another page size was picked. */
  readonly onPageSizeChange?: (size: number) => void
}

export function AdminUsersTableView({
  className,
  classNames,
  text,
  headingLevel = 1,
  forbidden = false,
  loading = false,
  fetching = false,
  error = null,
  users = [],
  selfId,
  page = 1,
  lastPage = 1,
  pageItems,
  from = 0,
  to = 0,
  total = 0,
  pageSize = DEFAULT_PAGE_SIZE,
  pageSizes = DEFAULT_PAGE_SIZES,
  searchText = "",
  searchField = "email",
  role = "all",
  status = "all",
  sort = "created_desc",
  shortcuts = true,
  userHref = defaultUserHref,
  Link = AnchorLink,
  onOpen,
  onSearchTextChange,
  onSearchFieldChange,
  onRoleChange,
  onStatusChange,
  onSortChange,
  onPageChange,
  onPageSizeChange,
}: AdminUsersTableViewProps) {
  const t: AdminUsersTableText = { ...ADMIN_USERS_TABLE_TEXT, ...text }
  const searchId = useId()
  const searchRef = useRef<HTMLInputElement>(null)
  const goTo = (next: number) => onPageChange?.(Math.min(lastPage, Math.max(1, next)))

  // "/" focuses the search, "←" and "→" turn pages, wherever focus is but a field or a menu.
  useEffect(() => {
    if (!shortcuts) return
    const onKey = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey || typingIn(e.target)) return
      if (e.key === "/") {
        e.preventDefault()
        searchRef.current?.focus()
      } else if (e.key === "ArrowLeft") {
        onPageChange?.(Math.max(1, page - 1))
      } else if (e.key === "ArrowRight") {
        onPageChange?.(Math.min(lastPage, page + 1))
      }
    }
    document.addEventListener("keydown", onKey)
    return () => document.removeEventListener("keydown", onKey)
  }, [shortcuts, page, lastPage, onPageChange])

  const sortText: Record<AdminUsersTableSort, string> = {
    created_desc: t.sortNewest,
    created_asc: t.sortOldest,
    name_asc: t.sortNameAsc,
    name_desc: t.sortNameDesc,
  }
  const roleText: Record<AdminRoleFilter, string> = { all: t.roleAll, admins: t.roleAdmins, others: t.roleOthers }
  const statusText: Record<AdminStatusFilter, string> = { all: t.statusAll, banned: t.statusBanned, active: t.statusActive }
  const fieldText: Record<AdminUsersTableSearchField, string> = { email: t.fieldEmail, name: t.fieldName }

  const onSearchKey = (e: ReactKeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Escape" && searchText !== "") {
      e.preventDefault()
      onSearchTextChange?.("")
    }
  }

  return (
    <Card className={cn("w-full max-w-5xl", className, classNames?.root)}>
      <CardHeader className={classNames?.header}>
        <CardTitle className={cn("flex items-center gap-2", classNames?.title)} role="heading" aria-level={headingLevel}>
          <UsersRoundIcon aria-hidden className="size-4 text-muted-foreground" />
          {t.title}
          {fetching && !loading && <Spinner className="size-3 text-muted-foreground" />}
        </CardTitle>
        <CardDescription className={classNames?.description}>{t.description}</CardDescription>
      </CardHeader>
      <CardContent className={cn("flex flex-col gap-2", classNames?.content)}>
        {forbidden ? (
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
                  onChange={(e) => onSearchTextChange?.(e.target.value)}
                  onKeyDown={onSearchKey}
                  placeholder={fillText(t.searchPlaceholder, { field: fieldText[searchField] })}
                  className={cn("pr-14 pl-7 [&::-webkit-search-cancel-button]:hidden", classNames?.search)}
                />
                <span className="absolute top-1/2 right-1.5 flex -translate-y-1/2 items-center gap-1">
                  {searchText !== "" ? (
                    <Button type="button" variant="ghost" size="icon-xs" aria-label={t.clearSearch} onClick={() => onSearchTextChange?.("")}>
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
                options={ADMIN_USERS_TABLE_SEARCH_FIELDS}
                text={fieldText}
                onChange={(v) => onSearchFieldChange?.(v)}
                className={classNames?.filter}
              />
              <FilterMenu label={t.roleLabel} value={role} options={ADMIN_ROLE_FILTERS} text={roleText} onChange={(v) => onRoleChange?.(v)} className={classNames?.filter} />
              <FilterMenu
                label={t.statusLabel}
                value={status}
                options={ADMIN_STATUS_FILTERS}
                text={statusText}
                onChange={(v) => onStatusChange?.(v)}
                className={classNames?.filter}
              />
              <FilterMenu label={t.sortLabel} value={sort} options={ADMIN_USERS_TABLE_SORTS} text={sortText} onChange={(v) => onSortChange?.(v)} className={classNames?.filter} />
            </div>

            {error !== null && (
              <Alert variant="destructive" className={classNames?.formError}>
                <CircleAlertIcon aria-hidden />
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            <div className="rounded-lg border">
              <Table className={classNames?.table} aria-busy={fetching}>
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
                <TableBody className={cn(fetching && !loading && "opacity-60 transition-opacity")}>
                  {loading ? (
                    Array.from({ length: SKELETON_ROWS }, (_, i) => (
                      <TableRow key={i} aria-hidden>
                        <TableCell colSpan={5}>
                          <Skeleton className="h-6 w-full" />
                        </TableCell>
                      </TableRow>
                    ))
                  ) : users.length === 0 ? (
                    <TableRow className="hover:bg-transparent">
                      <TableCell colSpan={5} className="py-6 text-center text-muted-foreground">
                        {t.empty}
                      </TableCell>
                    </TableRow>
                  ) : (
                    users.map((u) => (
                      <UserRow key={u.id} row={u} self={u.id === selfId} href={userHref(u.id)} Link={Link} onOpen={onOpen} t={t} classNames={classNames} />
                    ))
                  )}
                </TableBody>
              </Table>
            </div>

            <div className={cn("flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground tabular-nums", classNames?.pagination)}>
              <div className="flex items-center gap-2">
                <span aria-live="polite">{fillText(t.range, { from, to, total })}</span>
                <DropdownMenu>
                  <DropdownMenuTrigger render={<Button type="button" variant="ghost" size="sm" aria-label={`${t.pageSizeLabel}: ${pageSize}`} />}>
                    {fillText(t.perPage, { size: pageSize })}
                    <ChevronDownIcon aria-hidden />
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="start" className="w-32">
                    <DropdownMenuGroup>
                      <DropdownMenuLabel>{t.pageSizeLabel}</DropdownMenuLabel>
                      <DropdownMenuRadioGroup value={String(pageSize)} onValueChange={(next: string) => onPageSizeChange?.(Number(next))}>
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
                {(pageItems ?? [page]).map((item, i) =>
                  item === ADMIN_PAGER_GAP ? (
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
                      aria-label={fillText(t.pageLabel, { page: item })}
                      aria-current={item === page ? "page" : undefined}
                      onClick={() => goTo(item)}
                    >
                      {item}
                    </Button>
                  ),
                )}
                <Button type="button" variant="ghost" size="icon-sm" aria-label={t.next} disabled={page >= lastPage} onClick={() => goTo(page + 1)}>
                  <ChevronRightIcon aria-hidden />
                </Button>
                <Button type="button" variant="ghost" size="icon-sm" aria-label={t.last} disabled={page >= lastPage} onClick={() => goTo(lastPage)}>
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
  Link,
  onOpen,
  t,
  classNames,
}: {
  row: AdminUserSummary
  self: boolean
  href: string
  Link: ViewLinkComponent
  onOpen: ((row: AdminUserSummary) => void) | undefined
  t: AdminUsersTableText
  classNames: AdminUsersTableViewProps["classNames"]
}) {
  const name = row.name.trim()
  const shown = name === "" ? t.unnamed : name
  const label = fillText(t.openUser, { name: shown })
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
