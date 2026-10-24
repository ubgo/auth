// The pure parts of the admin dashboard: which request a users-table state
// becomes, which page buttons a pager shows, and the "from–to of total" a
// page covers. No React and no client here, so test/admin.ts runs them in
// Node and an app with its own table can reuse them.

import type { AdminSearchUsersRequest, AdminUsersRequest } from "@ubgo/auth-client";

/** The orders the users list takes, as plugin/admin's UserSortValues names them. */
export const ADMIN_USER_SORTS = ["created_desc", "created_asc", "name_asc", "name_desc"] as const;

/** One of ADMIN_USER_SORTS. */
export type AdminUserSort = (typeof ADMIN_USER_SORTS)[number];

/** The fields a fragment search reads, as plugin/admin's SearchFieldValues names them. */
export const ADMIN_SEARCH_FIELDS = ["email", "name"] as const;

/** One of ADMIN_SEARCH_FIELDS. */
export type AdminSearchField = (typeof ADMIN_SEARCH_FIELDS)[number];

/**
 * The longest search the server takes (plugin/admin's maxSearchLength); a
 * longer value is cut here rather than refused there.
 */
export const ADMIN_MAX_SEARCH_LENGTH = 320;

/** The page sizes a pager offers by default; the server clamps above 200 (plugin/admin's MaxPageSize). */
export const ADMIN_PAGE_SIZES: readonly number[] = [10, 25, 50, 100];

/** Rows per page when the caller names none: the server's own default (plugin/admin's DefaultPageSize). */
export const ADMIN_DEFAULT_PAGE_SIZE = 50;

/** What a users table asks for. Every field is optional; the empty object is the first page, newest first. */
export type AdminUsersQuery = {
  /** 1-based page. 1 by default. */
  readonly page?: number;
  /** Rows per page. ADMIN_DEFAULT_PAGE_SIZE by default. */
  readonly pageSize?: number;
  /** A fragment to find (search-users); empty or blank lists every user (users). */
  readonly search?: string;
  /** Which field the fragment is matched against. "email" by default. */
  readonly searchField?: AdminSearchField;
  /** Only admins (true), only non-admins (false), or everyone (undefined). */
  readonly admin?: boolean;
  /** Only banned users (true), only users not banned (false), or everyone (undefined). */
  readonly banned?: boolean;
  /** The order. "created_desc" by default. */
  readonly sort?: AdminUserSort;
};

/**
 * The call a users-table state becomes: `searchUsers` when there is a
 * fragment to find, `users` otherwise, with the wire's text-valued query
 * parameters. Only what the caller set is sent, so the server's defaults
 * apply to the rest.
 */
export type AdminUsersCall =
  | { readonly op: "users"; readonly input: AdminUsersRequest }
  | { readonly op: "searchUsers"; readonly input: AdminSearchUsersRequest };

/** Builds the call for a users-table state (see AdminUsersCall). */
export function adminUsersCall(query: AdminUsersQuery): AdminUsersCall {
  const page = normalPage(query.page);
  const limit = normalPageSize(query.pageSize);
  const common: AdminUsersRequest = {
    page: String(page),
    limit: String(limit),
    ...(query.sort === undefined ? {} : { sort: query.sort }),
    ...(query.admin === undefined ? {} : { admin: String(query.admin) }),
    ...(query.banned === undefined ? {} : { banned: String(query.banned) }),
  };
  const value = (query.search ?? "").trim().slice(0, ADMIN_MAX_SEARCH_LENGTH);
  if (value === "") return { op: "users", input: common };
  return { op: "searchUsers", input: { ...common, value, field: query.searchField ?? "email" } };
}

/** A whole page number of at least 1; anything else (0, negative, NaN, a fraction) becomes the nearest valid one. */
export function normalPage(page: number | undefined): number {
  if (page === undefined || !Number.isFinite(page)) return 1;
  return Math.max(1, Math.floor(page));
}

/** A whole page size of at least 1; anything else becomes ADMIN_DEFAULT_PAGE_SIZE. */
export function normalPageSize(size: number | undefined): number {
  if (size === undefined || !Number.isFinite(size) || size < 1) return ADMIN_DEFAULT_PAGE_SIZE;
  return Math.floor(size);
}

/** The last page for a total, at least 1 so an empty table still has a page. */
export function lastPage(total: number, pageSize: number): number {
  const size = normalPageSize(pageSize);
  if (!Number.isFinite(total) || total <= 0) return 1;
  return Math.ceil(total / size);
}

/** The rows a page covers, 1-based and inclusive; {0, 0} on an empty table or a page past the end. */
export function pageRange(page: number, pageSize: number, total: number): { readonly from: number; readonly to: number } {
  const size = normalPageSize(pageSize);
  const p = normalPage(page);
  const from = (p - 1) * size + 1;
  if (!Number.isFinite(total) || total <= 0 || from > total) return { from: 0, to: 0 };
  return { from, to: Math.min(p * size, total) };
}

/** The gap marker in a pager's buttons. */
export const PAGE_GAP = "gap" as const;

/** A pager button: a page number, or a gap standing for the pages it skips. */
export type PageItem = number | typeof PAGE_GAP;

/**
 * The buttons a numbered pager shows: always the first and the last page,
 * `siblings` pages either side of the current one, and a gap for each run
 * of skipped pages. A gap never hides a single page (that page is shown
 * instead, since the button costs the same space), so the list has at most
 * 2 × siblings + 5 items whatever the page count. The current page is
 * clamped into 1..last.
 */
export function pageItems(current: number, last: number, siblings = 1): readonly PageItem[] {
  const end = Math.max(1, Math.floor(Number.isFinite(last) ? last : 1));
  const at = Math.min(normalPage(current), end);
  const side = Math.max(0, Math.floor(siblings));
  // Every page fits in the fixed width: no gaps needed.
  if (end <= 2 * side + 5) return Array.from({ length: end }, (_, i) => i + 1);
  let lo = Math.max(2, at - side);
  let hi = Math.min(end - 1, at + side);
  // Keep the window the same width at either end, so the pager does not jump.
  if (at - side <= 3) {
    lo = 2;
    hi = 2 * side + 3;
  } else if (at + side >= end - 2) {
    lo = end - 2 * side - 2;
    hi = end - 1;
  }
  const items: PageItem[] = [1];
  if (lo > 2) items.push(PAGE_GAP);
  for (let p = lo; p <= hi; p++) items.push(p);
  if (hi < end - 1) items.push(PAGE_GAP);
  items.push(end);
  return items;
}
