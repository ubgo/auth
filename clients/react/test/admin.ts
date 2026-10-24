// The pure parts of the admin dashboard (src/admin-paging.ts), case by case:
// the pager's buttons across page counts and positions, the page range, and
// which request a table state becomes. Node runs this file directly (type
// stripping, Node 22.18+): `node test/admin.ts` from clients/react; task
// ui:check runs it. It prints one line per failed case and exits non-zero.

import { PAGE_GAP, adminUsersCall, lastPage, pageItems, pageRange, type AdminUsersCall, type AdminUsersQuery, type PageItem } from "../src/admin-paging.ts";

// Node's process, declared here so the package needs no @types/node.
declare const process: { exitCode?: number };

let failures = 0;
function expect(name: string, got: unknown, want: unknown): void {
  const g = JSON.stringify(got);
  const w = JSON.stringify(want);
  if (g !== w) {
    failures++;
    console.log(`FAIL ${name}: got ${g}, want ${w}`);
  }
}

const G = PAGE_GAP;

/** pageItems: [current, last, siblings, want]. */
const PAGER: readonly (readonly [number, number, number, readonly PageItem[]])[] = [
  // Few pages: every page, no gap.
  [1, 1, 1, [1]],
  [1, 0, 1, [1]],
  [1, 2, 1, [1, 2]],
  [3, 7, 1, [1, 2, 3, 4, 5, 6, 7]],
  // Many pages, the current page at the start, the middle and the end.
  [1, 10, 1, [1, 2, 3, 4, 5, G, 10]],
  [4, 10, 1, [1, 2, 3, 4, 5, G, 10]],
  [5, 10, 1, [1, G, 4, 5, 6, G, 10]],
  [6, 10, 1, [1, G, 5, 6, 7, G, 10]],
  [7, 10, 1, [1, G, 6, 7, 8, 9, 10]],
  [10, 10, 1, [1, G, 6, 7, 8, 9, 10]],
  [50, 100, 1, [1, G, 49, 50, 51, G, 100]],
  // Out of range is clamped: past the end is the last page, 0 and negatives the first.
  [99, 10, 1, [1, G, 6, 7, 8, 9, 10]],
  [0, 10, 1, [1, 2, 3, 4, 5, G, 10]],
  [-3, 10, 1, [1, 2, 3, 4, 5, G, 10]],
  [Number.NaN, 10, 1, [1, 2, 3, 4, 5, G, 10]],
  // No siblings and two siblings.
  [5, 20, 0, [1, G, 5, G, 20]],
  [10, 20, 2, [1, G, 8, 9, 10, 11, 12, G, 20]],
];

for (const [current, last, siblings, want] of PAGER) {
  const got = pageItems(current, last, siblings);
  expect(`pageItems(${current}, ${last}, ${siblings})`, got, want);
  // Invariants on every case: first and last present, ascending, no gap hides a single page, bounded width.
  const nums = got.filter((x): x is number => x !== G);
  const end = Math.max(1, last);
  if (nums[0] !== 1 || nums[nums.length - 1] !== end) expect(`pageItems(${current}, ${last}) ends`, [nums[0], nums[nums.length - 1]], [1, end]);
  for (let i = 1; i < got.length; i++) {
    const a = got[i - 1];
    const b = got[i];
    if (a === undefined || b === undefined) continue;
    if (a === G && b === G) expect(`pageItems(${current}, ${last}) two gaps in a row`, got, "no adjacent gaps");
    if (a !== G && b !== G && b !== a + 1) expect(`pageItems(${current}, ${last}) consecutive`, [a, b], "consecutive");
    const before = got[i - 2];
    if (a === G && before !== undefined && before !== G && b !== G && b - before < 3) expect(`pageItems(${current}, ${last}) gap hides one page`, [before, b], "gap of 2+");
  }
  if (got.length > 2 * siblings + 5) expect(`pageItems(${current}, ${last}, ${siblings}) width`, got.length, `<= ${2 * siblings + 5}`);
}

// Every position on every size up to 30 keeps the width bound and contains the current page.
for (let last = 1; last <= 30; last++) {
  for (let current = 1; current <= last; current++) {
    const got = pageItems(current, last);
    if (!got.includes(current)) expect(`pageItems(${current}, ${last}) shows the current page`, got, current);
    if (got.length > 7) expect(`pageItems(${current}, ${last}) width`, got.length, "<= 7");
  }
}

// lastPage and pageRange.
expect("lastPage(0, 50)", lastPage(0, 50), 1);
expect("lastPage(50, 50)", lastPage(50, 50), 1);
expect("lastPage(51, 50)", lastPage(51, 50), 2);
expect("lastPage(67, 10)", lastPage(67, 10), 7);
expect("lastPage(10, 0) falls back to the default size", lastPage(10, 0), 1);
expect("pageRange(1, 50, 67)", pageRange(1, 50, 67), { from: 1, to: 50 });
expect("pageRange(2, 50, 67)", pageRange(2, 50, 67), { from: 51, to: 67 });
expect("pageRange(1, 50, 0)", pageRange(1, 50, 0), { from: 0, to: 0 });
expect("pageRange(3, 50, 67) past the end", pageRange(3, 50, 67), { from: 0, to: 0 });
expect("pageRange(0, 10, 5) clamps the page", pageRange(0, 10, 5), { from: 1, to: 5 });

// adminUsersCall: which operation and which wire parameters.
const CALLS: readonly (readonly [string, AdminUsersQuery, AdminUsersCall])[] = [
  ["the empty query is page 1 at the default size", {}, { op: "users", input: { page: "1", limit: "50" } }],
  ["filters and sort are sent as text", { page: 3, pageSize: 25, admin: true, banned: false, sort: "name_asc" }, { op: "users", input: { page: "3", limit: "25", sort: "name_asc", admin: "true", banned: "false" } }],
  ["a blank search lists every user", { search: "   " }, { op: "users", input: { page: "1", limit: "50" } }],
  ["a search becomes search-users on email by default, trimmed", { search: "  ada " }, { op: "searchUsers", input: { page: "1", limit: "50", value: "ada", field: "email" } }],
  ["a name search keeps case and the filters", { search: "Ada", searchField: "name", banned: true }, { op: "searchUsers", input: { page: "1", limit: "50", banned: "true", value: "Ada", field: "name" } }],
  ["a bad page and size fall back", { page: -2, pageSize: 0 }, { op: "users", input: { page: "1", limit: "50" } }],
  ["a fractional page is floored", { page: 2.7 }, { op: "users", input: { page: "2", limit: "50" } }],
];
for (const [name, query, want] of CALLS) expect(`adminUsersCall: ${name}`, adminUsersCall(query), want);

const long = adminUsersCall({ search: "x".repeat(400) });
expect("adminUsersCall cuts a search to the server's limit", long.op === "searchUsers" ? long.input.value.length : -1, 320);

if (failures > 0) {
  console.log(`${failures} admin paging case(s) failed`);
  process.exitCode = 1;
} else {
  console.log("admin paging: every case passed");
}
