// The two entries stay apart, read from the source (and from dist/ when a
// build is present): everything the browser entry (src/index.ts) reaches
// through relative imports lies outside src/oidc/, so a browser bundle can
// never pull the server-only relying party in; the oidc entry reaches only
// files inside src/oidc/; and neither imports a bare specifier, so the
// package keeps zero runtime dependencies.

import { check, test } from "./harness.ts";

/** The two Node built-ins this file needs, typed here so the package needs no @types/node. */
declare const process: {
  getBuiltinModule(id: "node:fs"): { readFileSync(path: URL, encoding: "utf8"): string; existsSync(path: URL): boolean };
};
const fs = process.getBuiltinModule("node:fs");

/** Every module specifier in a source file: static imports and re-exports, side-effect imports, and dynamic `import("…")`. */
const SPECIFIER = /(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s+)(["'])([^"']+)\1/g;

/** Every file reachable from `entry` by relative imports, and every non-relative specifier met on the way. */
function reach(entry: URL): { readonly files: ReadonlySet<string>; readonly bare: ReadonlySet<string> } {
  const files = new Set<string>();
  const bare = new Set<string>();
  const queue = [entry];
  while (queue.length > 0) {
    const file = queue.pop();
    if (file === undefined || files.has(file.href)) continue;
    files.add(file.href);
    for (const m of fs.readFileSync(file, "utf8").matchAll(SPECIFIER)) {
      const spec = m[2] ?? "";
      if (spec.startsWith("./") || spec.startsWith("../")) queue.push(new URL(spec, file));
      else bare.add(spec);
    }
  }
  return { files, bare };
}

/** The roots to check: source always, dist/ when built. */
const ROOTS: ReadonlyArray<{ readonly name: string; readonly dir: URL; readonly ext: string }> = [
  { name: "src", dir: new URL("../../src/", import.meta.url), ext: "ts" },
  { name: "dist", dir: new URL("../../dist/", import.meta.url), ext: "js" },
];

for (const root of ROOTS) {
  test(`entries (${root.name}): the browser entry never reaches src/oidc, the oidc entry never leaves it, no runtime dependencies`, () => {
    const browserEntry = new URL(`index.${root.ext}`, root.dir);
    if (root.name === "dist" && !fs.existsSync(browserEntry)) return; // not built: the src run covers the rule
    const oidcDir = new URL("oidc/", root.dir).href;
    const browser = reach(browserEntry);
    const leaked = [...browser.files].filter((f) => f.startsWith(oidcDir));
    check(leaked.length === 0, `browser entry reaches ${leaked.join(", ")}`);
    check(browser.files.size > 1, "browser entry graph was walked");
    const oidc = reach(new URL(`oidc/index.${root.ext}`, root.dir));
    const outside = [...oidc.files].filter((f) => !f.startsWith(oidcDir));
    check(outside.length === 0, `oidc entry reaches ${outside.join(", ")}`);
    check(oidc.files.size > 10, "oidc entry graph was walked");
    check(browser.bare.size === 0 && oidc.bare.size === 0, `bare imports: ${[...browser.bare, ...oidc.bare].join(", ")}`);
  });
}
