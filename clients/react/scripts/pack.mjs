// Build, publish guard and publish dry run for @ubgo/auth-react.
//
//   node scripts/pack.mjs build     dist/: .js and .d.ts for every module in src/
//   node scripts/pack.mjs guard     refuse a publish not run through pnpm (prepublishOnly)
//   node scripts/pack.mjs dry-run   pnpm pack, check the tarball, npm publish --dry-run on it
//
// Why two manifests: in this repository the package's `exports` points at
// src/index.ts, because the showcase, the demo and the examples link the
// package (`link:../../clients/react`) and bundle and type-check its source
// directly, with no build step. The published package must point at dist/
// instead; `publishConfig.exports` says so, and pnpm (not npm) applies
// `publishConfig` when it packs. So the tarball is made with `pnpm pack`, and a
// real publish is `pnpm publish`; `npm publish` from this folder would ship the
// source paths, which `guard` refuses. `npm publish --dry-run` is run on the
// pnpm-made tarball, which is the exact file a real publish uploads.
//
// No dependencies beyond Node and the package's own typescript devDependency.
import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** The package folder (clients/react), whatever the caller's working directory. */
const ROOT = new URL("..", import.meta.url).pathname;
/** Where `build` writes; the only code folder the tarball carries. */
const DIST = join(ROOT, "dist");
/** The emit config: tsconfig.json's strict options, src/ only, with emit on. */
const BUILD_TSCONFIG = join(ROOT, "tsconfig.build.json");

/** The subcommands, as typed on the command line. */
const COMMAND = Object.freeze({ build: "build", guard: "guard", dryRun: "dry-run" });

/**
 * Every path the tarball may hold, apart from dist/: npm always adds
 * package.json and README, and LICENSE when the folder has one. Anything else
 * (src/, registry/, test/, showcase/) in the tarball fails the dry run.
 */
const ALLOWED_TOP_LEVEL = new Set(["package.json", "README.md", "LICENSE"]);
/** The prefix every packed path carries inside an npm tarball. */
const TARBALL_PREFIX = "package/";

/**
 * Relative specifiers ending in .ts or .tsx inside a declaration file.
 * rewriteRelativeImportExtensions rewrites them to .js in the emitted .js but
 * leaves .d.ts files alone (TypeScript 5.7+ behaviour), and a consumer's
 * TypeScript resolves "./context.js" to context.d.ts but not "./context.tsx".
 */
const DTS_TS_SPECIFIER = /(from\s+|import\s*\(\s*)(["'])(\.{1,2}\/[^"']+?)\.tsx?\2/g;

/** Runs a program with inherited output and fails the script when it fails. */
function run(file, args, cwd = ROOT) {
  execFileSync(file, args, { cwd, stdio: "inherit" });
}

/** Runs a program and returns its standard output as text. */
function capture(file, args, cwd = ROOT) {
  return execFileSync(file, args, { cwd, encoding: "utf8" });
}

/** Every file target in a package.json `exports` value: the strings at its leaves, conditions and subpaths walked. */
function exportTargets(value) {
  if (typeof value === "string") return [value];
  if (value === null || typeof value !== "object") return [];
  return Object.values(value).flatMap(exportTargets);
}

/** Every file under a folder, as paths relative to it. */
function walk(dir, prefix = "") {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory() ? walk(join(dir, entry.name), `${prefix}${entry.name}/`) : [`${prefix}${entry.name}`],
  );
}

/** Emits dist/ from src/ and makes every .d.ts import its siblings by .js. */
function build() {
  rmSync(DIST, { recursive: true, force: true });
  const tsc = createRequire(import.meta.url).resolve("typescript/bin/tsc");
  run(process.execPath, [tsc, "-p", BUILD_TSCONFIG]);
  for (const file of walk(DIST).filter((path) => path.endsWith(".d.ts"))) {
    const path = join(DIST, file);
    const source = readFileSync(path, "utf8");
    const rewritten = source.replace(DTS_TS_SPECIFIER, "$1$2$3.js$2");
    if (rewritten !== source) writeFileSync(path, rewritten);
  }
  const sources = walk(join(ROOT, "src")).filter((path) => /\.tsx?$/.test(path) && !path.endsWith(".d.ts"));
  const emitted = new Set(walk(DIST));
  const missing = sources.filter((path) => {
    const base = path.replace(/\.tsx?$/, "");
    return !emitted.has(`${base}.js`) || !emitted.has(`${base}.d.ts`);
  });
  if (missing.length > 0) throw new Error(`build: no .js or .d.ts emitted for ${missing.join(", ")}`);
}

/**
 * prepublishOnly: only pnpm applies publishConfig.exports, so a publish run
 * by npm (or yarn) from this folder would upload a package whose exports point
 * at src/, which the tarball does not contain.
 */
function guard() {
  const agent = process.env.npm_config_user_agent ?? "";
  if (!agent.startsWith("pnpm/")) {
    throw new Error(`publish @ubgo/auth-react with pnpm (pnpm publish), not "${agent.split(" ")[0] || "unknown"}": only pnpm applies publishConfig.exports`);
  }
}

/**
 * Packs with pnpm into a temporary folder, fails when the tarball holds a path
 * outside dist/ and ALLOWED_TOP_LEVEL or when its manifest's exports name a
 * file it does not carry, then runs `npm publish --dry-run` on that tarball.
 * Never publishes: --dry-run is always passed.
 */
function dryRun() {
  const out = mkdtempSync(join(tmpdir(), "ubgo-auth-react-pack-"));
  try {
    run("pnpm", ["pack", "--pack-destination", out]);
    const tarball = readdirSync(out).find((name) => name.endsWith(".tgz"));
    if (tarball === undefined) throw new Error(`dry-run: pnpm pack wrote no .tgz into ${out}`);
    const tarballPath = join(out, tarball);

    const files = capture("tar", ["-tzf", tarballPath])
      .split("\n")
      .filter((line) => line !== "")
      .map((line) => line.slice(TARBALL_PREFIX.length));
    const stray = files.filter((path) => !path.startsWith("dist/") && !ALLOWED_TOP_LEVEL.has(path));
    if (stray.length > 0) throw new Error(`dry-run: the tarball carries files outside dist/: ${stray.join(", ")}`);

    const manifest = JSON.parse(capture("tar", ["-xzOf", tarballPath, `${TARBALL_PREFIX}package.json`]));
    // The leaf values of the exports map are file targets; its keys (".",
    // or a subpath like "./hooks" if one is added) are not files, so only
    // values are checked.
    const targets = exportTargets(manifest.exports);
    const absent = targets.map((target) => target.slice(2)).filter((path) => !files.includes(path));
    if (targets.length === 0 || absent.length > 0) {
      throw new Error(`dry-run: the packed exports name files the tarball lacks: ${absent.join(", ") || "(no exports)"}`);
    }

    console.log(`\n${tarball}: ${files.length} files`);
    for (const path of files.sort()) console.log(`  ${path}`);
    console.log("");
    run("npm", ["publish", "--dry-run", tarballPath]);
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
}

const command = process.argv[2];
switch (command) {
  case COMMAND.build:
    build();
    break;
  case COMMAND.guard:
    guard();
    break;
  case COMMAND.dryRun:
    dryRun();
    break;
  default:
    throw new Error(`usage: node scripts/pack.mjs ${Object.values(COMMAND).join("|")} (got ${command ?? "nothing"})`);
}
