// The open-redirect rule of src/redirect.ts, case by case. Node runs this
// file directly (type stripping, Node 22.18+): `node test/redirect.ts` from
// clients/react; task ui:check runs it. It prints one line per failed case
// and exits non-zero, so a loosened check fails the gate.

import { safeRedirect, safeRedirectOrUndefined } from "../src/redirect.ts";

// Node's process, declared here so the package needs no @types/node.
declare const process: { exitCode?: number };

/** The fallback every case uses, so a refused target is easy to read in a failure. */
const FALLBACK = "/home";

/** One case: the target, and what safeRedirect must answer (FALLBACK means refused). */
type Case = { readonly target: string | null | undefined; readonly want: string; readonly allowedOrigins?: readonly string[] };

const CASES: readonly Case[] = [
  // Paths on this site pass unchanged, query and fragment included.
  { target: "/account", want: "/account" },
  { target: "/account?tab=security#passkeys", want: "/account?tab=security#passkeys" },
  { target: "/", want: "/" },
  { target: "/two-factor?redirectTo=%2Faccount", want: "/two-factor?redirectTo=%2Faccount" },
  // Absent and empty give the fallback.
  { target: undefined, want: FALLBACK },
  { target: null, want: FALLBACK },
  { target: "", want: FALLBACK },
  // Another site, every spelling a browser accepts.
  { target: "https://evil.example", want: FALLBACK },
  { target: "http://evil.example/account", want: FALLBACK },
  { target: "//evil.example", want: FALLBACK },
  { target: "///evil.example", want: FALLBACK },
  { target: "/\\evil.example", want: FALLBACK },
  { target: "\\\\evil.example", want: FALLBACK },
  { target: "/\t/evil.example", want: FALLBACK },
  { target: "/\n/evil.example", want: FALLBACK },
  { target: " /account", want: FALLBACK },
  { target: "javascript:alert(1)", want: FALLBACK },
  { target: "data:text/html,<script>alert(1)</script>", want: FALLBACK },
  { target: "evil.example", want: FALLBACK },
  { target: "account", want: FALLBACK },
  // Encoded so that a later decode makes it another site.
  { target: "/%2F/evil.example", want: FALLBACK },
  { target: "%2F%2Fevil.example", want: FALLBACK },
  { target: "/%5Cevil.example", want: FALLBACK },
  { target: "/%252F%252Fevil.example", want: FALLBACK },
  { target: "/%09/evil.example", want: FALLBACK },
  { target: "/%E0%A4%A", want: FALLBACK },
  // The escape hatch: an allow-listed origin, and only that origin.
  { target: "https://app.example.com/dashboard", want: "https://app.example.com/dashboard", allowedOrigins: ["https://app.example.com"] },
  { target: "https://app.example.com:8443/x", want: FALLBACK, allowedOrigins: ["https://app.example.com"] },
  { target: "https://app.example.com.evil.example/x", want: FALLBACK, allowedOrigins: ["https://app.example.com"] },
  { target: "https://user:pw@app.example.com/x", want: FALLBACK, allowedOrigins: ["https://app.example.com"] },
  { target: "http://app.example.com/x", want: FALLBACK, allowedOrigins: ["https://app.example.com"] },
  { target: "javascript://app.example.com/%0aalert(1)", want: FALLBACK, allowedOrigins: ["https://app.example.com"] },
  { target: "https://evil.example", want: FALLBACK, allowedOrigins: ["not a url"] },
  // An allow list never loosens the same-site rule.
  { target: "//app.example.com/x", want: FALLBACK, allowedOrigins: ["https://app.example.com"] },
];

let failed = 0;
for (const c of CASES) {
  const options = c.allowedOrigins === undefined ? {} : { allowedOrigins: c.allowedOrigins };
  const got = safeRedirect(c.target, FALLBACK, options);
  if (got !== c.want) {
    failed++;
    console.log(`FAIL safeRedirect(${JSON.stringify(c.target)}${c.allowedOrigins ? `, ${JSON.stringify(c.allowedOrigins)}` : ""}) = ${JSON.stringify(got)}, want ${JSON.stringify(c.want)}`);
  }
  // The undefined form agrees: refused is undefined, accepted is the same value.
  const loose = safeRedirectOrUndefined(c.target, options);
  const wantLoose = c.want === FALLBACK ? undefined : c.want;
  if (loose !== wantLoose) {
    failed++;
    console.log(`FAIL safeRedirectOrUndefined(${JSON.stringify(c.target)}) = ${JSON.stringify(loose)}, want ${JSON.stringify(wantLoose)}`);
  }
}

if (failed > 0) {
  console.log(`${failed} redirect check(s) failed`);
  process.exitCode = 1;
} else {
  console.log(`ok: ${CASES.length} redirect cases`);
}
