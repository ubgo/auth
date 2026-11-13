// Package-private: sign-ins in flight. The login route makes the state,
// nonce and PKCE verifier and seals them, with the return path, into the
// flow cookie beside up to two other pending sign-ins; the callback takes
// the one whose state matches. Nothing here is
// re-exported from index.ts.

import { base64url, constantTimeEqual, randomToken, sha256, utf8 } from "./bytes.ts";
import { OidcClientError, OidcErrorCode } from "./errors.ts";
import { isJsonObject, num, parseJsonObject, str, type JsonObject } from "./json.ts";
import { isSameSitePath, type SameSitePath } from "./routes.ts";

/** One sign-in in flight, as the flow cookie holds it. */
export interface Flow {
  /** Sent as `state`; the callback's must equal it (constant time). Binds the callback to this browser (CSRF). */
  readonly state: string;
  /** Sent as `nonce`; the ID token's must equal it. Binds the ID token to this sign-in (replay). */
  readonly nonce: string;
  /** The PKCE code verifier; its S256 challenge was sent. Binds the code to this client instance (code injection). */
  readonly verifier: string;
  /** Where the browser lands afterwards, already through the return policy and the same-site floor. */
  readonly returnTo: SameSitePath;
  /** When the sign-in started (epoch milliseconds); the callback refuses a flow older than `FLOW_TTL_MS`. */
  readonly startedAt: number;
}

/**
 * How long a sign-in may take from the login route to the callback: long
 * enough for a password manager, a second factor and a slow consent page,
 * short enough that a flow cookie left in a shared browser is soon useless.
 */
export const FLOW_TTL_MS = 10 * 60 * 1000;

/** A fresh flow for `returnTo`. */
export function newFlow(returnTo: SameSitePath, now: number): Flow {
  return { state: randomToken(), nonce: randomToken(), verifier: randomToken(), returnTo, startedAt: now };
}

/** The S256 code challenge of `verifier` (RFC 7636 section 4.2). */
export async function codeChallenge(verifier: string): Promise<string> {
  return base64url(await sha256(utf8(verifier)));
}

/**
 * How many sign-ins one browser may have in flight: two tabs that both
 * found their session expired each start one, and both must be able to
 * finish. The oldest is dropped beyond it. The same number as the Go client.
 */
export const MAX_PENDING_FLOWS = 3;

/** The flow cookie's member names. Changing one is a format change. */
const FlowField = { version: "v", flows: "flows", state: "state", nonce: "nonce", verifier: "verifier", returnTo: "return_to", startedAt: "started_at" } as const;

/** The flow encoding's version; another is refused. */
const FLOW_FORMAT_V2 = 2;

/** The pending flows as the text the sealer seals, oldest first. */
export function encodeFlows(flows: readonly Flow[]): string {
  return JSON.stringify({
    [FlowField.version]: FLOW_FORMAT_V2,
    [FlowField.flows]: flows.map((f) => ({
      [FlowField.state]: f.state,
      [FlowField.nonce]: f.nonce,
      [FlowField.verifier]: f.verifier,
      [FlowField.returnTo]: f.returnTo,
      [FlowField.startedAt]: f.startedAt,
    })),
  });
}

/**
 * The pending flows in an opened flow cookie, oldest first, without those
 * outside `FLOW_TTL_MS` of `now` (or started in the future). Anything
 * malformed is `sealedCorrupt`.
 */
export function decodeFlows(text: string, now: number): readonly Flow[] {
  const o = parseJsonObject(text);
  const list = o === undefined ? undefined : o[FlowField.flows];
  if (o === undefined || num(o, FlowField.version) !== FLOW_FORMAT_V2 || !Array.isArray(list)) return malformed();
  return list.map(decodeOne).filter((f) => now >= f.startedAt && now - f.startedAt <= FLOW_TTL_MS);
}

/** One flow record; malformed is `sealedCorrupt`. */
function decodeOne(v: unknown): Flow {
  if (!isJsonObject(v)) return malformed();
  const o: JsonObject = v;
  const state = str(o, FlowField.state);
  const nonce = str(o, FlowField.nonce);
  const verifier = str(o, FlowField.verifier);
  const returnTo = str(o, FlowField.returnTo);
  const startedAt = num(o, FlowField.startedAt);
  if (!state || !nonce || !verifier || startedAt === undefined || returnTo === undefined || !isSameSitePath(returnTo)) return malformed();
  return { state, nonce, verifier, returnTo, startedAt };
}

/** `flows` with `f` appended, the oldest dropped beyond `MAX_PENDING_FLOWS`. */
export function addFlow(flows: readonly Flow[], f: Flow): readonly Flow[] {
  return [...flows, f].slice(-MAX_PENDING_FLOWS);
}

/**
 * The flow whose state is `state` and the flows left without it. Every
 * pending flow is compared in constant time, and all of them always, so the
 * time taken says nothing about which (if any) matched. An empty state
 * matches nothing.
 */
export function takeFlow(flows: readonly Flow[], state: string): { readonly flow: Flow | undefined; readonly rest: readonly Flow[] } {
  let found = -1;
  flows.forEach((f, i) => {
    if (constantTimeEqual(f.state, state) && state !== "") found = i;
  });
  return found < 0 ? { flow: undefined, rest: flows } : { flow: flows[found], rest: flows.filter((_, i) => i !== found) };
}

function malformed(): never {
  throw new OidcClientError(OidcErrorCode.sealedCorrupt, "flow cookie is malformed");
}
