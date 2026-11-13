// Shared test plumbing: a settable clock, a cookie jar that plays the
// browser, a client wired to the fake server, and a full sign-in.

import { createOidcClient, secret, type OidcClient, type OidcClientBaseOptions, type OidcClientOptions, type OidcEvent, type Logger, type Secret } from "../../src/oidc/index.ts";
import { APP_URL, CLIENT_ID, CLIENT_SECRET, ISSUER, createFakeProvider, type FakeAlg, type FakeProvider } from "./fake-provider.ts";
import { check } from "./harness.ts";

/** A clock a test moves by hand. Starts at a fixed instant so runs are repeatable. */
export class Clock {
  t = Date.UTC(2026, 0, 1);
  readonly now = (): number => this.t;
  advance(ms: number): void {
    this.t += ms;
  }
}

export const SECOND = 1000;
export const MINUTE = 60 * SECOND;

/** A visibly fake 32-character run, so the test secrets below read as fixtures, not keys. */
const FIXTURE_RUN = "0123456789abcdef".repeat(2);
/** 32+ bytes, as the sealer requires. */
export const SESSION_SECRET = `${FIXTURE_RUN}-current`;
export const OLD_SESSION_SECRET = `${FIXTURE_RUN}-previous`;

/** A browser's cookies for the app's origin: what Set-Cookie wrote, sent back as Cookie. */
export class Jar {
  readonly cookies = new Map<string, string>();
  /** Every Set-Cookie value seen, newest last, for tests that read attributes. */
  readonly seen: string[] = [];

  take(response: Response): Response {
    for (const line of response.headers.getSetCookie()) {
      this.seen.push(line);
      const [pair = "", ...attrs] = line.split(";").map((p) => p.trim());
      const eq = pair.indexOf("=");
      const name = pair.slice(0, eq);
      const value = pair.slice(eq + 1);
      const maxAge = attrs.find((a) => a.toLowerCase().startsWith("max-age="));
      if (maxAge !== undefined && Number(maxAge.slice("max-age=".length)) <= 0) this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
    return response;
  }

  header(): string {
    return [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ");
  }

  copy(): Jar {
    const j = new Jar();
    for (const [k, v] of this.cookies) j.cookies.set(k, v);
    return j;
  }
}

/** A request to the app with the jar's cookies. */
export function appRequest(path: string, jar: Jar | undefined, init: RequestInit & { accept?: string } = {}): Request {
  const headers = new Headers(init.headers);
  if (jar !== undefined && jar.cookies.size > 0) headers.set("Cookie", jar.header());
  headers.set("Accept", init.accept ?? "text/html");
  return new Request(APP_URL + path, { ...init, headers });
}

/** A logger that keeps what it is told, for tests that check a failure was logged. */
export function memoryLogger(): Logger & { readonly lines: string[] } {
  const lines: string[] = [];
  const log = (level: string) => (message: string, fields?: Readonly<Record<string, unknown>>) => {
    lines.push(`${level} ${message} ${fields === undefined ? "" : JSON.stringify(fields)}`);
  };
  return { lines, debug: log("debug"), info: log("info"), warn: log("warn"), error: log("error") };
}

/** Everything a test needs: the clock, the fake server, the client, the events it reported, the log. */
export interface World {
  readonly clock: Clock;
  readonly fake: FakeProvider;
  readonly oidc: OidcClient;
  readonly events: OidcEvent[];
  readonly logger: ReturnType<typeof memoryLogger>;
}

/**
 * The options every test client starts from: one concrete arm of the
 * credentials and sealing unions (a secret each), so a test can spread it
 * and override a field without leaving the union.
 */
export type BaseOptions = OidcClientBaseOptions & { readonly clientSecret: Secret; readonly sessionSecret: Secret; readonly previousSessionSecrets?: readonly Secret[] };

/** The options every test client starts from. */
export function baseOptions(w: { clock: Clock; fake: FakeProvider; events: OidcEvent[]; logger: Logger }): BaseOptions {
  return {
    issuer: ISSUER,
    clientId: CLIENT_ID,
    clientSecret: secret(CLIENT_SECRET),
    appUrl: APP_URL,
    sessionSecret: secret(SESSION_SECRET),
    fetch: w.fake.fetch,
    now: w.clock.now,
    logger: w.logger,
    observe: (e) => w.events.push(e),
  };
}

/** A world with a fresh fake and a client built from the base options merged with `make(base)`. */
export async function world(make: (base: BaseOptions, w: { clock: Clock; fake: FakeProvider }) => OidcClientOptions = (b) => b, alg: FakeAlg = "RS256"): Promise<World> {
  const clock = new Clock();
  const fake = await createFakeProvider(clock.now, alg);
  const events: OidcEvent[] = [];
  const logger = memoryLogger();
  const oidc = createOidcClient(make(baseOptions({ clock, fake, events, logger }), { clock, fake }));
  return { clock, fake, oidc, events, logger };
}

/** Starts a sign-in: GET the login route; returns the redirect to the authorization endpoint. */
export async function startLogin(w: World, jar: Jar, returnTo?: string): Promise<URL> {
  const q = returnTo === undefined ? "" : `?return_to=${encodeURIComponent(returnTo)}`;
  const res = jar.take(await w.oidc.login(appRequest(`/auth/login${q}`, jar)));
  check(res.status === 302, `login answered ${res.status}`);
  return new URL(res.headers.get("Location") ?? "");
}

/** The callback request for a callback URL the fake produced. */
export function callbackRequest(callbackUrl: string, jar: Jar): Request {
  const u = new URL(callbackUrl);
  return appRequest(u.pathname + u.search, jar);
}

/** A whole sign-in through the fake; returns the callback's response (cookies already in the jar). */
export async function signIn(w: World, jar: Jar, returnTo?: string): Promise<Response> {
  const auth = await startLogin(w, jar, returnTo);
  return jar.take(await w.oidc.callback(callbackRequest(w.fake.authorize(auth.toString()), jar)));
}

/** GET `path` through `requireSession`, taking the cookies it set; returns the gate. */
export async function gate(w: World, jar: Jar, path = "/dashboard", accept?: string) {
  const g = await w.oidc.requireSession(appRequest(path, jar, accept === undefined ? {} : { accept }));
  if (g.allowed) jar.take(g.commit(new Response("ok")));
  else jar.take(g.response);
  return g;
}
