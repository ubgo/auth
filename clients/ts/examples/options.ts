// The per-call options (signal, headers) and the fetch option, run against a
// stub fetch so no server is needed: `node clients/ts/examples/options.ts`
// (Node 22.18 or later) prints what each call sent and what it resolved to.
// Type-checked by task ts:check; docs/client/reference.md shows its output.

import { createAuthClient, memoryTokenStore, password, type AuthError, type Methods, type PasswordOps } from "../src/index.ts";

/** One request the stub saw: method, path and the headers the guides talk about. */
interface Seen {
  readonly method: string;
  readonly path: string;
  readonly headers: Readonly<Record<string, string>>;
}

const WATCHED_HEADERS = ["accept-language", "authorization", "auth-token-mode", "x-request-id"];

// A fetch for tests: answers from a table of canned responses and records
// every request, so a test can check what the client sent without a server.
// ds:def id=options-stubfetch-7kq3wn5x owner=@khanakia stability=stable
export function stubFetch(answers: Record<string, () => Response>, seen: Seen[]): typeof fetch {
  return async (input, init) => {
    const url = new URL(String(input));
    const headers = new Headers(init?.headers);
    const watched: Record<string, string> = {};
    for (const name of WATCHED_HEADERS) {
      const value = headers.get(name);
      if (value !== null) watched[name] = value;
    }
    seen.push({ method: init?.method ?? "GET", path: url.pathname, headers: watched });
    if (init?.signal?.aborted) throw init.signal.reason;
    const answer = answers[url.pathname];
    return answer ? answer() : new Response("404 page not found", { status: 404 });
  };
}

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
}

const USER = { id: "usr_demo", name: "Ada", image: "" };
const seen: Seen[] = [];
const store = memoryTokenStore();

// The fetch option: any function with fetch's signature. Here a stub; in an
// app a fetch with a cookie jar (server code), a test server's, or one that
// adds tracing.
// ds:def id=options-fetch-3wn8kq2v owner=@khanakia stability=stable
const auth = createAuthClient({
  baseURL: "https://api.example.com/auth",
  tokenMode: "bearer",
  tokenStore: store,
  plugins: [password()],
  headers: { "X-Request-Id": "demo-1" },
  fetch: stubFetch(
    {
      "/auth/password/sign-in": () =>
        json(200, { user: USER, verificationRequired: false, secondFactorRequired: false }, { "Set-Auth-Token": "tok_1" }),
      "/auth/session": () => json(401, { error: { code: "auth.signed_out", message: "Melde dich an, um fortzufahren.", originalMessage: "Sign in to continue." } }),
      "/auth/sign-out": () => json(401, { error: { code: "auth.signed_out", message: "Sign in to continue." } }),
    },
    seen,
  ),
});

// Per-call headers: added to this call only, over the client's headers. Here
// the language the server should translate the message into.
// ds:def id=options-callheaders-5qx2mw8k owner=@khanakia stability=stable
export async function sessionInGerman(): Promise<AuthError | null> {
  const { error } = await auth.session(undefined, { headers: { "Accept-Language": "de" } });
  return error;
}

// signal: give up after a deadline, or when the user leaves the page. An
// aborted call resolves to client.network_error with the abort as its cause;
// it does not throw.
// ds:def id=options-signal-8mw4kx3q owner=@khanakia stability=stable
export async function signInWithin(ms: number, identifier: string, secret: string): Promise<AuthError | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error(`no answer within ${ms}ms`)), ms);
  try {
    const { error } = await auth.password.signIn({ identifier, password: secret }, { signal: controller.signal });
    return error;
  } finally {
    clearTimeout(timer);
  }
}

// The helper types: a function that works with any client's password
// namespace, whatever else that client has. Methods<Ops> is the type of a
// namespace; typeof auth is the type of the whole client.
// ds:def id=options-generic-2kw7qn4x owner=@khanakia stability=stable
export async function signInAs(methods: Methods<PasswordOps>, identifier: string, secret: string): Promise<string | null> {
  const { data } = await methods.signIn({ identifier, password: secret });
  return data?.user.name ?? null;
}

/** The run behind the transcript in docs/client/reference.md. */
async function main(): Promise<void> {
  const signedIn = await auth.password.signIn({ identifier: "ada@example.com", password: "correct horse battery staple" });
  console.log("signIn          ", signedIn.error ? signedIn.error.code : `ok, store holds ${await store.get()}`);

  const german = await sessionInGerman();
  console.log("session (de)    ", german ? `${german.status} ${german.code} "${german.message}" original "${german.originalMessage}"` : "ok");

  const aborted = new AbortController();
  aborted.abort(new Error("user left the page"));
  const gone = await auth.password.signIn({ identifier: "ada@example.com", password: "x" }, { signal: aborted.signal });
  console.log("signIn (aborted)", gone.error ? `${gone.error.status} ${gone.error.code}, cause: ${String(gone.error.cause)}` : "ok");

  // The session is already gone on the server (the stub answers
  // auth.signed_out): the client still forgets the dead token.
  const refused = await auth.signOut();
  console.log("signOut         ", refused.error ? `${refused.error.status} ${refused.error.code}, store holds ${await store.get()}` : "ok");

  console.log("signInAs        ", await signInAs(auth.password, "ada@example.com", "correct horse battery staple"));

  console.log("requests the stub saw:");
  for (const request of seen) console.log(`  ${request.method} ${request.path} ${JSON.stringify(request.headers)}`);
}

await main();
