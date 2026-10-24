// Client-wide hooks, typed session extras, a persistent token store and the
// last-login hint. Type-checked by task ts:check; docs/client/reference.md
// and docs/client/plugins.md show these blocks.

import { createAuthClient, keyValueTokenStore, lastLoginMethod, LAST_LOGIN_STORAGE_KEY, password, type KeyValueStorage } from "../src/index.ts";

// Hooks see every call: add a header, log refusals, time requests. A hook
// that throws fails the call with client.hook_failed.
// ds:def id=tsx-hooks-client-5qw8kn3v owner=@khanakia stability=stable
export const traced = createAuthClient({
  baseURL: "/auth",
  plugins: [password()],
  onRequest: ({ headers }) => {
    headers.set("X-Request-Id", crypto.randomUUID());
  },
  onError: ({ op, error }) => {
    if (error.code !== "auth.signed_out") console.warn(op.id, error.code, error.rawCode);
  },
});

// The server's auth.WithSessionExtras returns any, so the app says what the
// extras are: a decoder that returns them typed, or throws (the call then
// fails with client.invalid_response).
interface Plan {
  readonly plan: "free" | "pro";
  readonly seats: number;
}

// ds:def id=tsx-session-extras-8mv2qk4w owner=@khanakia stability=stable
function planExtras(value: unknown): Plan {
  if (typeof value === "object" && value !== null && "plan" in value && "seats" in value) {
    const { plan, seats } = value;
    if ((plan === "free" || plan === "pro") && typeof seats === "number") return { plan, seats };
  }
  throw new Error("session extras are not a Plan");
}

export const withPlan = createAuthClient({ baseURL: "/auth", sessionExtras: planExtras });

// ds:def id=tsx-session-seats-4wq9kn2v owner=@khanakia stability=stable
export async function seatsLeft(used: number): Promise<number> {
  const { data } = await withPlan.session();
  return (data?.extras?.seats ?? 0) - used; // extras is Plan here
}

// A bearer token kept across reloads: localStorage in a browser, or any
// store with getItem/setItem/removeItem (React Native's AsyncStorage).
// ds:def id=tsx-keyvalue-store-3nw7qk2m owner=@khanakia stability=stable
export const persistent = createAuthClient({
  baseURL: "https://api.example.com/auth",
  tokenMode: "bearer",
  tokenStore: keyValueTokenStore(localStorage),
  plugins: [password()],
});

// The last-login hint on a sign-in page: put the method used last first.
// In a browser it reads the server's cookie (lastlogin.WithCookie).
// ds:def id=tsx-lastlogin-web-6kq3wn8v owner=@khanakia stability=stable
export const web = createAuthClient({ baseURL: "/auth", plugins: [password(), lastLoginMethod()] });

// ds:def id=tsx-lastlogin-order-9wq4kn7m owner=@khanakia stability=stable
export async function orderMethods(methods: readonly string[]): Promise<string[]> {
  const { data: last } = await web.lastLoginMethod.getLastUsedLoginMethod();
  return [...methods].sort((a, b) => Number(b === last) - Number(a === last));
}

// On React Native the hint lives on the device: the client records the
// method of every sign-in it makes and reads it back with no request.
// ds:def id=tsx-lastlogin-native-2vm8qk5w owner=@khanakia stability=stable
export function nativeClient(asyncStorage: KeyValueStorage) {
  return createAuthClient({
    baseURL: "https://api.example.com/auth",
    tokenMode: "bearer",
    tokenStore: keyValueTokenStore(asyncStorage),
    plugins: [password(), lastLoginMethod({ storage: keyValueTokenStore(asyncStorage, LAST_LOGIN_STORAGE_KEY) })],
  });
}
