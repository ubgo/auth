// Bearer mode: an app that cannot keep the session cookie (a mobile app, a
// desktop or CLI program, a frontend on another site) keeps the token itself.
// The client asks for it, stores it, sends it, and forgets it on sign-out.
// Type-checked by task ts:check.

import { createAuthClient, password, type AuthError, type TokenStore } from "../src/index.ts";

// A TokenStore over localStorage, for a browser app on another site. Any
// script on the page can read localStorage, so prefer cookie mode on your
// own site; this is for when the cookie cannot work.
// ds:def id=bearer-localstore-8wq2mk4z owner=@khanakia stability=stable
export function localStorageTokenStore(key = "auth-token"): TokenStore {
  return {
    get: () => localStorage.getItem(key),
    set: (token) => {
      if (token === null) localStorage.removeItem(key);
      else localStorage.setItem(key, token);
    },
  };
}

// The shape a platform's secure storage usually has (a keychain, a
// keystore, an encrypted file): async get, set and delete by key. Wrap the
// one your platform offers in this, then hand it to secureTokenStore.
// ds:def id=bearer-securestorage-3kv9qx7m owner=@khanakia stability=stable
export interface SecureStorage {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  deleteItem(key: string): Promise<void>;
}

// A TokenStore may be async: the client awaits get() before each request
// and set() after each answer that issues or ends a token.
// ds:def id=bearer-securestore-6nm4wq2t owner=@khanakia stability=stable
export function secureTokenStore(storage: SecureStorage, key = "auth-token"): TokenStore {
  return {
    get: () => storage.getItem(key),
    set: (token) => (token === null ? storage.deleteItem(key) : storage.setItem(key, token)),
  };
}

// React Native with Expo: expo-secure-store already has this shape under
// other names, so `expoSecureStorage(SecureStore)` (after
// `import * as SecureStore from "expo-secure-store"`) is a SecureStorage
// backed by the iOS keychain and the Android keystore.
// ds:def id=bearer-expostore-4qw8kx2m owner=@khanakia stability=stable
export function expoSecureStorage(store: {
  getItemAsync(key: string): Promise<string | null>;
  setItemAsync(key: string, value: string): Promise<void>;
  deleteItemAsync(key: string): Promise<void>;
}): SecureStorage {
  return {
    getItem: (key) => store.getItemAsync(key),
    setItem: (key, value) => store.setItemAsync(key, value),
    deleteItem: (key) => store.deleteItemAsync(key),
  };
}

// A cross-site SPA, or a native app: an absolute baseURL and bearer mode.
// ds:def id=bearer-client-2xq7kw9n owner=@khanakia stability=stable
export const remote = createAuthClient({
  baseURL: "https://api.example.com/auth",
  tokenMode: "bearer",
  tokenStore: localStorageTokenStore(),
  plugins: [password()],
});

// Sign out. The client forgets the token by itself when the server accepts,
// and also when it answers auth.signed_out: the session had already ended
// (expired, revoked from another device), so the token is dead either way.
// Any other error (a network failure, a rate limit) leaves the session and
// the token in place, so the user can try again.
// ds:def id=bearer-signout-7nk3wq9x owner=@khanakia stability=stable
export async function signOutRemote(): Promise<AuthError | null> {
  const { error } = await remote.signOut();
  return error?.code === "auth.signed_out" ? null : error;
}

// Server-side code (a Node, Bun or Deno server rendering a page) calling the
// API for the browser that asked: forward that browser's Cookie header on a
// client made for this one request. Reads only: a mutation sent with a cookie
// must also carry a trusted Origin, which a server-side caller does not have.
// ds:def id=bearer-serverside-5qk2nw8v owner=@khanakia stability=stable
export async function userForRequest(cookieHeader: string): Promise<string | null> {
  const perRequest = createAuthClient({
    baseURL: "http://localhost:8081/auth",
    headers: { Cookie: cookieHeader },
  });
  const { data } = await perRequest.session();
  return data?.user.id ?? null;
}
