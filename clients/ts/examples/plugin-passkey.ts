// The passkey plugin from a browser. Every ceremony is begin, the browser's
// WebAuthn prompt, finish. The server speaks WebAuthn JSON (the options and
// the credential are typed unknown, because the Go types marshal
// themselves); navigator.credentials speaks binary, so the page converts
// both ways. The React kit's createPasskeyCredential and
// getPasskeyCredential do exactly that; here the conversion is passed in.
// Type-checked by task ts:check; the "From TypeScript" section of
// docs/plugins/passkey.md shows these blocks.

import { createAuthClient, passkey } from "../src/index.ts";

const auth = createAuthClient({ baseURL: "/auth", plugins: [passkey()] });

/** Runs one WebAuthn prompt on the options JSON and answers the credential JSON, or null when the person closed it. */
export type Ceremony = (options: unknown) => Promise<unknown>;

// Add a passkey to the signed-in account: a FreshSignIn operation.
// ds:def id=tsp-passkey-register-6kq3wx8m owner=@khanakia stability=stable
export async function addPasskey(create: Ceremony, name: string): Promise<string | null> {
  const begun = await auth.passkey.registerBegin({});
  if (begun.error) return null; // auth.fresh_session_required: re-authenticate, then retry
  const credential = await create(begun.data.options);
  if (credential === null) return null;
  const { data } = await auth.passkey.registerFinish({ ceremony: begun.data.ceremony, credential, name });
  return data?.id ?? null;
}

// Sign in with a passkey. name is unused at sign-in and goes empty.
// ds:def id=tsp-passkey-signin-4wm8qk2x owner=@khanakia stability=stable
export async function signInWithPasskey(get: Ceremony): Promise<"signed-in" | "second-factor" | "failed"> {
  const begun = await auth.passkey.loginBegin();
  if (begun.error) return "failed";
  const credential = await get(begun.data.options);
  if (credential === null) return "failed";
  const { data, error } = await auth.passkey.loginFinish({ ceremony: begun.data.ceremony, credential });
  if (error) return "failed"; // passkey.invalid or passkey.ceremony_invalid
  return data.secondFactorRequired ? "second-factor" : "signed-in";
}

// The account page: list, rename, remove (remove is a FreshSignIn operation,
// and refuses the user's last way in with auth.last_sign_in_method).
// ds:def id=tsp-passkey-manage-8nx2wq5k owner=@khanakia stability=stable
export async function renameAndPrune(keepId: string, newName: string): Promise<number> {
  const { data } = await auth.passkey.list();
  await auth.passkey.rename({ id: keepId, name: newName });
  let removed = 0;
  for (const key of data?.passkeys ?? []) {
    if (key.id === keepId) continue;
    const { error } = await auth.passkey.remove({ id: key.id });
    if (!error) removed++;
  }
  return removed;
}

// Prove it is still you with a passkey, on the session already held, before
// a FreshSignIn operation is retried. No new session is created.
// ds:def id=tsp-passkey-reauth-3mq9kw7n owner=@khanakia stability=stable
export async function reauthenticateWithPasskey(get: Ceremony): Promise<"fresh" | "second-factor" | "failed"> {
  const begun = await auth.passkey.reauthenticateBegin();
  if (begun.error) return "failed";
  const credential = await get(begun.data.options);
  if (credential === null) return "failed";
  const { data, error } = await auth.passkey.reauthenticateFinish({ ceremony: begun.data.ceremony, credential });
  if (error) return "failed";
  return data.fresh ? "fresh" : "second-factor"; // second-factor: finish with twofactor.reauthenticate and data.ticket
}
