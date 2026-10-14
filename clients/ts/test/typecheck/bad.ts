// Code that MUST NOT compile: task ts:typecheck runs tsc on this file and
// fails unless every line marked `expect TSnnnn` errors with exactly that
// code and no other line errors. Each marked line is a mistake the typed
// client exists to catch at compile time.

import { createAuthClient, oauthPopup, oauthprovider, password } from "../../src/index.ts";

const client = createAuthClient({ baseURL: "/auth", plugins: [password()] });

const typed = createAuthClient({
  baseURL: "/auth",
  plugins: [oauthPopup(), oauthprovider()],
  sessionExtras: (v: unknown): { plan: string } => ({ plan: String(v) }),
});

// ds:def id=typecheck-mistakes-6qw2kx9m owner=@khanakia stability=stable
export async function mistakes(): Promise<void> {
  // A plugin that was not enabled has no namespace.
  await client.twofactor.verify({ code: "123456" }); // expect TS2339
  // A required input field left out.
  await client.password.signIn({ identifier: "a@example.com" }); // expect TS2345
  // A field of the wrong type.
  await client.password.signIn({ identifier: 42, password: "x" }); // expect TS2322
  // A field the server would refuse as unknown.
  await client.password.signIn({ identifier: "a@example.com", password: "x", keepMeIn: true }); // expect TS2353
  // A misspelt error code: the code is a closed union.
  const r = await client.password.signIn({ identifier: "a@example.com", password: "x" });
  if (r.error?.code === "password.invalid_credential") return; // expect TS2367
  // data is null until error is checked.
  console.log(r.data.user.id); // expect TS18047
}

// ds:def id=typecheck-extensions-3kq8wn5v owner=@khanakia stability=stable
export async function extensionMistakes(): Promise<void> {
  // The session extras have the decoder's type: a member it lacks is an error.
  const s = await typed.session();
  console.log(s.data?.extras?.seats); // expect TS2339
  // A popup error code is a closed union too.
  const p = await typed.oauthPopup.signIn({ provider: "google" });
  if (p.error?.code === "popup.closd") return; // expect TS2367
  // oauth_query is filled by the client, but the answer itself is still required.
  await typed.oauthprovider.consent({ scope: "openid" }); // expect TS2345
}
