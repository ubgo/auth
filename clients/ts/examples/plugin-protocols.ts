// Pages of YOUR app that the protocol plugins send a browser to, written with
// the client: the OAuth provider's consent page and the device-code approval
// page; plus a device client (a CLI on Node) asking for a code and polling.
// Type-checked by task ts:check; the "From TypeScript" sections of
// docs/plugins/oauthprovider.md and deviceauth.md show these blocks.

import { createAuthClient, device, memoryTokenStore, oauthprovider } from "../src/index.ts";

const auth = createAuthClient({ baseURL: "/auth", plugins: [oauthprovider(), device()] });

// oauthprovider: the consent page. The authorize endpoint sends the browser
// here with a signed copy of its parameters in the query; the page shows the
// client and posts the answer with that query unchanged, then NAVIGATES to
// redirect_to (the client's redirect URI with the code, or the error).
// ds:def id=tsp-oauthprovider-consent-4kq8wm2x owner=@khanakia stability=stable
export async function onConsentPage(ask: (clientName: string, scope: string) => Promise<boolean>): Promise<void> {
  const query = new URLSearchParams(location.search);
  const client = await auth.oauthprovider.publicClient({ client_id: query.get("client_id") ?? "" });
  if (client.error) return; // auth.signed_out: the login page comes first
  const accept = await ask(client.data.client_name, query.get("scope") ?? "");
  // Without scope the consent grants every scope the client asked for; a
  // space-separated subset in scope narrows it. The client posts the signed
  // query back itself (oauth_query, from location.search).
  const { data } = await auth.oauthprovider.consent({ accept });
  if (data) location.assign(data.redirect_to);
}

// The user's "connected apps" page: every client they consented to, and
// revoking one (its tokens stop working).
// ds:def id=tsp-oauthprovider-consents-7wn3kx5q owner=@khanakia stability=stable
export async function disconnectApp(clientName: string): Promise<boolean> {
  const { data } = await auth.oauthprovider.listConsents();
  const consent = (data?.consents ?? []).find((c) => c.client_name === clientName);
  if (!consent) return false;
  const { error } = await auth.oauthprovider.revokeConsent({ client_id: consent.client_id });
  return error === null;
}

// deviceauth (namespace device): the approval page at /device. verify claims
// the code for the signed-in user and shows which client asked; approve or
// deny posts the decision.
// ds:def id=tsp-device-approve-9mx2qw6k owner=@khanakia stability=stable
export async function onDevicePage(typedCode: string, confirm: (clientId: string, scope: string) => Promise<boolean>): Promise<string> {
  const code = typedCode || (new URLSearchParams(location.search).get("user_code") ?? "");
  const looked = await auth.device.verify({ user_code: code });
  if (looked.error) return looked.error.code === "auth.signed_out" ? "Sign in first." : "This code is not valid.";
  const allow = await confirm(looked.data.client_id ?? "", looked.data.scope ?? "");
  const decided = allow ? await auth.device.approve({ userCode: code }) : await auth.device.deny({ userCode: code });
  return decided.error ? decided.error.message : allow ? "Done. Go back to your device." : "Denied.";
}

// The device itself, a CLI on Node: ask for a code, show it, poll at the
// interval the server gave until the user decides. The answer's access_token
// is the session token, sent as Authorization: Bearer from then on.
// ds:def id=tsp-device-poll-3qk7wn8m owner=@khanakia stability=stable
export async function deviceSignIn(show: (url: string, code: string) => void): Promise<string | null> {
  const cli = createAuthClient({ baseURL: "https://app.example.com/auth", tokenMode: "bearer", tokenStore: memoryTokenStore(), plugins: [device()] });
  const started = await cli.device.code({ client_id: "my-cli" });
  if (started.error) return null;
  show(started.data.verification_uri, started.data.user_code);
  let wait = started.data.interval;
  for (;;) {
    await new Promise((resolve) => setTimeout(resolve, wait * 1000));
    const { data, error } = await cli.device.token({
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      device_code: started.data.device_code,
      client_id: "my-cli",
    });
    if (data) return data.access_token;
    if (error.code === "device.polling_too_frequently") wait += 5;
    else if (error.code !== "device.authorization_pending") return null; // denied, expired, ...
  }
}
