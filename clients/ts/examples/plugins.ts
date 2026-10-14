// One typed call per plugin namespace of the prebuilt client, plus the core
// on the root: what each factory adds, with an input the compiler checks and
// an answer it knows the shape of. A real app lists only the plugins its Go
// server wires; this client lists every one so the tour fits one file.
// Type-checked by task ts:check; the guides link each call from the table in
// docs/client/plugins.md.

import {
  admin,
  anonymous,
  apikey,
  audit,
  createAuthClient,
  device,
  email,
  emailchallenge,
  handoff,
  invite,
  jwt,
  ldap,
  magiclink,
  metadata,
  oauth,
  oauthprovider,
  organization,
  passkey,
  password,
  phone,
  pow,
  referral,
  siwe,
  terms,
  twofactor,
  username,
} from "../src/index.ts";

const auth = createAuthClient({
  baseURL: "/auth",
  plugins: [
    admin(),
    anonymous(),
    apikey(),
    audit(),
    device(),
    email(),
    emailchallenge(),
    handoff(),
    invite(),
    jwt(),
    ldap(),
    magiclink(),
    metadata(),
    oauth(),
    oauthprovider(),
    organization(),
    passkey(),
    password(),
    phone(),
    pow(),
    referral(),
    siwe(),
    terms(),
    twofactor(),
    username(),
  ],
});

// Core, on the root of every client: the caller's sessions on every device.
// ds:def id=plugins-core-3wq8kn5m owner=@khanakia stability=stable
export async function sessionCount(): Promise<number> {
  const { data } = await auth.sessions();
  return data?.sessions?.length ?? 0;
}

// admin: page through users. Query inputs travel in the query string, so the
// paging fields are strings.
// ds:def id=plugins-admin-7kx2mq9w owner=@khanakia stability=stable
export async function firstUsers(): Promise<number> {
  const { data } = await auth.admin.users({ limit: "20" });
  return data?.total ?? 0;
}

// anonymous: a guest account with no identifier, upgraded later by a sign-up.
// ds:def id=plugins-anonymous-5nw3qk8x owner=@khanakia stability=stable
export async function continueAsGuest(): Promise<string | null> {
  const { data } = await auth.anonymous.signIn();
  return data?.user.id ?? null;
}

// apikey: the caller's keys (the secret is shown once, by apikey.create).
// ds:def id=plugins-apikey-8qm4wx2n owner=@khanakia stability=stable
export async function apiKeyCount(): Promise<number> {
  const { data } = await auth.apikey.list();
  return data?.total ?? 0;
}

// audit: the caller's own security events, newest first.
// ds:def id=plugins-audit-2kv9nw4q owner=@khanakia stability=stable
export async function recentEvents(): Promise<number> {
  const { data } = await auth.audit.myEvents({ limit: "10" });
  return data?.events?.length ?? 0;
}

// device (plugin/deviceauth): a CLI or TV asks for a code the user types on
// another device. The fields are RFC 8628's snake_case names.
// ds:def id=plugins-device-6wq3mk8v owner=@khanakia stability=stable
export async function startDeviceSignIn(): Promise<string | null> {
  const { data } = await auth.device.code({ client_id: "my-cli" });
  return data ? `${data.verification_uri}  code ${data.user_code}` : null;
}

// email: the caller's addresses, primary and verified flags included.
// ds:def id=plugins-email-4mx8qw2k owner=@khanakia stability=stable
export async function addressCount(): Promise<number> {
  const { data } = await auth.email.list();
  return data?.addresses?.length ?? 0;
}

// emailchallenge: sign in by approving a mail, polled from the page that asked.
// ds:def id=plugins-emailchallenge-9vk2wn5q owner=@khanakia stability=stable
export async function startEmailChallenge(address: string): Promise<string | null> {
  const { data } = await auth.emailchallenge.start({ identifier: address });
  return data?.pollToken ?? null;
}

// handoff: a one-time token that carries this session to another app or device.
// ds:def id=plugins-handoff-3nq7kx4w owner=@khanakia stability=stable
export async function handoffToken(): Promise<string | null> {
  const { data } = await auth.handoff.generate();
  return data?.token ?? null;
}

// invite: an invitation link for a new user (sign-up by invitation).
// ds:def id=plugins-invite-7wk4mq2x owner=@khanakia stability=stable
export async function inviteLink(address: string): Promise<string | null> {
  const { data } = await auth.invite.create({ email: address, role: "member" });
  return data?.url ?? null;
}

// jwt: a short-lived JWT for the signed-in user, for a service that checks it
// against jwt.jwks without calling this server.
// ds:def id=plugins-jwt-5qx2nw8k owner=@khanakia stability=stable
export async function serviceToken(): Promise<string | null> {
  const { data } = await auth.jwt.token();
  return data?.token ?? null;
}

// ldap: sign in against the company directory.
// ds:def id=plugins-ldap-8km3wq5n owner=@khanakia stability=stable
export async function directorySignIn(user: string, secret: string): Promise<boolean> {
  const { error } = await auth.ldap.signIn({ username: user, password: secret });
  return error === null;
}

// magiclink: mail a sign-in link (the page it opens is in flows.ts).
// ds:def id=plugins-magiclink-2wn8kq4x owner=@khanakia stability=stable
export async function mailSignInLink(address: string): Promise<boolean> {
  const { error } = await auth.magiclink.send({ identifier: address });
  return error === null;
}

// metadata: the signed-in user's public and unsafe documents (private never
// reaches a client).
// ds:def id=plugins-metadata-7qn3wk5x owner=@khanakia stability=stable
export async function myMetadata(): Promise<unknown> {
  const { data } = await auth.metadata.get();
  return data?.public ?? null;
}

// oauth: the configured providers, to draw one button each. Signing in is a
// page navigation to the start route, never a call (flows.ts continueWith).
// ds:def id=plugins-oauth-6kq9wm3v owner=@khanakia stability=stable
export async function providerCount(): Promise<number> {
  const { data } = await auth.oauth.providers();
  return data?.providers?.length ?? 0;
}

// oauthprovider: the OAuth clients this user registered against your app.
// ds:def id=plugins-oauthprovider-4xw7nq2m owner=@khanakia stability=stable
export async function registeredClients(): Promise<number> {
  const { data } = await auth.oauthprovider.listClients();
  return data?.clients?.length ?? 0;
}

// organization: the caller's organizations with their role in each.
// ds:def id=plugins-organization-9mq5kw3x owner=@khanakia stability=stable
export async function myOrganizations(): Promise<string[]> {
  const { data } = await auth.organization.list();
  return (data?.orgs ?? []).map((org) => `${org.name} (${org.role})`);
}

// passkey: step one of a passkey sign-in. options is the WebAuthn JSON to hand
// to navigator.credentials.get; its answer goes to passkey.loginFinish.
// ds:def id=plugins-passkey-3kw8qn6x owner=@khanakia stability=stable
export async function passkeyOptions(): Promise<unknown> {
  const { data } = await auth.passkey.loginBegin();
  return data?.options ?? null;
}

// password: sign in (the quickstart page covers it in full).
// ds:def id=plugins-password-7nx4wk2q owner=@khanakia stability=stable
export async function passwordSignIn(identifier: string, secret: string): Promise<boolean> {
  const { error } = await auth.password.signIn({ identifier, password: secret });
  return error === null;
}

// phone: text a sign-in code; phone.signIn takes it back.
// ds:def id=plugins-phone-5wm2qx8k owner=@khanakia stability=stable
export async function textSignInCode(number: string): Promise<boolean> {
  const { error } = await auth.phone.sendCode({ phone: number });
  return error === null;
}

// pow: a proof-of-work puzzle; the solved proof goes back in the X-Pow-Proof
// header of the call the server challenged (per-call headers, see options.ts).
// ds:def id=plugins-pow-8qk3nw5x owner=@khanakia stability=stable
export async function powPuzzle(): Promise<string | null> {
  const { data } = await auth.pow.challenge();
  return data ? `${data.algorithm} difficulty ${data.difficulty}` : null;
}

// referral: the caller's referral code and its stats.
// ds:def id=plugins-referral-2mx9kw4q owner=@khanakia stability=stable
export async function referralCode(): Promise<string | null> {
  const { data } = await auth.referral.dashboard();
  return data?.code ?? null;
}

// siwe: a nonce for a Sign-In with Ethereum message (ERC-4361); the signed
// message goes to siwe.verify.
// ds:def id=plugins-siwe-6vq2wm8k owner=@khanakia stability=stable
export async function siweNonce(wallet: string): Promise<string | null> {
  const { data } = await auth.siwe.nonce({ walletAddress: wallet, chainId: 1 });
  return data?.nonce ?? null;
}

// terms: record that the caller accepted a version of the terms.
// ds:def id=plugins-terms-4nk8qx2w owner=@khanakia stability=stable
export async function acceptTerms(version: string): Promise<boolean> {
  const { data } = await auth.terms.accept({ version });
  return data?.ok ?? false;
}

// twofactor: whether the caller has a second factor on, and which methods.
// ds:def id=plugins-twofactor-9wk5mq3n owner=@khanakia stability=stable
export async function secondFactorMethods(): Promise<string[]> {
  const { data } = await auth.twofactor.status();
  return data?.enabled ? (data.methods ?? []) : [];
}

// username: check a name before a sign-up form submits it.
// ds:def id=plugins-username-3xq7kn5w owner=@khanakia stability=stable
export async function usernameFree(name: string): Promise<boolean> {
  const { data } = await auth.username.available({ username: name });
  return data?.available ?? false;
}
