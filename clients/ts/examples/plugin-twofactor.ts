// The twofactor plugin from a browser: turn on an authenticator app, read
// the status, make new recovery codes, forget remembered devices and turn it
// off. The sign-in step (a pending session and twofactor.verify) is in
// flows.ts. Type-checked by task ts:check; the "From TypeScript" section of
// docs/plugins/twofactor.md shows these blocks.

import { createAuthClient, password, twofactor } from "../src/index.ts";

const auth = createAuthClient({ baseURL: "/auth", plugins: [password(), twofactor()] });

// Enrolment is two calls. enroll answers the otpauth:// URL to draw as a QR
// code and the secret to type by hand; the factor is off until confirm
// accepts a first code, and confirm answers the recovery codes, once.
// ds:def id=tsp-twofactor-enrol-7kq2wm5x owner=@khanakia stability=stable
export async function turnOnAuthenticatorApp(
  showQRCode: (otpauthURL: string, secret: string) => void,
  askForCode: () => Promise<string>,
): Promise<string[] | null> {
  const started = await auth.twofactor.enroll({ method: "totp" });
  if (started.error) return null; // auth.fresh_session_required, twofactor.already_enabled, ...
  showQRCode(started.data.url ?? "", started.data.secret ?? "");
  const confirmed = await auth.twofactor.confirm({ code: await askForCode() });
  if (confirmed.error) return null; // twofactor.code_invalid: ask again; the enrolment stays open
  return confirmed.data.codes ?? [];
}

// The settings page: is it on, and which methods may the user pick.
// ds:def id=tsp-twofactor-status-3wn8kx4q owner=@khanakia stability=stable
export async function secondFactorSummary(): Promise<string> {
  const { data, error } = await auth.twofactor.status();
  if (error) return error.message;
  return data.enabled ? `On (${data.method ?? "totp"})` : `Off; available: ${(data.methods ?? []).join(", ")}`;
}

// A new set of recovery codes replaces the old set; the call needs a current
// code from the app (or an unused recovery code).
// ds:def id=tsp-twofactor-recovery-9mx4qw2k owner=@khanakia stability=stable
export async function newRecoveryCodes(code: string): Promise<string[]> {
  const { data } = await auth.twofactor.recoveryCodes({ code });
  return data?.codes ?? [];
}

// Remembered devices (twofactor.TrustDevices): list them, forget one or all.
// ds:def id=tsp-twofactor-devices-5kw2nq8v owner=@khanakia stability=stable
export async function forgetOtherDevices(): Promise<number> {
  const { data } = await auth.twofactor.devices();
  const others = (data?.devices ?? []).filter((d) => !d.current);
  for (const device of others) await auth.twofactor.forgetDevice({ id: device.id });
  return others.length;
}

// Turn it off, with a current code. A FreshSignIn operation.
// ds:def id=tsp-twofactor-disable-2qx7mk9w owner=@khanakia stability=stable
export async function turnOff(code: string): Promise<boolean> {
  const { error } = await auth.twofactor.disable({ code });
  return error === null;
}
