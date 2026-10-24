// The browser half of a passkey ceremony (sign-in and registration): turn the server's JSON options
// into the binary ones navigator.credentials wants, and the credential back
// into JSON. Current browsers do both (parseRequestOptionsFromJSON, toJSON);
// the base64url fallback covers the ones that do not yet.

import type { AuthError, AuthResult, CallOptions, EmptyInput, PasskeyBeginResult, PasskeyFinishRequest, PasskeySignInResult } from "@ubgo/auth-client";

/** Why a passkey ceremony did not produce a credential. */
// ds:def id=passkeyfailure-xeqr573b owner=@khanakia stability=stable
export type PasskeyFailure =
  /** The browser has no WebAuthn. */
  | "unsupported"
  /** The person closed the prompt, or no passkey matched (WebAuthn does not tell the two apart, on purpose). */
  | "cancelled"
  /** The server's options were not WebAuthn request or creation options. */
  | "invalid_options"
  /** Registration only: this authenticator already holds a passkey for the account (InvalidStateError). */
  | "already_registered";

/** A ceremony's outcome. */
export type PasskeyCeremony =
  | { readonly credential: Record<string, unknown>; readonly failure: null }
  | { readonly credential: null; readonly failure: PasskeyFailure };

/** Whether this browser can run a passkey ceremony at all. */
export function supportsPasskeys(): boolean {
  return typeof window !== "undefined" && typeof window.PublicKeyCredential === "function" && navigator.credentials !== undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function fromBase64URL(value: string): ArrayBuffer {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function toBase64URL(buffer: ArrayBuffer): string {
  let binary = "";
  for (const byte of new Uint8Array(buffer)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Whether a value has the one member WebAuthn JSON request options require.
 * parseRequestOptionsFromJSON validates the rest and throws on anything
 * else, which the caller turns into "invalid_options".
 */
function isRequestOptionsJSON(value: Record<string, unknown>): value is Record<string, unknown> & PublicKeyCredentialRequestOptionsJSON {
  return typeof value["challenge"] === "string";
}

/**
 * The request options inside the server's begin answer. The server sends
 * the WebAuthn JSON form under `publicKey`, with binary fields as base64url.
 */
function requestOptions(options: unknown): PublicKeyCredentialRequestOptions | null {
  if (!isRecord(options) || !isRecord(options["publicKey"])) return null;
  const json = options["publicKey"];
  if (typeof json["challenge"] !== "string") return null;
  if (typeof PublicKeyCredential.parseRequestOptionsFromJSON === "function" && isRequestOptionsJSON(json)) {
    return PublicKeyCredential.parseRequestOptionsFromJSON(json);
  }
  const allow = Array.isArray(json["allowCredentials"]) ? json["allowCredentials"] : [];
  const out: PublicKeyCredentialRequestOptions = {
    challenge: fromBase64URL(json["challenge"]),
    allowCredentials: allow.filter(isRecord).flatMap((c) =>
      typeof c["id"] === "string" ? [{ type: "public-key" as const, id: fromBase64URL(c["id"]) }] : [],
    ),
  };
  if (typeof json["rpId"] === "string") out.rpId = json["rpId"];
  if (typeof json["timeout"] === "number") out.timeout = json["timeout"];
  if (json["userVerification"] === "required" || json["userVerification"] === "preferred" || json["userVerification"] === "discouraged") {
    out.userVerification = json["userVerification"];
  }
  return out;
}

/** The credential as the JSON the server's finish route reads. */
function credentialJSON(credential: PublicKeyCredential): Record<string, unknown> | null {
  if (typeof credential.toJSON === "function") {
    const json: unknown = credential.toJSON();
    if (isRecord(json)) return json;
  }
  const response = credential.response;
  if (!(response instanceof AuthenticatorAssertionResponse)) return null;
  return {
    id: credential.id,
    rawId: toBase64URL(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      clientDataJSON: toBase64URL(response.clientDataJSON),
      authenticatorData: toBase64URL(response.authenticatorData),
      signature: toBase64URL(response.signature),
      userHandle: response.userHandle === null ? null : toBase64URL(response.userHandle),
    },
  };
}

/**
 * Whether this browser can offer passkeys in an input's autofill list
 * (WebAuthn conditional mediation). Resolves false rather than throwing, so
 * a page can call it on mount without a try.
 */
export async function supportsPasskeyAutofill(): Promise<boolean> {
  if (!supportsPasskeys() || typeof PublicKeyCredential.isConditionalMediationAvailable !== "function") return false;
  try {
    return await PublicKeyCredential.isConditionalMediationAvailable();
  } catch {
    return false;
  }
}

/**
 * Asks the browser for a passkey with the server's begin options. Never
 * throws: a cancelled prompt is an expected outcome, not an exception.
 * `mediation: "conditional"` asks without a dialog: the browser lists the
 * passkeys in the autofill of an input marked `autocomplete="username
 * webauthn"` and the promise settles only when one is picked or `signal`
 * aborts it, so a conditional request always needs a signal.
 */
export async function getPasskeyCredential(
  options: unknown,
  signal?: AbortSignal,
  mediation?: CredentialMediationRequirement,
): Promise<PasskeyCeremony> {
  if (!supportsPasskeys()) return { credential: null, failure: "unsupported" };
  let publicKey: PublicKeyCredentialRequestOptions | null;
  try {
    publicKey = requestOptions(options);
  } catch {
    publicKey = null;
  }
  if (publicKey === null) return { credential: null, failure: "invalid_options" };
  try {
    const request: CredentialRequestOptions = { publicKey };
    if (signal !== undefined) request.signal = signal;
    if (mediation !== undefined) request.mediation = mediation;
    const credential = await navigator.credentials.get(request);
    if (!(credential instanceof PublicKeyCredential)) return { credential: null, failure: "cancelled" };
    const json = credentialJSON(credential);
    return json === null ? { credential: null, failure: "cancelled" } : { credential: json, failure: null };
  } catch {
    // NotAllowedError (closed, timed out, nothing matched) and AbortError
    // both mean no credential; WebAuthn hides which on purpose.
    return { credential: null, failure: "cancelled" };
  }
}

/** Whether a value has the members WebAuthn JSON creation options require. */
function isCreationOptionsJSON(value: Record<string, unknown>): value is Record<string, unknown> & PublicKeyCredentialCreationOptionsJSON {
  return typeof value["challenge"] === "string" && isRecord(value["user"]) && isRecord(value["rp"]) && Array.isArray(value["pubKeyCredParams"]);
}

/** The creation options inside the server's register-begin answer (`{ publicKey: … }`, binary fields base64url). */
function creationOptions(options: unknown): PublicKeyCredentialCreationOptions | null {
  if (!isRecord(options) || !isRecord(options["publicKey"])) return null;
  const json = options["publicKey"];
  if (!isCreationOptionsJSON(json)) return null;
  if (typeof PublicKeyCredential.parseCreationOptionsFromJSON === "function") {
    return PublicKeyCredential.parseCreationOptionsFromJSON(json);
  }
  const exclude = Array.isArray(json["excludeCredentials"]) ? json["excludeCredentials"] : [];
  const out: PublicKeyCredentialCreationOptions = {
    challenge: fromBase64URL(json.challenge),
    rp: { name: json.rp.name, ...(json.rp.id === undefined ? {} : { id: json.rp.id }) },
    user: { id: fromBase64URL(json.user.id), name: json.user.name, displayName: json.user.displayName },
    pubKeyCredParams: json.pubKeyCredParams,
    excludeCredentials: exclude.filter(isRecord).flatMap((c) =>
      typeof c["id"] === "string" ? [{ type: "public-key" as const, id: fromBase64URL(c["id"]) }] : [],
    ),
  };
  if (json.timeout !== undefined) out.timeout = json.timeout;
  const conveyance = json.attestation;
  if (conveyance === "none" || conveyance === "indirect" || conveyance === "direct" || conveyance === "enterprise") out.attestation = conveyance;
  if (json.authenticatorSelection !== undefined) out.authenticatorSelection = json.authenticatorSelection;
  return out;
}

/** A new credential as the JSON the server's register-finish route reads. */
function attestationJSON(credential: PublicKeyCredential): Record<string, unknown> | null {
  if (typeof credential.toJSON === "function") {
    const json: unknown = credential.toJSON();
    if (isRecord(json)) return json;
  }
  const response = credential.response;
  if (!(response instanceof AuthenticatorAttestationResponse)) return null;
  return {
    id: credential.id,
    rawId: toBase64URL(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      clientDataJSON: toBase64URL(response.clientDataJSON),
      attestationObject: toBase64URL(response.attestationObject),
      transports: typeof response.getTransports === "function" ? response.getTransports() : [],
    },
  };
}

/**
 * Asks the browser to create a passkey with the server's register-begin (or
 * sign-up-begin) options. Never throws, like getPasskeyCredential; an
 * authenticator that already holds a passkey for the account answers
 * "already_registered".
 */
export async function createPasskeyCredential(options: unknown, signal?: AbortSignal): Promise<PasskeyCeremony> {
  if (!supportsPasskeys()) return { credential: null, failure: "unsupported" };
  let publicKey: PublicKeyCredentialCreationOptions | null;
  try {
    publicKey = creationOptions(options);
  } catch {
    publicKey = null;
  }
  if (publicKey === null) return { credential: null, failure: "invalid_options" };
  try {
    const credential = await navigator.credentials.create(signal === undefined ? { publicKey } : { publicKey, signal });
    if (!(credential instanceof PublicKeyCredential)) return { credential: null, failure: "cancelled" };
    const json = attestationJSON(credential);
    return json === null ? { credential: null, failure: "cancelled" } : { credential: json, failure: null };
  } catch (err) {
    if (err instanceof DOMException && err.name === "InvalidStateError") return { credential: null, failure: "already_registered" };
    return { credential: null, failure: "cancelled" };
  }
}

/** The two passkey calls autofill makes, as the passkey plugin's namespace has them. */
export type PasskeyAutofillCalls = {
  readonly loginBegin: (input?: EmptyInput, options?: CallOptions) => Promise<AuthResult<PasskeyBeginResult>>;
  readonly loginFinish: (input: PasskeyFinishRequest, options?: CallOptions) => Promise<AuthResult<PasskeySignInResult>>;
};

/** How one autofill attempt ended. */
// ds:def id=passkeyautofilloutcome-xa546psy owner=@khanakia stability=stable
export type PasskeyAutofillOutcome =
  /** A passkey was picked and the server signed its owner in (maybe pending a second factor). */
  | { readonly kind: "signed_in"; readonly result: PasskeySignInResult }
  /** A passkey was picked and the server refused it: an expired ceremony, a passkey it does not know. */
  | { readonly kind: "refused"; readonly error: AuthError }
  /** Autofill was not offered: no conditional mediation in this browser, or login-begin failed. */
  | { readonly kind: "unavailable"; readonly error: AuthError | null }
  /** The browser ended the request without a credential (no passkey for this site, or it gave up). */
  | { readonly kind: "no_credential" }
  /** `signal` aborted it: the person chose another method, or the page went away. */
  | { readonly kind: "aborted" };

/** The stages runPasskeyAutofill reports while it runs. */
export type PasskeyAutofillStage = "waiting" | "finishing";

/**
 * One passkey-autofill attempt, framework-free: login-begin, a conditional
 * credential request (the browser offers passkeys in the autofill of the
 * page's `autocomplete="username webauthn"` input), then login-finish with
 * the picked passkey. It settles when a passkey is picked or `signal` aborts
 * it. Abort it before any other WebAuthn call on the page: a browser runs
 * one credential request at a time, so a pending conditional request makes
 * the "Sign in with a passkey" dialog fail. `onStage` hears "waiting" once
 * the browser is offering passkeys and "finishing" once one was picked.
 * Never throws.
 */
export async function runPasskeyAutofill(
  calls: PasskeyAutofillCalls,
  signal: AbortSignal,
  onStage?: (stage: PasskeyAutofillStage) => void,
): Promise<PasskeyAutofillOutcome> {
  if (!(await supportsPasskeyAutofill())) return { kind: "unavailable", error: null };
  if (signal.aborted) return { kind: "aborted" };
  const begin = await calls.loginBegin({}, { signal });
  if (signal.aborted) return { kind: "aborted" };
  if (begin.error !== null) return { kind: "unavailable", error: begin.error };
  onStage?.("waiting");
  const ceremony = await getPasskeyCredential(begin.data.options, signal, "conditional");
  if (signal.aborted) return { kind: "aborted" };
  if (ceremony.credential === null) return { kind: "no_credential" };
  onStage?.("finishing");
  // Not aborted from here on: the person picked a passkey, and abandoning
  // the finish would leave them on the sign-in page for no reason.
  const done = await calls.loginFinish({ ceremony: begin.data.ceremony, credential: ceremony.credential });
  if (done.error !== null) return { kind: "refused", error: done.error };
  return { kind: "signed_in", result: done.data };
}
