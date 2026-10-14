// runPasskeyAutofill (src/webauthn.ts), case by case, against a fake browser
// and fake passkey calls. Node runs this file directly (type stripping, Node
// 22.18+): `node test/autofill.ts` from clients/react; task ui:check runs it.
// It prints one line per failed case and exits non-zero.

import type { AuthResult, PasskeyBeginResult, PasskeySignInResult } from "@ubgo/auth-client";
import { runPasskeyAutofill, type PasskeyAutofillCalls, type PasskeyAutofillOutcome } from "../src/webauthn.ts";

// Node's process, declared here so the package needs no @types/node.
declare const process: { exitCode?: number };

/** The begin answer every case starts from: discoverable request options, as the server sends them. */
const BEGIN: PasskeyBeginResult = { ceremony: "cer-1", options: { publicKey: { challenge: "AAAA", allowCredentials: [] } } };
const SIGNED_IN: PasskeySignInResult = { user: { id: "u1", name: "Ada", image: "" } };
const CREDENTIAL_JSON = { id: "cred-1", type: "public-key" };

/** What the fake browser does with a credential request. */
type GetBehaviour = "pick" | "nothing" | "wait-for-abort";

/** A stand-in for the browser's PublicKeyCredential, enough for webauthn.ts. */
class FakeCredential {
  toJSON(): Record<string, unknown> {
    return CREDENTIAL_JSON;
  }
}

/** Every call the fakes saw, for the assertions. */
type Seen = { begin: number; finish: Array<{ ceremony: string; credential: unknown }>; get: CredentialRequestOptions[] };

/** Installs a fake browser for one case and returns what it records. */
function fakeBrowser(conditional: boolean, behaviour: GetBehaviour, seen: Seen): void {
  const PublicKeyCredential = Object.assign(FakeCredential, {
    isConditionalMediationAvailable: async () => conditional,
    parseRequestOptionsFromJSON: (json: { challenge: string }) => ({ challenge: new TextEncoder().encode(json.challenge).buffer }),
  });
  const credentials = {
    get: (options: CredentialRequestOptions) => {
      seen.get.push(options);
      if (behaviour === "pick") return Promise.resolve(new FakeCredential());
      if (behaviour === "nothing") return Promise.reject(new DOMException("no passkey", "NotAllowedError"));
      return new Promise((_, reject) => {
        options.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
      });
    },
  };
  Object.defineProperty(globalThis, "window", { value: { PublicKeyCredential }, configurable: true });
  Object.defineProperty(globalThis, "PublicKeyCredential", { value: PublicKeyCredential, configurable: true });
  Object.defineProperty(globalThis, "navigator", { value: { credentials }, configurable: true });
}

/** Passkey calls that answer as given and record what they were asked. */
function fakeCalls(seen: Seen, begin: AuthResult<PasskeyBeginResult>, finish: AuthResult<PasskeySignInResult>, onBegin?: () => void): PasskeyAutofillCalls {
  return {
    loginBegin: async () => {
      seen.begin++;
      onBegin?.();
      return begin;
    },
    loginFinish: async (input) => {
      seen.finish.push(input);
      return finish;
    },
  };
}

const ok = <T,>(data: T): AuthResult<T> => ({ data, error: null });
const refusal = (code: "auth.rate_limited" | "passkey.ceremony_invalid"): AuthResult<never> => ({
  data: null,
  error: { code, rawCode: code, message: code, status: 400 },
});

let failures = 0;
function expect(name: string, cond: boolean, detail: unknown): void {
  if (!cond) {
    failures++;
    console.log(`FAIL ${name}: ${JSON.stringify(detail)}`);
  }
}

async function run(
  name: string,
  setup: { conditional?: boolean; get?: GetBehaviour; begin?: AuthResult<PasskeyBeginResult>; finish?: AuthResult<PasskeySignInResult>; abortAt?: "begin" | "waiting" },
  check: (outcome: PasskeyAutofillOutcome, seen: Seen, stages: string[]) => void,
): Promise<void> {
  const seen: Seen = { begin: 0, finish: [], get: [] };
  const stages: string[] = [];
  const ac = new AbortController();
  fakeBrowser(setup.conditional ?? true, setup.get ?? "pick", seen);
  const calls = fakeCalls(seen, setup.begin ?? ok(BEGIN), setup.finish ?? ok(SIGNED_IN), setup.abortAt === "begin" ? () => ac.abort() : undefined);
  const outcome = await runPasskeyAutofill(calls, ac.signal, (stage) => {
    stages.push(stage);
    // Abort once the browser is offering passkeys, as pause() or an unmount would.
    if (stage === "waiting" && setup.abortAt === "waiting") queueMicrotask(() => ac.abort());
  });
  try {
    check(outcome, seen, stages);
  } catch (err) {
    expect(name, false, String(err));
  }
}

await run("a picked passkey signs in through a conditional request", {}, (o, seen, stages) => {
  expect("signed in", o.kind === "signed_in", o);
  expect("one begin", seen.begin === 1, seen.begin);
  const get = seen.get[0];
  expect("conditional mediation", get?.mediation === "conditional", get?.mediation);
  expect("abortable", get?.signal instanceof AbortSignal, typeof get?.signal);
  expect("finish gets the ceremony and the credential", seen.finish[0]?.ceremony === "cer-1" && seen.finish[0]?.credential === CREDENTIAL_JSON, seen.finish);
  expect("stages in order", stages.join(",") === "waiting,finishing", stages);
});

await run("no conditional mediation: nothing is asked of the server", { conditional: false }, (o, seen) => {
  expect("unavailable", o.kind === "unavailable" && o.error === null, o);
  expect("no begin", seen.begin === 0, seen.begin);
  expect("no request", seen.get.length === 0, seen.get.length);
});

await run("a failed begin is unavailable, with its error, and asks the browser nothing", { begin: refusal("auth.rate_limited") }, (o, seen) => {
  expect("unavailable with the error", o.kind === "unavailable" && o.error?.code === "auth.rate_limited", o);
  expect("no request", seen.get.length === 0, seen.get.length);
});

await run("the browser ending without a passkey is no_credential, and finish is not called", { get: "nothing" }, (o, seen) => {
  expect("no credential", o.kind === "no_credential", o);
  expect("no finish", seen.finish.length === 0, seen.finish);
});

await run("a refused passkey is refused, with the server's error", { finish: refusal("passkey.ceremony_invalid") }, (o) => {
  expect("refused", o.kind === "refused" && o.error.code === "passkey.ceremony_invalid", o);
});

await run("aborting while the browser offers passkeys ends it without finishing", { get: "wait-for-abort", abortAt: "waiting" }, (o, seen, stages) => {
  expect("aborted", o.kind === "aborted", o);
  expect("no finish", seen.finish.length === 0, seen.finish);
  expect("never finishing", !stages.includes("finishing"), stages);
});

await run("aborting during begin never starts the browser request", { abortAt: "begin" }, (o, seen, stages) => {
  expect("aborted", o.kind === "aborted", o);
  expect("no request", seen.get.length === 0, seen.get.length);
  expect("never waiting", stages.length === 0, stages);
});

if (failures > 0) process.exitCode = 1;
else console.log("runPasskeyAutofill: every case passed");
