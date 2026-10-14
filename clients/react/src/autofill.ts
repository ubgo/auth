// Passkey autofill (WebAuthn conditional mediation) as a hook: while the
// sign-in page is open, the browser lists the person's passkeys in the
// autofill of the identifier field, and picking one signs in without a
// dialog. The ceremony itself is runPasskeyAutofill in webauthn.ts; this file
// only ties its life to the component's.

import type { AuthError, PasskeySignInResult } from "@ubgo/auth-client";
import { useCallback, useEffect, useEffectEvent, useMemo, useRef, useState } from "react";
import { usePluginClient } from "./plugins.ts";
import { runPasskeyAutofill } from "./webauthn.ts";

/** Where passkey autofill is: not running, offering passkeys in the field's autofill, or signing in with the picked one. */
export type PasskeyAutofillStatus = "off" | "waiting" | "finishing";

/** What usePasskeyAutofill takes. */
export type PasskeyAutofillOptions = {
  /**
   * Run it. False stops it. Turn it off while the page has no input marked
   * `autocomplete="username webauthn"`, because the browser has nowhere to
   * offer the passkeys then. True by default.
   */
  readonly enabled?: boolean;
  /** A picked passkey signed its owner in. Refresh the session and move on, as after any sign-in. */
  readonly onSignedIn: (result: PasskeySignInResult) => void | Promise<void>;
  /**
   * The server refused a picked passkey (its ceremony expired, or it does not
   * know the passkey). Autofill starts again by itself, so another pick works.
   */
  readonly onError?: (error: AuthError) => void;
};

/** What usePasskeyAutofill returns. */
// ds:def id=passkeyautofill-5gb93jhu owner=@khanakia stability=stable
export type PasskeyAutofill = {
  readonly status: PasskeyAutofillStatus;
  /**
   * Aborts the pending request now, synchronously, and keeps it stopped.
   * Call it first thing when the person picks another way in (the passkey
   * button, a password submit, an OAuth button): a browser runs one
   * credential request at a time, so the passkey dialog fails while an
   * autofill request is pending.
   */
  readonly pause: () => void;
  /** Starts it again after pause, for when the other way in failed and the form is back. */
  readonly resume: () => void;
};

/**
 * Offers the person's passkeys in the autofill of the page's identifier
 * input (which must carry `autocomplete="username webauthn"`). Starts on
 * mount when the client has the passkey plugin and the browser supports
 * conditional mediation, and aborts on unmount, on pause, and when
 * `enabled` turns false. Starting it is an effect, not a render-time fetch:
 * it is a browser request that lives as long as the field does.
 */
export function usePasskeyAutofill({ enabled = true, onSignedIn, onError }: PasskeyAutofillOptions): PasskeyAutofill {
  const passkey = usePluginClient("passkey");
  const [status, setStatus] = useState<PasskeyAutofillStatus>("off");
  const [paused, setPaused] = useState(false);
  // Bumped to start a fresh attempt after a refused passkey or a resume.
  const [attempt, setAttempt] = useState(0);
  const controller = useRef<AbortController | null>(null);
  const signedIn = useEffectEvent(onSignedIn);
  const refused = useEffectEvent((error: AuthError) => onError?.(error));

  useEffect(() => {
    if (!enabled || paused || passkey === null) return;
    const ac = new AbortController();
    controller.current = ac;
    void runPasskeyAutofill(passkey, ac.signal, (stage) => {
      if (!ac.signal.aborted) setStatus(stage);
    }).then(async (outcome) => {
      if (ac.signal.aborted) return;
      setStatus("off");
      if (outcome.kind === "signed_in") {
        await signedIn(outcome.result);
      } else if (outcome.kind === "refused") {
        refused(outcome.error);
        setAttempt((n) => n + 1);
      }
      // "unavailable" and "no_credential" end quietly: autofill is an offer,
      // and the page's other methods are still there.
    });
    return () => {
      ac.abort();
      if (controller.current === ac) controller.current = null;
      setStatus("off");
    };
  }, [enabled, paused, passkey, attempt]);

  const pause = useCallback(() => {
    // Synchronous on purpose: the caller's next line is often another
    // credential request, which must not find this one still pending.
    controller.current?.abort();
    controller.current = null;
    setPaused(true);
  }, []);
  const resume = useCallback(() => {
    setPaused(false);
    setAttempt((n) => n + 1);
  }, []);
  return useMemo(() => ({ status, pause, resume }), [status, pause, resume]);
}
