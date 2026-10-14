// Plugins a page reaches through a request header on someone else's call,
// sent with the per-call headers option: a captcha token, a proof of work,
// the terms version the form showed, a referral code. And invitations, whose
// page posts the token and whose sign-up may carry it. Type-checked by task
// ts:check; the "From TypeScript" sections of docs/plugins/captcha.md,
// pow.md, terms.md, referral.md and invite.md show these blocks.

import { createAuthClient, invite, password, pow, referral, terms } from "../src/index.ts";

const auth = createAuthClient({ baseURL: "/auth", plugins: [password(), pow(), terms(), referral(), invite()] });

// captcha: the widget's token goes in X-Captcha-Response on the protected
// call. Missing is captcha.missing, refused is captcha.failed: get a new
// token from the widget and try again.
// ds:def id=tsp-captcha-header-7kx2wq9m owner=@khanakia stability=stable
export async function signUpWithCaptcha(address: string, secret: string, widgetToken: string): Promise<string> {
  const { error } = await auth.password.signUp(
    { identifier: address, password: secret },
    { headers: { "X-Captcha-Response": widgetToken } },
  );
  if (!error) return "signed-up";
  return error.code === "captcha.failed" || error.code === "captcha.missing" ? "Solve the captcha again." : error.message;
}

/** The decimal nonce whose SHA-256 of "<challenge>:<nonce>" starts with `difficulty` zero bits. */
async function solve(challenge: string, difficulty: number): Promise<number> {
  for (let nonce = 0; ; nonce++) {
    const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${challenge}:${nonce}`)));
    let zeros = 0;
    for (const byte of hash) {
      if (byte === 0) {
        zeros += 8;
        continue;
      }
      zeros += Math.clz32(byte) - 24;
      break;
    }
    if (zeros >= difficulty) return nonce;
  }
}

// pow: a call answered auth.challenge_required is sent again with a solved
// puzzle in X-Pow-Proof ("<challenge>.<nonce>"). A proof works once.
// ds:def id=tsp-pow-retry-4mw8kq3x owner=@khanakia stability=stable
export async function signInWithWork(identifier: string, secret: string): Promise<boolean> {
  const first = await auth.password.signIn({ identifier, password: secret });
  if (first.error?.code !== "auth.challenge_required") return first.error === null;
  const puzzle = await auth.pow.challenge();
  if (puzzle.error) return false;
  const nonce = await solve(puzzle.data.challenge, puzzle.data.difficulty);
  const proof = `${puzzle.data.challenge}.${nonce}`;
  const second = await auth.password.signIn({ identifier, password: secret }, { headers: { "X-Pow-Proof": proof } });
  return second.error === null;
}

// terms: the sign-up form sends the version it showed in Terms-Version, and
// the acceptance is recorded with the account. A stale version is not
// recorded; the user accepts the current one later with terms.accept.
// ds:def id=tsp-terms-signup-9wn3mk2q owner=@khanakia stability=stable
export async function signUpAcceptingTerms(address: string, secret: string, shownVersion: string): Promise<boolean> {
  const { error } = await auth.password.signUp(
    { identifier: address, password: secret },
    { headers: { "Terms-Version": shownVersion } },
  );
  return error === null;
}

// An existing user accepts the version in force. terms.stale_version means
// the terms changed while the page was open: show the new ones first.
// ds:def id=tsp-terms-accept-3kq7xw5n owner=@khanakia stability=stable
export async function acceptCurrentTerms(version: string): Promise<"accepted" | "show-new-terms" | string> {
  const { error } = await auth.terms.accept({ version });
  if (!error) return "accepted";
  return error.code === "terms.stale_version" ? "show-new-terms" : error.message;
}

// referral: a sign-up carries the referrer's code in Referral-Code. Before an
// OAuth sign-up (whose callback carries no header) the landing page calls
// remember, which keeps the code in a cookie for an hour and refuses a bad
// one early (referral.invalid_code).
// ds:def id=tsp-referral-signup-6nx2qk8w owner=@khanakia stability=stable
export async function signUpReferred(address: string, secret: string, code: string): Promise<boolean> {
  const { error } = await auth.password.signUp(
    { identifier: address, password: secret },
    { headers: { "Referral-Code": code } },
  );
  return error === null;
}

export async function rememberReferralBeforeOAuth(code: string): Promise<boolean> {
  const { error } = await auth.referral.remember({ code });
  return error === null;
}

// The referrer's page: their code to share, and who joined with it.
// ds:def id=tsp-referral-dashboard-2wq9kn4x owner=@khanakia stability=stable
export async function referralSummary(): Promise<string> {
  const board = await auth.referral.dashboard();
  if (board.error) return board.error.message;
  const list = await auth.referral.list({ limit: 20 });
  const names = (list.data?.referrals ?? []).map((r) => `${r.referredUser.name} (${r.progress.completed}/${r.progress.total})`);
  return `Code ${board.data.code}: ${board.data.stats.completed} of ${board.data.stats.total} completed. ${names.join(", ")}`;
}

// invite: a signed-in user makes a link to share (or, with email, a private
// invite that is mailed and never answered).
// ds:def id=tsp-invite-create-8mk3wq7x owner=@khanakia stability=stable
export async function shareableInvite(): Promise<string | null> {
  const { data, error } = await auth.invite.create({ maxUses: 5, expiresIn: 7 * 24 * 3600 });
  if (error) return null; // invite.forbidden when the server's CanCreate refuses
  return data.url ?? null;
}

// The page the invite link opens: show it, then activate. Signed in, the
// invite is used now; signed out, it waits in a cookie for ten minutes and
// the next sign-up or sign-in in this browser spends it.
// ds:def id=tsp-invite-page-5kw2xn9q owner=@khanakia stability=stable
export async function onInvitePage(): Promise<"accepted" | "sign-in-or-sign-up" | "invalid"> {
  const token = new URLSearchParams(location.search).get("token") ?? "";
  const shown = await auth.invite.get({ token });
  if (shown.error || shown.data.status !== "pending") return "invalid";
  const { data, error } = await auth.invite.activate({ token });
  if (error) return "invalid";
  return data.action === "accepted" ? "accepted" : "sign-in-or-sign-up";
}
