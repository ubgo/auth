// The OIDC tests' harness: named async tests run in order, one line each,
// and a non-zero exit code when any fails. No test framework, so the
// package keeps zero dependencies, dev ones included; Node runs the .ts
// files directly (type stripping, Node 22.18+).

/** Node's process, declared here so the package needs no @types/node. */
declare const process: { exitCode?: number };

/** A failed check: thrown by the assertions, caught by `run`. */
export class CheckFailed extends Error {
  override readonly name = "CheckFailed";
}

interface Case {
  readonly name: string;
  readonly fn: () => Promise<void> | void;
}

const cases: Case[] = [];

/** Registers a test; `run` executes every registered test in order. */
export function test(name: string, fn: () => Promise<void> | void): void {
  cases.push({ name, fn });
}

/** Fails the current test unless `ok`. */
export function check(ok: boolean, what: string): asserts ok {
  if (!ok) throw new CheckFailed(what);
}

/** Fails unless `got` is strictly `want`. */
export function equal<T>(got: T, want: T, what: string): void {
  if (got !== want) throw new CheckFailed(`${what}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
}

/** Fails unless `fn` throws (or rejects) with an error whose `code` is `code`; returns the error. */
export async function rejects(fn: () => unknown, code: string, what: string): Promise<Error> {
  try {
    await fn();
  } catch (err) {
    const got = err instanceof Error && "code" in err ? err.code : undefined;
    if (got !== code) throw new CheckFailed(`${what}: threw code ${JSON.stringify(got)} (${err instanceof Error ? err.message : String(err)}), want ${code}`);
    return err instanceof Error ? err : new Error(String(err));
  }
  throw new CheckFailed(`${what}: did not throw`);
}

/** Runs every registered test and reports; sets a failing exit code when any failed. */
export async function run(): Promise<void> {
  let failed = 0;
  for (const c of cases) {
    try {
      await c.fn();
      console.log(`  ok   ${c.name}`);
    } catch (err) {
      failed++;
      console.log(`  FAIL ${c.name}: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}`);
    }
  }
  console.log(`${cases.length - failed} passed, ${failed} failed, ${cases.length} total`);
  if (failed > 0) process.exitCode = 1;
}
