// A command-line program signed in with the typed client in bearer mode. A
// CLI has no cookie jar, so it asks for the session token, keeps it in a
// file (a TokenStore), and sends it as Authorization: Bearer on every call.
// Each command is a new process, so `whoami` after `sign-in` proves the
// token survived the restart; `sign-out` ends the session on the server and
// deletes the file.
//
//   AUTH_URL=http://localhost:8111 node ts-client-bearer/web/cli.ts sign-up ada@example.com "correct horse battery staple" Ada
//   AUTH_URL=http://localhost:8111 node ts-client-bearer/web/cli.ts whoami
//   AUTH_URL=http://localhost:8111 node ts-client-bearer/web/cli.ts sign-out

import { readFile, rm, writeFile } from "node:fs/promises";
import { createAuthClient, email, password, type TokenStore } from "../../../clients/ts/src/index.ts";

/** The server's origin: AUTH_URL, or the port the README starts it on. */
const SERVER = process.env["AUTH_URL"] ?? "http://localhost:8111";
/** Where the token is kept between runs: AUTH_TOKEN_FILE, or a file in the current directory. */
const TOKEN_FILE = process.env["AUTH_TOKEN_FILE"] ?? ".auth-token";
/** Owner read and write only: the token signs in as the user, like a password. */
const TOKEN_FILE_MODE = 0o600;
/** How long one call may take before the CLI gives up, instead of hanging on a dead server. */
const CALL_TIMEOUT_MS = 10_000;
/** Names this program in the server's session list (the device a user sees and can sign out). */
const USER_AGENT = "ts-client-bearer-cli/1.0";

/** Exit codes: 0 done, 1 refused by the server (or signed out), 2 wrong command line. */
const EXIT_OK = 0;
const EXIT_REFUSED = 1;
const EXIT_USAGE = 2;

/**
 * A TokenStore over one file. get() runs before every request and set()
 * after every answer that issues or ends a token, so a missing file reads as
 * signed out and set(null) deletes it.
 */
// ds:def id=filetokenstore-az67vtyj
function fileTokenStore(path: string): TokenStore {
  return {
    get: async () => {
      try {
        return (await readFile(path, "utf8")).trim() || null;
      } catch (err) {
        if (isMissingFile(err)) return null; // no file yet: signed out
        throw err; // unreadable (permissions, a directory): say so, never pretend to be signed out
      }
    },
    set: async (token) => {
      if (token === null) await rm(path, { force: true });
      else await writeFile(path, token, { mode: TOKEN_FILE_MODE });
    },
  };
}

/** Whether a filesystem error is "no such file" (Node's ENOENT). */
function isMissingFile(err: unknown): boolean {
  return typeof err === "object" && err !== null && "code" in err && err.code === "ENOENT";
}

/**
 * The client's fetch option: every call names this program and gives up
 * after CALL_TIMEOUT_MS. A caller's own signal (CallOptions.signal) still
 * wins, because the client passes it in init.
 */
// ds:def id=clifetch-2wa5e3a3
const cliFetch: typeof fetch = (input, init) => {
  const headers = new Headers(init?.headers);
  headers.set("User-Agent", USER_AGENT);
  return fetch(input, { ...init, headers, signal: init?.signal ?? AbortSignal.timeout(CALL_TIMEOUT_MS) });
};

const auth = createAuthClient({
  baseURL: `${SERVER}/auth`,
  tokenMode: "bearer",
  tokenStore: fileTokenStore(TOKEN_FILE),
  fetch: cliFetch,
  plugins: [email(), password()],
});

/** The commands and their arguments, for the usage line. */
const USAGE = "usage: cli.ts sign-up <email> <password> <name> | sign-in <email> <password> | whoami | sign-out";

/** Runs one command and returns the process exit code; an unknown command or a missing argument prints the usage line. */
async function main(args: readonly string[]): Promise<number> {
  const [command, ...rest] = args;
  switch (command) {
    case "sign-up": {
      const [identifier, secret, name] = rest;
      if (identifier === undefined || secret === undefined || name === undefined) break;
      const { data, error } = await auth.password.signUp({ identifier, password: secret, name });
      if (error) return refused(error.code, error.message);
      console.log(`signed up and signed in as ${data.user.name}; token saved`);
      return EXIT_OK;
    }
    case "sign-in": {
      const [identifier, secret] = rest;
      if (identifier === undefined || secret === undefined) break;
      const { data, error } = await auth.password.signIn({ identifier, password: secret });
      if (error) return refused(error.code, error.message);
      console.log(`signed in as ${data.user.name}; token saved`);
      return EXIT_OK;
    }
    case "whoami": {
      const { data, error } = await auth.session();
      if (error) return refused(error.code, "not signed in");
      console.log(`${data.user.name} (token read from ${TOKEN_FILE})`);
      return EXIT_OK;
    }
    case "sign-out": {
      const { error } = await auth.signOut();
      if (error) return refused(error.code, error.message);
      console.log("signed out; token file removed");
      return EXIT_OK;
    }
  }
  console.error(USAGE);
  return EXIT_USAGE;
}

/** Prints a refusal with its typed code and returns the exit code for it. */
function refused(code: string, message: string): number {
  console.log(`${message} (${code})`);
  return EXIT_REFUSED;
}

process.exitCode = await main(process.argv.slice(2));
