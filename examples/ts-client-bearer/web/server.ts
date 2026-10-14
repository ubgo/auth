// Server-side code using the typed client for a browser: a Node HTTP server
// (the shape of a server-rendering or backend-for-frontend app) that answers
// GET / with the signed-in user's name. The browser sent its session cookie
// to this server, not to the auth API, so the server forwards that Cookie
// header on a client made for this one request. A client is never shared
// between requests: its headers are one browser's credentials.
//
// Reads only. A mutation sent with a cookie must also carry an Origin the
// auth API trusts, which a server-side caller does not have, so server code
// that changes something calls the Go API in-process or uses bearer mode.
//
//   AUTH_URL=http://localhost:8111 PORT=8112 node ts-client-bearer/web/server.ts

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createAuthClient } from "../../../clients/ts/src/index.ts";

/** The auth API's origin: AUTH_URL, or the port the README starts it on. */
const AUTH_URL = process.env["AUTH_URL"] ?? "http://localhost:8111";
/** Where this server listens: PORT, or 0 (any free port; the first line printed names it). */
const PORT = Number(process.env["PORT"] ?? "0");
/** This machine only, for development. */
const HOST = "127.0.0.1";

/** The Cookie header the browser sent, as one string ("" when it sent none). */
function cookieOf(req: IncomingMessage): string {
  const raw = req.headers["cookie"];
  return Array.isArray(raw) ? raw.join("; ") : (raw ?? "");
}

/** The signed-in user's name for the browser that sent `cookie`, or null when it is signed out. */
// ds:def id=username-ztrn8raq
async function userName(cookie: string): Promise<string | null> {
  if (cookie === "") return null;
  const perRequest = createAuthClient({ baseURL: `${AUTH_URL}/auth`, headers: { Cookie: cookie } });
  const { data, error } = await perRequest.session();
  if (error) {
    // auth.signed_out is the normal answer for a stale cookie; anything else
    // (the API is down, a 500) is worth a log line, and still renders signed out.
    if (error.code !== "auth.signed_out") console.error(`session: ${error.code} ${error.message}`);
    return null;
  }
  return data.user.name;
}

/** GET /: the page for the browser that asked, by the cookie it sent. */
// ds:def id=handle-mesexndv
function handle(req: IncomingMessage, res: ServerResponse): void {
  void userName(cookieOf(req)).then((name) => {
    if (name === null) res.writeHead(401, { "Content-Type": "text/plain" }).end("signed out\n");
    else res.writeHead(200, { "Content-Type": "text/plain" }).end(`hello ${name}\n`);
  });
}

const server = createServer(handle);

server.listen(PORT, HOST, () => {
  const address = server.address();
  const port = typeof address === "object" && address !== null ? address.port : PORT;
  console.log(`listening on http://${HOST}:${port}`);
});
