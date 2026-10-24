// Runs the frontend code in src/ against a running ts-client-custom server
// from Node (22.18 or later, or 23.6 on the 23 line, runs TypeScript as is), in bearer mode because
// Node keeps no cookies. It prints what each call answered.
//
//	PORT=8096 go run ./ts-client-custom      # in one terminal, from examples/
//	AUTH_URL=http://localhost:8096/auth node ts-client-custom/web/demo.ts

import { createAppClient } from "./src/app-auth.ts";
import { currentNickname, saveNickname } from "./src/nickname-form.ts";

// Node's process, declared here so the example needs no @types/node.
declare const process: { env: Record<string, string | undefined> };

const baseURL = process.env["AUTH_URL"] ?? "http://localhost:8081/auth";
const client = createAppClient({ baseURL, tokenMode: "bearer" });

const signUp = await client.password.signUp({ identifier: `demo-${Date.now()}@example.com`, password: "correct horse battery staple", name: "Demo" });
console.log("password.signUp:", signUp.error ? signUp.error.code : `user ${signUp.data.user.id}`);
console.log("nickname before:", await currentNickname(client));
console.log("saveNickname(\"Ada\"):", await saveNickname(client, "Ada"));
console.log("saveNickname(40 letters):", await saveNickname(client, "x".repeat(40)));
console.log("nickname after:", await currentNickname(client));
await client.signOut();
console.log("nickname signed out:", await currentNickname(client));
