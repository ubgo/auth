// The small public values: claim readers, Secret redaction, the error
// cause chain, logoutTargetMatches' empty-string rule.

import { OidcClientError, OidcErrorCode, claimBool, claimString, claimStrings, isOidcError, logoutTargetMatches, secret } from "../../src/oidc/index.ts";
import { check, equal, test } from "./harness.ts";
import { Jar, gate, signIn, world } from "./helpers.ts";

test("claim readers: typed reads, a single string is a list of one, mixed lists are undefined", () => {
  const c = { s: "x", b: true, bs: "true", l: ["a", "b"], one: "g", mixed: ["a", 1], n: 3 };
  equal(claimString(c, "s"), "x", "string");
  equal(claimString(c, "n"), undefined, "number is not a string");
  equal(claimBool(c, "b"), true, "bool");
  equal(claimBool(c, "bs"), undefined, "the string true is not a boolean");
  equal(claimStrings(c, "l")?.join(","), "a,b", "list");
  equal(claimStrings(c, "one")?.join(","), "g", "one");
  equal(claimStrings(c, "mixed"), undefined, "mixed");
});

test("Secret: redacted through String, templates and JSON; reveal is the one way out", () => {
  const s = secret("hunter2");
  equal(String(s), "[redacted]", "String");
  equal(`${s}`, "[redacted]", "template");
  equal(JSON.stringify({ s }), '{"s":"[redacted]"}', "JSON");
  equal(s.reveal(), "hunter2", "reveal");
  check(secret("").isEmpty() && !s.isEmpty(), "isEmpty");
});

test("isOidcError follows the cause chain to a fixed depth", () => {
  const inner = new OidcClientError(OidcErrorCode.accessDenied);
  check(isOidcError(new Error("wrapped", { cause: inner }), OidcErrorCode.accessDenied), "wrapped");
  check(!isOidcError(new Error("other"), OidcErrorCode.accessDenied), "other");
  const cyclic = new Error("a");
  Object.assign(cyclic, { cause: cyclic });
  check(!isOidcError(cyclic, OidcErrorCode.accessDenied), "cycle terminates");
});

test("logoutTargetMatches: empty strings never match", async () => {
  const w = await world();
  const jar = new Jar();
  await signIn(w, jar);
  const g = await gate(w, jar);
  check(g.allowed, "signed in");
  const session = { id: "x", user: g.user, providerSessionId: "sid_1", tokens: {}, createdAt: 0, lastSeenAt: 0, checkedAt: 0, expiresAt: 1 };
  check(!logoutTargetMatches({ issuer: "", subject: g.user.subject }, session), "empty issuer");
  check(!logoutTargetMatches({ issuer: g.user.issuer, subject: "", providerSessionId: "" }, session), "empty both");
  check(logoutTargetMatches({ issuer: g.user.issuer, providerSessionId: "sid_1" }, session), "sid");
  check(!logoutTargetMatches({ issuer: g.user.issuer, subject: g.user.subject, providerSessionId: "sid_2" }, session), "sub with another sid");
});
