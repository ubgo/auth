// Package-private readers for JSON that arrives from outside: the login
// server's answers, token payloads, opened cookies. `JSON.parse` returns an
// untyped value; these narrow it to `JsonValue` and read members by type, so
// nothing untyped travels past the boundary. Nothing here is re-exported.

import type { Claims, JsonValue } from "./identity.ts";

/** A JSON object: what every protocol message and token payload must be. */
export type JsonObject = Claims;

/** Whether `v` is a JSON value all the way down (no functions, undefined, cycles from a reviver, or non-finite numbers). */
function isJsonValue(v: unknown, depth: number): v is JsonValue {
  if (depth > MAX_JSON_DEPTH) return false;
  if (v === null || typeof v === "string" || typeof v === "boolean") return true;
  if (typeof v === "number") return Number.isFinite(v);
  if (Array.isArray(v)) return v.every((item) => isJsonValue(item, depth + 1));
  if (typeof v === "object") return Object.values(v).every((item) => isJsonValue(item, depth + 1));
  return false;
}

/** Nesting deeper than this is refused: no real claim set comes close, and it bounds the recursion on hostile input. */
const MAX_JSON_DEPTH = 32;

/** Whether `v` is a JSON object (not an array, not null). */
export function isJsonObject(v: unknown): v is JsonObject {
  return typeof v === "object" && v !== null && !Array.isArray(v) && isJsonValue(v, 0);
}

/** Parses `text` as a JSON object, or returns `undefined` for anything else (invalid JSON, an array, a string). */
export function parseJsonObject(text: string): JsonObject | undefined {
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    return undefined;
  }
  return isJsonObject(v) ? v : undefined;
}

/** Member `name` when it is a string. */
export function str(o: JsonObject, name: string): string | undefined {
  const v = o[name];
  return typeof v === "string" ? v : undefined;
}

/** Member `name` when it is a finite number. */
export function num(o: JsonObject, name: string): number | undefined {
  const v = o[name];
  return typeof v === "number" ? v : undefined;
}

/** Member `name` when it is a boolean. */
export function bool(o: JsonObject, name: string): boolean | undefined {
  const v = o[name];
  return typeof v === "boolean" ? v : undefined;
}

/** Member `name` when it is an object. */
export function obj(o: JsonObject, name: string): JsonObject | undefined {
  const v = o[name];
  return isJsonObject(v) ? v : undefined;
}

/** Member `name` when it is a list of strings (every item a string), else `undefined`. */
export function strList(o: JsonObject, name: string): readonly string[] | undefined {
  const v = o[name];
  return Array.isArray(v) && v.every((item): item is string => typeof item === "string") ? v : undefined;
}
