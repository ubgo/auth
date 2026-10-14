// What a settings page does with the app's own plugin: the methods and the
// error code below come from the Go plugin in ../../nickname, through the
// generated client. Rename the Go field or the code and this file stops
// compiling.

import type { AppClient } from "./app-auth.ts";

/** What the form shows after a save. */
export type SaveOutcome = { readonly saved: string | null } | { readonly error: string };

// ds:def id=tsclientcustom-save-8nq4kw2x
export async function saveNickname(client: AppClient, value: string): Promise<SaveOutcome> {
  const { data, error } = await client.nickname.set({ nickname: value });
  if (error) {
    switch (error.code) {
      case "nickname.too_long": // the plugin's own code, typed like the library's
        return { error: "That nickname is too long." };
      case "auth.signed_out":
        return { error: "Sign in again to change your nickname." };
      default:
        return { error: error.message };
    }
  }
  return { saved: data.nickname };
}

/** The nickname to show in the header, or null when there is none or nobody is signed in. */
// ds:def id=tsclientcustom-show-2vk8mq5t
export async function currentNickname(client: AppClient): Promise<string | null> {
  const { data } = await client.nickname.get();
  return data?.nickname ?? null;
}
