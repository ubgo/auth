// Package-private helpers. Nothing here is re-exported from index.ts, and
// package.json's "exports" map has no deep entry, so an app cannot reach it.

/**
 * The key that brands a genuine `Refreshed`. Package-private: an app cannot
 * name it, so it cannot write a `Refreshed` literal.
 */
export const refreshedBrand: unique symbol = Symbol("Refreshed");

/**
 * Every `Refreshed` that `Provider.refresh` built. The client accepts a
 * `RecheckResult.refreshed` only when it is in here, so a value forged with a
 * cast is refused at run time too. A WeakSet, so it never keeps a value alive.
 */
export const genuineRefreshed: WeakSet<object> = new WeakSet();
