// The props every UI component in the registry takes, so customising one
// works the same way as customising any other. CONTRACT.md is the prose
// version of these types.

import type { ComponentLocalizations } from "./localization.ts";

/**
 * Extra classes per named part of a component. Each component documents its
 * slot names as a string union; a slot not in the union does not compile.
 * The classes are merged after the component's own with tailwind-merge, so
 * `p-6` replaces the default padding instead of fighting it.
 */
export type SlotClassNames<Slot extends string> = Partial<Record<Slot, string>>;

/**
 * The props shared by every auth component. `Slot` is the component's slot
 * union, `Key` its localization key, `Result` what a success hands back.
 */
// ds:def id=authcomponentprops-pq4s8fyu owner=@khanakia stability=api
export type AuthComponentProps<Slot extends string, Key extends keyof ComponentLocalizations, Result> = {
  /** Classes for the root element, merged after the defaults. Same as classNames.root. */
  readonly className?: string;
  /** Classes per named part. */
  readonly classNames?: SlotClassNames<Slot>;
  /** Text overrides for this one use, over the provider's and the English defaults. */
  readonly localization?: Partial<ComponentLocalizations[Key]>;
  /**
   * Called after the action succeeds, instead of navigating. Return nothing;
   * navigate yourself if you want to go somewhere.
   */
  readonly onSuccess?: (result: Result) => void;
  /**
   * Where to go after success when there is no onSuccess. Defaults to the
   * provider's path for the flow. Only a path on this site (or an origin in
   * AuthProvider's allowedRedirectOrigins) is followed; anything else is
   * ignored and the default applies, so passing the address bar's
   * ?redirectTo= straight through is safe (useSafeRedirect).
   */
  readonly redirectTo?: string;
  /**
   * The heading level of the component's title. 1 by default, because on a
   * page of its own (/sign-in) the card is the main heading; pass 2 when the
   * page has its own h1, so the outline has one top heading.
   */
  readonly headingLevel?: HeadingLevel;
};

/** An HTML heading level, h1 to h6. */
export type HeadingLevel = 1 | 2 | 3 | 4 | 5 | 6;
