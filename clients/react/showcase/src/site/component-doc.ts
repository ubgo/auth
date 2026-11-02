// The shape scripts/build-docs.mjs writes for each component page into
// src/generated/docs/<name>.ts: the files shadcn installs, highlighted, and
// the props of the wired component and its view.

/** A token: its text and an index into the file set's palette. */
export type CodeToken = readonly [text: string, color: number]

/** One installed file, exactly as the built registry item carries it. */
export interface CodeFile {
  /** Where shadcn writes it in the app: "components/auth/verify-email.tsx". */
  readonly target: string
  /** The file's text, for the copy button. */
  readonly content: string
  /** The text split into highlighted lines. */
  readonly lines: readonly (readonly CodeToken[])[]
}

export interface ComponentCode {
  /** [light, dark] colour pairs the tokens index; "" leaves the text colour. */
  readonly palette: readonly (readonly [light: string, dark: string])[]
  /** The component's own files, then the shared auth-view lib. */
  readonly files: readonly CodeFile[]
  /** The ui primitives the install also pulls in (button, card, ...). */
  readonly primitives: readonly string[]
  /** Other auth components the install pulls in, each with its own page. */
  readonly components: readonly string[]
}

/** One prop, as the TypeScript source declares it. */
export interface PropRow {
  readonly name: string
  /** The type, shortened when long. */
  readonly type: string
  /** The full type, when type is shortened. */
  readonly fullType?: string
  readonly required: boolean
  /** A default visible in the source (the destructuring, or a @default tag). */
  readonly default?: string
  /** The prop's JSDoc; empty when the source has none. */
  readonly description: string
}

export interface PropsTable {
  /** The component's export name: VerifyEmail, VerifyEmailView. */
  readonly component: string
  readonly rows: readonly PropRow[]
}

export interface ComponentDoc {
  /** The registry item name. */
  readonly name: string
  readonly code: ComponentCode
  /** The wired component's props, then its view's. */
  readonly props: readonly PropsTable[]
}
