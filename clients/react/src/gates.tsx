// Render children only for one side of the session. Neither renders while
// the first session read is in flight, so a signed-in user never sees a
// flash of the sign-in button.

import type { ReactNode } from "react";
import { useSession } from "./session.ts";

/** Props of SignedIn and SignedOut. */
// ds:def id=sessiongateprops-8zaganxf owner=@khanakia stability=stable
export type SessionGateProps = {
  readonly children: ReactNode;
  /** Rendered while the first session read is in flight. Nothing by default. */
  readonly fallback?: ReactNode;
};

/** Renders children only when someone is signed in. */
export function SignedIn({ children, fallback = null }: SessionGateProps) {
  const { session, isPending } = useSession();
  if (isPending) return <>{fallback}</>;
  return session === null ? null : <>{children}</>;
}

/** Renders children only when nobody is signed in (a pending second factor counts as signed out). */
export function SignedOut({ children, fallback = null }: SessionGateProps) {
  const { session, isPending } = useSession();
  if (isPending) return <>{fallback}</>;
  return session === null ? <>{children}</> : null;
}
