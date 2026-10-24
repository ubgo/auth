// Session tasks: a session that is signed in but must finish a step (set up
// a second factor, choose a workspace) before it works for anything else.
// The server lists the open tasks on GET /session (`tasks`) and answers
// every other operation 403 auth.session_task_pending until they are done;
// finishing one issues a new session. These hooks read the list from the
// session entry and send the browser to the page that finishes a task.

import { useEffect, useMemo } from "react";
import { useAuth } from "./context.tsx";
import { useSession } from "./session.ts";

/** The task the twofactor plugin's RequireEnrolment opens (auth.TaskSetupMFA). */
// ds:def id=session-task-setup-mfa-2kq8vn4w owner=@khanakia stability=stable
export const SESSION_TASK_SETUP_MFA = "setup-mfa";

/** The code every other operation answers while a task is open (auth.ErrSessionTaskPending). */
export const SESSION_TASK_PENDING_CODE = "auth.session_task_pending";

/** What useSessionTasks returns. */
export type SessionTasksState = {
  /** The session's open tasks, in the server's order; empty for an ordinary session or when signed out. */
  readonly tasks: readonly string[];
  /** Whether any task is open, so the session works only for the task's own operations. */
  readonly pending: boolean;
};

/** The no-tasks answer, one object so a memoised consumer does not re-render. */
const NONE: readonly string[] = [];

/** The open tasks of the signed-in session (`tasks` on GET /session). */
export function useSessionTasks(): SessionTasksState {
  const { session } = useSession();
  const tasks = session?.tasks ?? NONE;
  return useMemo(() => ({ tasks, pending: tasks.length > 0 }), [tasks]);
}

/** Where each task is finished: task id to path. `setup-mfa` goes to paths.setupTwoFactor unless named here. */
export type SessionTaskRoutes = Readonly<Record<string, string>>;

/**
 * Sends the browser to the page that finishes the session's first open task,
 * from any page but that one, so a sign-in that opened a task (or a reload
 * in the middle of one) lands where it can be done. A task with no route is
 * left alone: the app handles it. Mount it once, through SessionTaskRedirect
 * or by calling it in the layout.
 */
export function useSessionTaskRedirect(routes: SessionTaskRoutes = {}): void {
  const { navigate, paths } = useAuth();
  const { tasks } = useSessionTasks();
  const first = tasks[0];
  const target = first === undefined ? undefined : (routes[first] ?? (first === SESSION_TASK_SETUP_MFA ? paths.setupTwoFactor : undefined));
  useEffect(() => {
    if (target === undefined || typeof window === "undefined") return;
    if (window.location.pathname === new URL(target, window.location.origin).pathname) return;
    navigate(target);
  }, [target, navigate]);
}

/** The props of SessionTaskRedirect. */
export type SessionTaskRedirectProps = {
  /** Task id to the path that finishes it; `setup-mfa` defaults to paths.setupTwoFactor. */
  readonly routes?: SessionTaskRoutes;
};

/** useSessionTaskRedirect as a component that renders nothing, for a layout. */
export function SessionTaskRedirect({ routes }: SessionTaskRedirectProps): null {
  useSessionTaskRedirect(routes);
  return null;
}
