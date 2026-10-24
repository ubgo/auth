// /user-button: UserButton in a mock app header, three ways: the avatar
// alone, with the name, and with an app item of its own. Signed out, each
// becomes a "Sign in" button.

import { useAuth } from "@ubgo/auth-react"
import { LayoutDashboardIcon } from "lucide-react"
import type { ReactNode } from "react"

import { UserButton, type UserButtonSlot } from "@/components/auth/user-button"
import { DemoPage } from "@/components/demo-page"
import { RouterLink } from "@/components/demo-shell"
import { DropdownMenuItem } from "@/components/ui/dropdown-menu"
import { useDemoCustomise } from "@/demo/customise"

/** The classNames the Custom appearance applies, shown verbatim in the panel. */
const CUSTOM: Partial<Record<UserButtonSlot, string>> = {
  trigger: "rounded-lg",
  avatar: "rounded-md after:rounded-md *:rounded-md",
  content: "w-64 rounded-xl",
}

const CUSTOM_CODE = `<UserButton
  showName
  classNames={${JSON.stringify(CUSTOM, null, 2).replace(/\n/g, "\n  ")}}
/>`

/** A strip that looks like an app's top bar, so the button is seen where it lives. */
function MockHeader({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-1.5">
      <span className="text-xs text-muted-foreground">{label}</span>
      <div className="flex h-11 items-center justify-between rounded-lg border bg-background px-3">
        <span className="font-semibold tracking-tight">Acme</span>
        {children}
      </div>
    </div>
  )
}

export function UserButtonPage() {
  const { custom } = useDemoCustomise()
  const { navigate } = useAuth()
  const classNames = custom ? CUSTOM : undefined
  return (
    <DemoPage
      title="User button"
      description="The avatar menu for an app's header: name and email, Manage account, the app's own items, Sign out. Signed out, a Sign in button."
      customCode={CUSTOM_CODE}
      tryThis={[
        <>
          <RouterLink href="/sign-in?redirectTo=/user-button">Sign in</RouterLink>, then open a menu with a click, or Tab to it and press Enter.
        </>,
        <>Arrow keys move through the items; Escape closes the menu and returns focus.</>,
        <>
          Set a picture under <RouterLink href="/account">Account settings</RouterLink>: every avatar here follows.
        </>,
        <>Sign out from a menu: you land on the sign-in page.</>,
      ]}
    >
      <div className="flex w-full max-w-lg flex-col gap-4">
        <MockHeader label="Avatar only">
          <UserButton classNames={classNames} />
        </MockHeader>
        <MockHeader label="With the name">
          <UserButton showName classNames={classNames} />
        </MockHeader>
        <MockHeader label="With an app item">
          <UserButton
            showName
            classNames={classNames}
            menuItems={
              <DropdownMenuItem onClick={() => navigate("/")}>
                <LayoutDashboardIcon aria-hidden />
                Dashboard
              </DropdownMenuItem>
            }
          />
        </MockHeader>
      </div>
    </DemoPage>
  )
}
