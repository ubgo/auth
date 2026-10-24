import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import { createBrowserRouter } from "react-router"
import { RouterProvider } from "react-router/dom"

import { AccountPage, HomePage, MagicLinkPage, RequireUser, SignInPage } from "./pages.tsx"
import { Root } from "./root.tsx"
import "./styles.css"

// The kit's default paths (DEFAULT_AUTH_PATHS) are the routes here: /sign-in,
// /account, and the page a magic link opens, /magic-link.
// ds:def id=rr-router-cnmjysbt
const router = createBrowserRouter([
  {
    path: "/",
    element: <Root />,
    children: [
      { index: true, element: <HomePage /> },
      { path: "sign-in", element: <SignInPage /> },
      { path: "account", element: <RequireUser><AccountPage /></RequireUser> },
      { path: "magic-link", element: <MagicLinkPage /> },
    ],
  },
])

const root = document.getElementById("root")
if (root === null) throw new Error("index.html has no #root")
createRoot(root).render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>,
)
