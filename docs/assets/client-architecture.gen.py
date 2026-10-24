# Generates docs/assets/client-architecture.svg, the client diagram embedded in
# docs/client/README.md, docs/README.md and the root README.md. Edit this
# file, never the SVG, then regenerate from the repository root:
#
#   python3 docs/assets/client-architecture.gen.py > docs/assets/client-architecture.svg
#
# Standard library only; it writes the SVG to stdout.

import sys

W, H = 900, 1023
out = []
P = out.append

COL = {
    "blue": ("#dbeafe", "#3b82f6", "#1e40af"),
    "orange": ("#fef3c7", "#f59e0b", "#b45309"),
    "green": ("#d1fae5", "#22c55e", "#166534"),
    "purple": ("#f3e8ff", "#a855f7", "#6b21a8"),
    "pink": ("#fce7f3", "#ec4899", "#9d174d"),
}


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def group(x, y, w, h, title):
    P(f'  <rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="#f8fafc" stroke="#94a3b8" stroke-dasharray="6,4"/>')
    P(f'  <text x="{x + 10}" y="{y + 14}" font-size="11" fill="#64748b">{esc(title)}</text>')


boxes = []


def box(x, y, w, h, color, main, *subs):
    fill, stroke, text = COL[color]
    boxes.append(f'  <rect x="{x}" y="{y}" width="{w}" height="{h}" rx="6" fill="{fill}" stroke="{stroke}"/>')
    cx = x + w / 2
    cx = int(cx) if cx == int(cx) else cx
    if not subs:
        boxes.append(f'  <text x="{cx}" y="{y + h / 2 + 4.2:g}" font-size="12" fill="{text}" text-anchor="middle">{esc(main)}</text>')
    elif len(subs) == 1:
        boxes.append(f'  <text x="{cx}" y="{y + 22}" font-size="12" fill="{text}" text-anchor="middle">{esc(main)}</text>')
        boxes.append(f'  <text x="{cx}" y="{y + 40}" font-size="10" fill="{text}" text-anchor="middle">{esc(subs[0])}</text>')
    else:
        boxes.append(f'  <text x="{cx}" y="{y + 23}" font-size="12" fill="{text}" text-anchor="middle">{esc(main)}</text>')
        boxes.append(f'  <text x="{cx}" y="{y + 41}" font-size="10" fill="{text}" text-anchor="middle">{esc(subs[0])}</text>')
        boxes.append(f'  <text x="{cx}" y="{y + 56}" font-size="10" fill="{text}" text-anchor="middle">{esc(subs[1])}</text>')


P(f'<svg viewBox="0 0 {W} {H}" width="{W}" xmlns="http://www.w3.org/2000/svg">')
P('  <title>ubgo/auth client architecture</title>')
P('  <desc>Layer stack of the TypeScript and React client of github.com/ubgo/auth: the browser, the React UI kit and app code, @ubgo/auth-react, @ubgo/auth-client, the network, the Go server and storage, with a numbered password sign-in going down and the answer coming back up, and the build-time column where the Go operations generate client.ts.</desc>')
P('  <style>')
P("    text { font-family: 'PingFang SC', 'Microsoft YaHei', 'Noto Sans CJK SC', system-ui, sans-serif; }")
P('  </style>')
P('  <defs>')
for mid, c in [("arrow", "#64748b"), ("arrow-blue", "#3b82f6"), ("arrow-green", "#22c55e"), ("arrow-purple", "#a855f7")]:
    P(f'    <marker id="{mid}" markerWidth="8" markerHeight="8" refX="2" refY="4" orient="auto" markerUnits="userSpaceOnUse">')
    P(f'      <path d="M0,0 L8,4 L0,8 L2,4 z" fill="{c}"/>')
    P('    </marker>')
P('  </defs>')
P('  <!-- White canvas, so the diagram reads as a light card on both GitHub themes. -->')
P(f'  <rect x="0" y="0" width="{W}" height="{H}" fill="#ffffff"/>')
P(f'  <text x="450" y="34" font-size="16" fill="#1e293b" text-anchor="middle">ubgo/auth client: from a click in React to a row in the database</text>')

# Main stack: groups x=22 w=632 (inner boxes 38..638); build column x=684 w=194.
GX, GW = 22, 632
bands = [
    # (y, h, title)
    (50, 95, "Browser"),
    (185, 113, "React UI kit: registry components you copy and own, plus your own code"),
    (338, 95, "@ubgo/auth-react: imported, headless, built on TanStack Query"),
    (473, 95, "@ubgo/auth-client: generated client.ts on a hand-written runtime.ts"),
    (608, 95, "Network: fetch to /auth/*"),
    (743, 95, "Go server: github.com/ubgo/auth"),
    (878, 95, "Storage"),
]
P('  <!-- Layer groups, top to bottom. -->')
for y, h, t in bands:
    group(GX, y, GW, h, t)
P('  <!-- Build-time column: aligned from @ubgo/auth-client down to the Go server. -->')
group(684, 473, 194, 365, "Build time: when Go changes")

# Connectors (painted under boxes).
P('  <!-- Down (blue, x=62) and up (green, x=92) through every gap between layers. -->')
gaps = [145, 298, 433, 568, 703, 838]
down = [
    "① click Sign in",
    "② SignInForm: usePluginClient(\"password\")",
    "③ client.password.signIn({ … })",
    "④ fetch POST /auth/password/sign-in",
    "⑤ JSON body, cookie or Bearer header",
    "⑥ read the hash, INSERT auth_session",
]
up = [
    "⑫ navigate: the page is signed in",
    "⑪ useSession() now has the user",
    "⑩ refreshSession(): refetch GET /auth/session",
    "⑨ runtime.ts resolves { data, error }",
    "⑧ 200 + Set-Cookie (or Set-Auth-Token)",
    "⑦ row stored",
]
labels = []
for g, d, u in zip(gaps, down, up):
    top = g + 40
    P(f'  <path d="M62,{g + 5} L 62,{top - 11}" fill="none" stroke="#3b82f6" stroke-width="1.5" marker-end="url(#arrow-blue)"/>')
    P(f'  <path d="M92,{top - 5} L 92,{g + 11}" fill="none" stroke="#22c55e" stroke-width="1.5" marker-end="url(#arrow-green)"/>')
    labels.append(f'  <text x="106" y="{g + 23.5}" font-size="10" fill="#1e40af">{esc(d)}</text>')
    labels.append(f'  <text x="360" y="{g + 23.5}" font-size="10" fill="#166534">{esc(u)}</text>')
P('  <!-- Inside the Go server: handler, pipeline, plugin. -->')
P('  <path d="M226,795 L 235,795" fill="none" stroke="#64748b" stroke-width="1.5" marker-end="url(#arrow)"/>')
P('  <path d="M434,795 L 443,795" fill="none" stroke="#64748b" stroke-width="1.5" marker-end="url(#arrow)"/>')
P('  <!-- Build time, bottom to top: operations, generator, the two ways to run it, the files; then into the client layer. -->')
P('  <path d="M781,763 L 781,749" fill="none" stroke="#a855f7" stroke-width="1.5" marker-end="url(#arrow-purple)"/>')
P('  <path d="M781,679 L 781,665" fill="none" stroke="#a855f7" stroke-width="1.5" marker-end="url(#arrow-purple)"/>')
P('  <path d="M781,577 L 781,563" fill="none" stroke="#a855f7" stroke-width="1.5" marker-end="url(#arrow-purple)"/>')
P('  <path d="M696,525 L 665,525" fill="none" stroke="#a855f7" stroke-width="1.5" marker-end="url(#arrow-purple)"/>')
out.extend(labels)

# Boxes.
w3, x3 = 183, [38, 246, 454]
w4, x4 = 131, [38, 194, 350, 506]
box(x3[0], 75, w3, 54, "blue", "User", "clicks Sign in")
box(x3[1], 75, w3, 54, "blue", "Page", "React app, same origin as /auth")
box(x3[2], 75, w3, 54, "blue", "Cookie jar", "__Host-auth_session")

box(x4[0], 210, w4, 72, "blue", "Sign-in forms", "SignInForm", "SignUpForm")
box(x4[1], 210, w4, 72, "blue", "Second factor", "TwoFactorChallenge", "TwoFactorSetup")
box(x4[2], 210, w4, 72, "blue", "Account", "AccountSettings", "UserButton · Passkeys")
box(x4[3], 210, w4, 72, "blue", "Your app code", "pages and routes", "SignedIn · SignedOut")

box(x4[0], 363, w4, 54, "orange", "AuthProvider", "client, queryClient")
box(x4[1], 363, w4, 54, "orange", "useAuth", "context for the kit")
box(x4[2], 363, w4, 54, "orange", "useSession", "one cached query")
box(x4[3], 363, w4, 54, "orange", "usePlugin", "is the plugin on?")

box(x4[0], 498, w4, 54, "purple", "client.ts", "plugin namespaces")
box(x4[1], 498, w4, 54, "orange", "runtime.ts", "fetch, never throws")
box(x4[2], 498, w4, 54, "orange", "TokenStore", "bearer mode only")
box(x4[3], 498, w4, 54, "purple", "error-codes.ts", "closed union of codes")

box(x3[0], 633, w3, 54, "pink", "Cookie mode (default)", "credentials: include")
box(x3[1], 633, w3, 54, "pink", "Bearer mode", "Authorization: Bearer")
box(x3[2], 633, w3, 54, "pink", "Dev proxy", "Vite forwards /auth to Go")

box(x3[0], 768, w3, 54, "orange", "authhttp.Handler", "routes under /auth")
box(x3[1], 768, w3, 54, "orange", "Operation pipeline", "rate limit · hooks · effects")
box(x3[2], 768, w3, 54, "purple", "password plugin", "verify hash, create session")

box(x3[0], 903, w3, 54, "green", "auth_identity", "password hash")
box(x3[1], 903, w3, 54, "green", "auth_session", "the new session row")
box(x3[2], 903, w3, 54, "green", "SQL database", "SQLite · Postgres · MySQL")

box(701, 498, 160, 54, "purple", "Four .ts files", "client.ts, runtime.ts, …")
box(701, 582, 160, 72, "purple", "Run the generator", "task docs:api → prebuilt", "auth client ts → app-exact")
box(701, 684, 160, 54, "purple", "TypeScriptClient(a)", "authhttp generator")
box(701, 768, 160, 54, "purple", "Go operations", "auth.Define, per plugin")
out.extend(boxes)

P('  <text x="450" y="999" font-size="10" fill="#64748b" text-anchor="middle">Blue: a password sign-in going down (1 to 6). Green: the answer coming back up (7 to 12). Purple: plugins and generated code.</text>')
P('</svg>')
sys.stdout.write("\n".join(out) + "\n")
