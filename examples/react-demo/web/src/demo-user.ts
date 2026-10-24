// The user the demo server seeds on start (examples/react-demo/seed.go).
// Keep the three places that name it in step: seed.go, this file, README.md.

export const DEMO_USER = {
  name: "Ada Lovelace",
  email: "ada@example.com",
  password: "correct horse battery staple",
} as const

// The second password user the server seeds (seed.go secondUser*), with the
// demo user's password: someone with sessions for the admin dashboard to revoke.
export const SECOND_USER = {
  name: "Linus Pauling",
  email: "linus@example.com",
} as const

// The user the server makes set up a second factor before the session works
// (seed.go mfaUser*, admin.go mustEnrol), with the demo user's password.
export const MFA_USER = {
  name: "Grace Required",
  email: "mfa@example.com",
} as const
