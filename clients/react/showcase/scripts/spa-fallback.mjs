// GitHub Pages answers a path with no file with 404.html. A copy of the app's
// index.html there makes every page's URL work on a reload or a shared link.
import { copyFileSync } from "node:fs"
import { join, resolve } from "node:path"

const dist = resolve(import.meta.dirname, "../dist")
copyFileSync(join(dist, "index.html"), join(dist, "404.html"))
console.log("dist/404.html written")
