import { existsSync } from "node:fs"
import { createRequire } from "node:module"
import path from "node:path"

// Lazy: on workerd import.meta.url is undefined and the addon is never
// loaded, so createRequire must not run at module scope.
//
// The addon is loaded only from safe, default locations. Attacker-controlled
// environment variables (OCNANO_OC_NANO_PATH, OCNANO_NODE_ASSETS_DIR) are NOT
// consulted: they would allow arbitrary .node loading. If a custom addon path
// is required, change this list rather than relying on env vars.
export default function load() {
  const require = createRequire(import.meta.url)
  const candidates = [
    path.join(path.dirname(process.execPath), "oc_nano_native.node"),
    path.join(path.dirname(process.execPath), "..", "resources", "oc-nano", "oc_nano_native.node"),
    new URL("./oc_nano_native.node", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"),
  ]
  for (const candidate of candidates) {
    if (!candidate) continue
    if (!existsSync(candidate)) continue
    return require(candidate)
  }
  return undefined
}
