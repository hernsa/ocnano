import { connect } from "node:net"

// Bun's fetch (and undici under Node) send every outbound request through
// HTTP_PROXY/HTTPS_PROXY/ALL_PROXY when those are set. A proxy that stopped
// answering turns every provider call into ECONNREFUSED, so a proxy whose
// target refuses the connection is dropped before the first request goes out.
// The operator can put it back by setting the variable again.

const PROXY_VARIABLES = [
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "ALL_PROXY",
  "http_proxy",
  "https_proxy",
  "all_proxy",
] as const

// A proxy that answers slowly is a proxy that is not serving. One second is
// long enough for a local relay and short enough to keep startup cheap.
const PROBE_TIMEOUT_MS = 1000

function proxyTarget(value: string) {
  try {
    const url = new URL(value.includes("://") ? value : `http://${value}`)
    const port = Number(url.port || (url.protocol === "https:" ? 443 : 80))
    if (!url.hostname) return undefined
    if (!Number.isInteger(port) || port <= 0 || port > 65535) return undefined
    return { host: url.hostname, port }
  } catch {
    return undefined
  }
}

function reachable(host: string, port: number) {
  return new Promise<boolean>((resolve) => {
    const socket = connect({ host, port })
    let settled = false
    const done = (ok: boolean) => {
      if (settled) return
      settled = true
      socket.destroy()
      resolve(ok)
    }
    socket.setTimeout(PROBE_TIMEOUT_MS)
    socket.once("connect", () => done(true))
    socket.once("timeout", () => done(false))
    socket.once("error", () => done(false))
  })
}

/**
 * Removes proxy variables whose target refuses connections. Returns one entry
 * per dropped variable, so the caller can report it.
 */
export async function dropUnreachableProxies(): Promise<string[]> {
  const dropped: string[] = []
  // Several variables usually name the same relay, so each target is probed
  // once and the answer is reused.
  const verdicts = new Map<string, boolean>()
  for (const name of PROXY_VARIABLES) {
    const value = process.env[name]
    if (!value) continue
    const target = proxyTarget(value)
    // A value no URL parser accepts is left alone: the HTTP client reports it
    // with a better message than a probe could.
    if (!target) continue
    const key = `${target.host}:${target.port}`
    let ok = verdicts.get(key)
    if (ok === undefined) {
      ok = await reachable(target.host, target.port)
      verdicts.set(key, ok)
    }
    if (ok) continue
    delete process.env[name]
    dropped.push(name)
  }
  return dropped
}
