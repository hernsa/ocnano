import { ServerAuth } from "../auth"
import { UnauthorizedError } from "@ocnano/protocol/errors"
import { Authorization } from "@ocnano/protocol/middleware/authorization"
export { Authorization } from "@ocnano/protocol/middleware/authorization"
import { PTY_CONNECT_PATH, PTY_CONNECT_TICKET_QUERY } from "@ocnano/protocol/groups/pty"
import { PERSISTENT_PTY_CONNECT_PATH } from "@ocnano/protocol/groups/persistent-pty"
import { MCP_CLIENT_PATH } from "@ocnano/protocol/groups/mcp"
import { PAIRING_CONNECT_PATH } from "@ocnano/protocol/groups/server"
import { Effect, Layer, Redacted } from "effect"
import { Base64 } from "effect/encoding"
import { HttpEffect, HttpRouter, HttpServerRequest, HttpServerResponse } from "effect/http"

const AUTH_TOKEN_QUERY = "auth_token"
const WWW_AUTHENTICATE = 'Basic realm="Secure Area"'

function emptyCredential() {
  return { username: "", password: Redacted.make("") }
}

function decodeCredential(input: string) {
  return Effect.fromResult(Base64.decodeString(input)).pipe(
    Effect.match({
      onFailure: emptyCredential,
      onSuccess: (header) => {
        const separator = header.indexOf(":")
        if (separator === -1) return emptyCredential()
        return { username: header.slice(0, separator), password: Redacted.make(header.slice(separator + 1)) }
      },
    }),
  )
}

function credentialFromRequest(request: HttpServerRequest.HttpServerRequest) {
  // The header wins: it is the one credential the client controls and the one that never
  // reaches a log. A token in the query string is read only for plain reads, because a
  // query string ends up in access logs, proxy logs and browser history.
  const match = /^Basic\s+(.+)$/i.exec(request.headers.authorization ?? "")
  if (match) return decodeCredential(match[1])
  if (request.method === "GET") {
    const url = new URL(request.url, "http://localhost")
    const token = url.searchParams.get(AUTH_TOKEN_QUERY)
    if (token) return decodeCredential(token)
  }
  return Effect.succeed(emptyCredential())
}

// Failed authentications are counted per client so a password cannot be guessed one
// attempt at a time. A client that authenticates clears its count. The counters expire
// with their window, so an idle server forgets them.
const FAILURE_WINDOW_MS = 60_000
const MAX_FAILURES = 20
const failures = new Map<string, { count: number; resetAt: number }>()

function clientKey(request: HttpServerRequest.HttpServerRequest) {
  const forwarded = request.headers["x-forwarded-for"]
  if (typeof forwarded === "string" && forwarded.length > 0) return forwarded.split(",")[0]?.trim() || "local"
  return "local"
}

function failedAttempts(key: string) {
  const entry = failures.get(key)
  if (!entry) return 0
  if (Date.now() >= entry.resetAt) {
    failures.delete(key)
    return 0
  }
  return entry.count
}

function recordFailure(key: string) {
  const entry = failures.get(key)
  if (!entry || Date.now() >= entry.resetAt) {
    failures.set(key, { count: 1, resetAt: Date.now() + FAILURE_WINDOW_MS })
    return
  }
  entry.count += 1
}

function clearFailures(key: string) {
  failures.delete(key)
}

const UNAUTHORIZED_MESSAGE = "Authentication required"

// Browsers show a native credentials prompt for a Basic challenge even on fetch, which would stall the web app
// before it can show its own sign-in screen. Only non-browser clients and page navigations get the challenge.
function challengeRequest(request: HttpServerRequest.HttpServerRequest) {
  const mode = request.headers["sec-fetch-mode"]
  return mode === undefined || mode === "navigate"
}

// Matches what the Authorization middleware encodes, for requests rejected before the HttpApi runs.
export function unauthorizedResponse(request: HttpServerRequest.HttpServerRequest) {
  return HttpServerResponse.jsonUnsafe(
    { _tag: "UnauthorizedError", message: UNAUTHORIZED_MESSAGE },
    { status: 401, headers: challengeRequest(request) ? { "www-authenticate": WWW_AUTHENTICATE } : undefined },
  )
}

export function authorizedRequest(request: HttpServerRequest.HttpServerRequest, config: ServerAuth.Info) {
  return credentialFromRequest(request).pipe(
    Effect.map((credential) => ServerAuth.authorized(credential, config) || authorizedSessionCookie(request, config)),
  )
}

function authorizedSessionCookie(request: HttpServerRequest.HttpServerRequest, config: ServerAuth.Info) {
  const token = request.cookies[ServerAuth.sessionCookieName(request.headers.host)]
  if (!token) return false
  // Same-site pages on other ports still send this cookie, so only same-origin requests may use it.
  const origin = request.headers.origin
  if (origin !== undefined && URL.parse(origin)?.host !== request.headers.host) return false
  return ServerAuth.verifySession(token, config)
}

export const authorizationLayer = Layer.effect(
  Authorization,
  Effect.gen(function* () {
    const config = yield* ServerAuth.Config
    if (!ServerAuth.required(config)) return Authorization.of((effect) => effect)
    return Authorization.of((effect) =>
      Effect.gen(function* () {
        const request = yield* HttpServerRequest.HttpServerRequest
        const route = yield* HttpRouter.RouteContext
        const url = new URL(request.url, "http://localhost")
        // Ticketed connects (PTY, persistent PTY, client MCP) and pairing links carry their own
        // single-use credential: a browser cannot set an Authorization header on a WebSocket
        // upgrade. Their handler consumes and validates the ticket or code, so the request
        // reaches it untouched. Use the route selected by Effect so authorization and dispatch
        // cannot disagree about the request path.
        const ticketed =
          ((route.route.path === PTY_CONNECT_PATH ||
            route.route.path === PERSISTENT_PTY_CONNECT_PATH ||
            route.route.path === MCP_CLIENT_PATH) &&
            !!url.searchParams.get(PTY_CONNECT_TICKET_QUERY)) ||
          route.route.path === PAIRING_CONNECT_PATH
        if (ticketed) return yield* effect
        // Every other request needs the server password or a session cookie.
        const key = clientKey(request)
        if (failedAttempts(key) >= MAX_FAILURES)
          return HttpServerResponse.jsonUnsafe(
            { _tag: "TooManyRequestsError", message: "Too many failed authentication attempts" },
            {
              status: 429,
              headers: { "retry-after": String(Math.ceil(FAILURE_WINDOW_MS / 1000)) },
            },
          )
        if (!(yield* authorizedRequest(request, config))) {
          recordFailure(key)
          if (challengeRequest(request))
            yield* HttpEffect.appendPreResponseHandler((_request, response) =>
              Effect.succeed(HttpServerResponse.setHeader(response, "www-authenticate", WWW_AUTHENTICATE)),
            )
          return yield* new UnauthorizedError({ message: UNAUTHORIZED_MESSAGE })
        }
        clearFailures(key)
        return yield* effect
      }),
    )
  }),
)
