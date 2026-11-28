import { Credential } from "@ocnano/core/credential"
import { FileSystem } from "@ocnano/core/filesystem"
import { Location } from "@ocnano/core/location"
import { LocationServiceMap } from "@ocnano/core/location-services"
import { AbsolutePath } from "@ocnano/core/schema"
import { ConflictError } from "@ocnano/protocol/errors"
import { Global } from "@ocnano/util/global"
import { Effect } from "effect"
import { HttpApiBuilder, HttpApiSchema } from "effect/http-api"
import { Api } from "../api"
import { requireConnectable } from "./integration"

export const CredentialHandler = HttpApiBuilder.group(Api, "server.credential", (handlers) =>
  Effect.gen(function* () {
    const global = yield* Global.Service
    const locations = yield* LocationServiceMap.Service
    // Credentials are global, so `integration.connect` is read from the global config Location, which carries managed
    // policy, the Console document, and user config.
    const services = locations.get(Location.Ref.make({ directory: AbsolutePath.make(global.config) }))
    return handlers
      .handle(
        "credential.list",
        Effect.fn(function* () {
          const credential = yield* Credential.Service
          return { data: entries(yield* credential.all()) }
        }),
      )
      .handle(
        "credential.export",
        Effect.fn(function* () {
          const credential = yield* Credential.Service
          return { data: entries(yield* credential.all(), true) }
        }),
      )
      .handle(
        "credential.create",
        Effect.fn(function* (ctx) {
          yield* requireConnectable(ctx.payload.integrationID).pipe(
            Effect.provide(services),
            // The global config directory always exists.
            Effect.catchIf((error) => error instanceof FileSystem.DirectoryNotFoundError, Effect.die),
          )
          const credential = yield* Credential.Service
          if (ctx.payload.id && (yield* credential.get(ctx.payload.id)))
            return yield* new ConflictError({
              resource: ctx.payload.id,
              message: `Credential already exists: ${ctx.payload.id}`,
            })
          const created = yield* credential.create(ctx.payload)
          const entry = entries(yield* credential.list(created.integrationID)).find((item) => item.id === created.id)
          return { data: entry ?? { ...created, active: false } }
        }),
      )
      .handle(
        "credential.update",
        Effect.fn(function* (ctx) {
          const credential = yield* Credential.Service
          yield* credential.update(ctx.params.credentialID, { label: ctx.payload.label })
          return HttpApiSchema.NoContent.make()
        }),
      )
      .handle(
        "credential.activate",
        Effect.fn(function* (ctx) {
          const credential = yield* Credential.Service
          yield* credential.activate(ctx.params.credentialID)
          return HttpApiSchema.NoContent.make()
        }),
      )
      .handle(
        "credential.remove",
        Effect.fn(function* (ctx) {
          const credential = yield* Credential.Service
          yield* credential.remove(ctx.params.credentialID)
          return HttpApiSchema.NoContent.make()
        }),
      )
  }),
)

// Credential listings order each integration's selected credential last.
function entries(credentials: Credential.Info[], reveal = false) {
  const selected = new Map(credentials.map((item) => [item.integrationID, item.id]))
  return credentials.map((item) => ({
    id: item.id,
    integrationID: item.integrationID,
    label: item.label,
    active: selected.get(item.integrationID) === item.id,
    value: reveal ? item.value : maskValue(item.value),
  }))
}

// A listing is metadata: the secret is only handed out by the export endpoint.
function maskValue(value: Credential.Info["value"]): Credential.Info["value"] {
  if (typeof value !== "object" || value === null) return value
  const record = value as Record<string, unknown>
  if (record.type === "key") return { ...record, key: "" } as Credential.Info["value"]
  if (record.type === "oauth")
    return { ...record, refresh: "", access: "", expires: 0 } as Credential.Info["value"]
  return value
}
