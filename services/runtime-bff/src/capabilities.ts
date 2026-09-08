import type { XOOSCapabilityResponse } from "@xoos/contracts";
import type { XOIdentity } from "./auth";
import { HttpError } from "./auth";

export interface CapabilityContext {
  identity: XOIdentity;
  clientId: string;
  traceId: string;
  microappKey?: string;
}

type Handler = (context: CapabilityContext, input: unknown) => Promise<unknown>;

const handlers = new Map<string, Handler>();

handlers.set("runtime.health", async (context) => ({
  status: "ok",
  userId: context.identity.userId,
  clientId: context.clientId
}));

export function registerCapability(name: string, handler: Handler): void {
  if (!name.trim()) throw new Error("Capability name is required.");
  handlers.set(name, handler);
}

export async function executeCapability(
  capability: string,
  context: CapabilityContext,
  input: unknown
): Promise<XOOSCapabilityResponse> {
  const handler = handlers.get(capability);
  if (!handler) throw new HttpError(404, "CAPABILITY_NOT_FOUND", `Capability '${capability}' is not registered.`);

  const data = await handler(context, input);
  return { ok: true, data, traceId: context.traceId };
}
