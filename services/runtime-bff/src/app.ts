import type { XOOSRuntimeContext } from "@xoos/contracts";
import { authenticateRequest, HttpError } from "./auth";
import { executeCapability } from "./capabilities";
import type { RuntimeBffConfig } from "./config";
import { buildRuntimeFeed, assertClientBinding } from "./feed";
import { createRegistryClient } from "./supabase";

export function createRuntimeBffHandler(config: RuntimeBffConfig) {
  const db = createRegistryClient(config);

  return async (request: Request): Promise<Response> => {
    const origin = request.headers.get("origin");
    const cors = corsHeaders(origin, config.allowedOrigins);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });

    const traceId = request.headers.get("x-xo-trace-id")?.trim() || crypto.randomUUID();

    try {
      const identity = await authenticateRequest(request, config);
      const clientId = request.headers.get("x-xo-client-id")?.trim();
      if (!clientId) throw new HttpError(400, "CLIENT_ID_MISSING", "X-XO-Client-Id header is required.");
      assertClientBinding(identity, clientId);

      const url = new URL(request.url);
      const path = normalizePath(url.pathname);

      if (request.method === "GET" && path === "/v1/runtime/context") {
        const body: XOOSRuntimeContext = {
          user: { id: identity.userId },
          tenant: { id: identity.tenantId },
          client: { id: clientId },
          runtime: { minimumVersion: config.minimumRuntimeVersion },
          scopes: identity.scopes
        };
        return json(body, 200, cors, traceId);
      }

      if (request.method === "GET" && path === "/v1/runtime/feed") {
        const feed = await buildRuntimeFeed(db, config, identity, clientId);
        return json(feed, 200, cors, traceId);
      }

      if (request.method === "POST" && path.startsWith("/v1/capabilities/")) {
        const capability = decodeURIComponent(path.slice("/v1/capabilities/".length));
        const body = await safeJson(request);
        const result = await executeCapability(
          capability,
          {
            identity,
            clientId,
            traceId,
            microappKey: typeof body.microappKey === "string" ? body.microappKey : undefined
          },
          body.input
        );
        return json(result, 200, cors, traceId);
      }

      if (request.method === "POST" && path === "/v1/telemetry") {
        return json({ ok: true, traceId }, 202, cors, traceId);
      }

      throw new HttpError(404, "ROUTE_NOT_FOUND", "Runtime BFF route not found.");
    } catch (error) {
      const failure = error instanceof HttpError
        ? error
        : new HttpError(500, "INTERNAL_ERROR", "Runtime BFF request failed.");
      if (!(error instanceof HttpError)) console.error("runtime-bff error", { traceId, error });
      return json({ error: { code: failure.code, message: failure.message }, traceId }, failure.status, cors, traceId);
    }
  };
}

function normalizePath(pathname: string): string {
  const marker = "/v1/";
  const index = pathname.indexOf(marker);
  return index >= 0 ? pathname.slice(index) : pathname;
}

async function safeJson(request: Request): Promise<Record<string, any>> {
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value) ? value : {};
  } catch {
    throw new HttpError(400, "INVALID_JSON", "Request body must be valid JSON.");
  }
}

function corsHeaders(origin: string | null, allowedOrigins: string[]): HeadersInit {
  const allowed = origin && allowedOrigins.includes(origin) ? origin : "null";
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "authorization,content-type,x-xo-client-id,x-xo-trace-id",
    "Access-Control-Expose-Headers": "x-xo-trace-id",
    Vary: "Origin"
  };
}

function json(body: unknown, status: number, cors: HeadersInit, traceId: string): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, "Content-Type": "application/json", "Cache-Control": "no-store", "X-XO-Trace-Id": traceId }
  });
}
