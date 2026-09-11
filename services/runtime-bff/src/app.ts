import type { XOOSRuntimeContext } from "@xoos/contracts";
import { authenticateRequest, HttpError } from "./auth";
import { executeCapability } from "./capabilities";
import type { RuntimeBffConfig } from "./config";
import { issueDataAccessSession } from "./data";
import { buildRuntimeFeed, assertClientBinding } from "./feed";
import { buildCorsHeaders, validateClientOrigin } from "./origin";
import { createRegistryClient } from "./supabase";

export function createRuntimeBffHandler(config: RuntimeBffConfig) {
  const db = createRegistryClient(config);

  return async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    const origin = request.headers.get("origin");
    const queryClientId = url.searchParams.get("client_id")?.trim() ?? "";
    const traceId = request.headers.get("x-xo-trace-id")?.trim() || crypto.randomUUID();

    if (!queryClientId) {
      return jsonWithoutCors(
        {
          error: {
            code: "CLIENT_ID_MISSING",
            message: "client_id query parameter is required."
          },
          traceId
        },
        400,
        traceId
      );
    }

    let clientRegistration: { clientId: string; environment: string };
    try {
      clientRegistration = await validateClientOrigin(db, queryClientId, origin);
    } catch (error) {
      const failure = error instanceof HttpError
        ? error
        : new HttpError(500, "ORIGIN_VALIDATION_FAILED", "Unable to validate client origin.");
      if (!(error instanceof HttpError)) console.error("runtime origin validation failed", { traceId, error });
      return jsonWithoutCors(
        { error: { code: failure.code, message: failure.message }, traceId },
        failure.status,
        traceId
      );
    }

    const cors = buildCorsHeaders(origin);
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }

    try {
      const headerClientId = request.headers.get("x-xo-client-id")?.trim() ?? "";
      if (!headerClientId) {
        throw new HttpError(400, "CLIENT_ID_MISSING", "X-XO-Client-Id header is required.");
      }
      if (headerClientId !== queryClientId) {
        throw new HttpError(
          400,
          "CLIENT_ID_MISMATCH",
          "client_id query parameter and X-XO-Client-Id header must match."
        );
      }

      const identity = await authenticateRequest(request, config);
      assertClientBinding(identity, headerClientId);

      const path = normalizePath(url.pathname);

      if (request.method === "GET" && path === "/v1/runtime/context") {
        const body: XOOSRuntimeContext = {
          user: { id: identity.userId },
          tenant: { id: identity.tenantId },
          client: { id: headerClientId },
          runtime: { minimumVersion: config.minimumRuntimeVersion },
          scopes: identity.scopes
        };
        return json(body, 200, cors, traceId);
      }

      if (request.method === "GET" && path === "/v1/runtime/feed") {
        const feed = await buildRuntimeFeed(
          db,
          config,
          identity,
          headerClientId,
          clientRegistration.environment
        );
        return json(feed, 200, cors, traceId);
      }

      if (request.method === "POST" && path === "/v1/data/token") {
        const body = await safeJson(request);
        const projectKey = typeof body.projectKey === "string" ? body.projectKey : "";
        const session = await issueDataAccessSession(
          db,
          config,
          identity,
          headerClientId,
          clientRegistration.environment,
          projectKey
        );
        return json(session, 200, cors, traceId);
      }

      if (request.method === "POST" && path.startsWith("/v1/capabilities/")) {
        const capability = decodeURIComponent(path.slice("/v1/capabilities/".length));
        const body = await safeJson(request);
        const result = await executeCapability(
          capability,
          {
            identity,
            clientId: headerClientId,
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

function json(body: unknown, status: number, cors: HeadersInit, traceId: string): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...cors,
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "X-XO-Trace-Id": traceId
    }
  });
}

function jsonWithoutCors(body: unknown, status: number, traceId: string): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "X-XO-Trace-Id": traceId
    }
  });
}
