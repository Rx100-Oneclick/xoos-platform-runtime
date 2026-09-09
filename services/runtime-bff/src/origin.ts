import type { SupabaseClient } from "@supabase/supabase-js";
import { HttpError } from "./auth";

export interface RuntimeClientRegistration {
  clientId: string;
  environment: string;
}

export async function validateClientOrigin(
  db: SupabaseClient,
  clientId: string,
  origin: string | null
): Promise<RuntimeClientRegistration> {
  const { data: client, error: clientError } = await db
    .from("oauth_clients")
    .select("client_id,status,environment")
    .eq("client_id", clientId)
    .maybeSingle();

  if (clientError) {
    console.error("runtime client lookup failed", {
      clientId,
      error: clientError.message
    });
    throw new HttpError(500, "CLIENT_LOOKUP_FAILED", "Unable to validate XOOS client.");
  }

  if (!client || client.status !== "active") {
    throw new HttpError(403, "CLIENT_NOT_ACTIVE", "XOOS client is not active.");
  }

  // Requests without an Origin header are non-browser/server-to-server requests.
  // They are still authenticated and client-bound later in the request pipeline.
  if (!origin) {
    return { clientId: client.client_id, environment: client.environment };
  }

  const { data: allowedOrigin, error: originError } = await db
    .from("oauth_allowed_origins")
    .select("uuid")
    .eq("client_id", clientId)
    .eq("origin", origin)
    .eq("environment", client.environment)
    .eq("validation_status", "valid")
    .maybeSingle();

  if (originError) {
    console.error("runtime origin lookup failed", {
      clientId,
      origin,
      error: originError.message
    });
    throw new HttpError(500, "ORIGIN_LOOKUP_FAILED", "Unable to validate client origin.");
  }

  if (!allowedOrigin) {
    throw new HttpError(
      403,
      "ORIGIN_NOT_ALLOWED",
      "Request origin is not registered for this XOOS client."
    );
  }

  return { clientId: client.client_id, environment: client.environment };
}

export function buildCorsHeaders(origin: string | null): HeadersInit {
  const headers: Record<string, string> = {
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": [
      "authorization",
      "content-type",
      "x-xo-client-id",
      "x-xo-trace-id",
      "apikey",
      "x-client-info"
    ].join(","),
    "Access-Control-Expose-Headers": "x-xo-trace-id",
    "Access-Control-Max-Age": "300",
    Vary: "Origin"
  };

  if (origin) headers["Access-Control-Allow-Origin"] = origin;
  return headers;
}
