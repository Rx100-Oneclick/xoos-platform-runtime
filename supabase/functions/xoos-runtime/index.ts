import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createRuntimeBffHandler } from "../../../services/runtime-bff/src/app.ts";
import type { RuntimeBffConfig } from "../../../services/runtime-bff/src/config.ts";

function required(name: string): string {
  const value = Deno.env.get(name)?.trim();
  if (!value) throw new Error(`Missing environment variable: ${name}`);
  return value;
}

function optional(name: string): string | undefined {
  return Deno.env.get(name)?.trim() || undefined;
}

function boundedInteger(
  value: string | undefined,
  fallback: number,
  minimum: number,
  maximum: number
): number {
  const parsed = value ? Number.parseInt(value, 10) : fallback;
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(Math.max(Math.floor(parsed), minimum), maximum);
}

function getDefaultSupabaseSecretKey(): string {
  const raw = required("SUPABASE_SECRET_KEYS");
  let parsed: Record<string, string>;

  try {
    parsed = JSON.parse(raw) as Record<string, string>;
  } catch {
    throw new Error("SUPABASE_SECRET_KEYS is not valid JSON.");
  }

  const key = parsed.default?.trim();
  if (!key) {
    throw new Error(
      "SUPABASE_SECRET_KEYS does not contain a default secret key."
    );
  }

  return key;
}

const config: RuntimeBffConfig = {
  jwksUrl: required("XO_AUTH_JWKS_URL"),
  issuer: required("XO_AUTH_ISSUER"),
  audience: Deno.env.get("XO_AUTH_AUDIENCE")?.trim() || "xo-api",
  xoAuthFunctionsBaseUrl: required("XO_AUTH_FUNCTIONS_BASE_URL").replace(/\/+$/, ""),
  supabaseUrl: required("SUPABASE_URL"),
  supabaseSecretKey: getDefaultSupabaseSecretKey(),
  servicesUrl: required("SERVICES_URL"),
  servicesSecretKey: required("SERVICES_SECRET_KEY"),
  runtimeVersion: Deno.env.get("XOOS_RUNTIME_VERSION")?.trim() || "1.2.0",
  minimumRuntimeVersion:
    Deno.env.get("XOOS_MINIMUM_RUNTIME_VERSION")?.trim() || "1.0.0",
  microappSignedUrlTtlSeconds: boundedInteger(
    optional("XOOS_MICROAPP_SIGNED_URL_TTL_SECONDS"),
    300,
    30,
    300
  ),
  authorizationSnapshotTtlSeconds: boundedInteger(
    optional("XOOS_AUTHORIZATION_SNAPSHOT_TTL_SECONDS"),
    45,
    10,
    120
  ),
  dataJwtPrivateJwk: optional("XOOS_DATA_JWT_PRIVATE_JWK"),
  dataJwtIssuer: optional("XOOS_DATA_JWT_ISSUER") || "xoos-data",
  dataJwtAudience: optional("XOOS_DATA_JWT_AUDIENCE") || "authenticated",
  dataJwtTtlSeconds: Number.parseInt(
    optional("XOOS_DATA_JWT_TTL_SECONDS") || "600",
    10
  )
};

const handler = createRuntimeBffHandler(config);

export default {
  fetch(request: Request): Promise<Response> {
    return handler(request);
  }
};
