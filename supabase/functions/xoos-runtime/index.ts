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

function getDefaultSupabaseSecretKey(): string {
  const raw = required("SUPABASE_SECRET_KEYS");
  let parsed: Record<string, string>;
  try {
    parsed = JSON.parse(raw) as Record<string, string>;
  } catch {
    throw new Error("SUPABASE_SECRET_KEYS is not valid JSON.");
  }

  const key = parsed.default?.trim();
  if (!key) throw new Error("SUPABASE_SECRET_KEYS does not contain a default secret key.");
  return key;
}

const config: RuntimeBffConfig = {
  jwksUrl: required("XO_AUTH_JWKS_URL"),
  issuer: required("XO_AUTH_ISSUER"),
  audience: Deno.env.get("XO_AUTH_AUDIENCE")?.trim() || "xo-api",
  supabaseUrl: required("SUPABASE_URL"),
  supabaseSecretKey: getDefaultSupabaseSecretKey(),
  runtimeVersion: Deno.env.get("XOOS_RUNTIME_VERSION")?.trim() || "0.1.0",
  minimumRuntimeVersion:
    Deno.env.get("XOOS_MINIMUM_RUNTIME_VERSION")?.trim() || "0.1.0",
  dataJwtPrivateJwk: optional("XOOS_DATA_JWT_PRIVATE_JWK"),
  dataJwtIssuer: optional("XOOS_DATA_JWT_ISSUER") || "xoos-data",
  dataJwtAudience: optional("XOOS_DATA_JWT_AUDIENCE") || "authenticated",
  dataJwtTtlSeconds: Number.parseInt(optional("XOOS_DATA_JWT_TTL_SECONDS") || "600", 10)
};

const handler = createRuntimeBffHandler(config);

export default {
  fetch(request: Request): Promise<Response> {
    return handler(request);
  }
};
