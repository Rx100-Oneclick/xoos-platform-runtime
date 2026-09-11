import type { SupabaseClient } from "@supabase/supabase-js";
import { importJWK, SignJWT, type JWK, type KeyLike } from "jose";
import type { XOOSDataAccessSession, XOOSDataSourceConfig } from "@xoos/contracts";
import type { RuntimeBffConfig } from "./config";
import { HttpError, type XOIdentity } from "./auth";

let signingKeyCache: { raw: string; key: KeyLike | Uint8Array; jwk: JWK } | null = null;

export async function issueDataAccessSession(
  db: SupabaseClient,
  config: RuntimeBffConfig,
  identity: XOIdentity,
  clientId: string,
  environment: string,
  projectKey: string
): Promise<XOOSDataAccessSession> {
  const key = projectKey.trim();
  if (!key) throw new HttpError(400, "DATA_PROJECT_KEY_REQUIRED", "projectKey is required.");

  const { data: source, error: sourceError } = await db
    .schema("xoos_control")
    .from("xoos_data_sources")
    .select("uuid,project_key,provider,supabase_url,publishable_key,environment,status")
    .eq("project_key", key)
    .eq("environment", environment)
    .eq("status", "active")
    .maybeSingle();

  if (sourceError) throw new HttpError(500, "DATA_SOURCE_LOOKUP_FAILED", sourceError.message);
  if (!source) throw new HttpError(404, "DATA_SOURCE_NOT_FOUND", `Data source '${key}' is not registered.`);
  if (source.provider !== "supabase") {
    throw new HttpError(400, "DATA_PROVIDER_UNSUPPORTED", `Unsupported data provider '${source.provider}'.`);
  }

  const { data: entitlement, error: entitlementError } = await db
    .schema("xoos_control")
    .from("xoos_client_data_source_entitlements")
    .select("uuid")
    .eq("client_id", clientId)
    .eq("data_source_id", source.uuid)
    .eq("environment", environment)
    .eq("is_enabled", true)
    .maybeSingle();

  if (entitlementError) throw new HttpError(500, "DATA_ENTITLEMENT_LOOKUP_FAILED", entitlementError.message);
  if (!entitlement) {
    throw new HttpError(403, "DATA_SOURCE_NOT_ENTITLED", `Client is not entitled to data source '${key}'.`);
  }

  const ttlSeconds = normalizeTtl(config.dataJwtTtlSeconds);
  const nowSeconds = Math.floor(Date.now() / 1000);
  const expiresAtSeconds = nowSeconds + ttlSeconds;
  const { key: signingKey, jwk } = await getSigningKey(config);
  const algorithm = jwk.alg || inferAlgorithm(jwk);

  const token = await new SignJWT({
    role: "authenticated",
    tenant_id: identity.tenantId,
    organization_id: identity.tenantId,
    xo_client_id: clientId,
    scope: identity.scopes.join(" ")
  })
    .setProtectedHeader({ alg: algorithm, typ: "JWT", kid: jwk.kid })
    .setSubject(identity.userId)
    .setIssuer(config.dataJwtIssuer || "xoos-data")
    .setAudience(config.dataJwtAudience || "authenticated")
    .setIssuedAt(nowSeconds)
    .setExpirationTime(expiresAtSeconds)
    .sign(signingKey);

  const dataSource: XOOSDataSourceConfig = {
    projectKey: source.project_key,
    provider: "supabase",
    supabaseUrl: source.supabase_url,
    publishableKey: source.publishable_key
  };

  return {
    accessToken: token,
    expiresAt: expiresAtSeconds * 1000,
    dataSource
  };
}

function normalizeTtl(value: number | undefined): number {
  if (!Number.isFinite(value)) return 600;
  return Math.min(Math.max(Math.floor(value!), 60), 900);
}

async function getSigningKey(
  config: RuntimeBffConfig
): Promise<{ key: KeyLike | Uint8Array; jwk: JWK }> {
  const raw = config.dataJwtPrivateJwk?.trim();
  if (!raw) {
    throw new HttpError(
      503,
      "DATA_TOKEN_SIGNING_NOT_CONFIGURED",
      "XOOS data token signing is not configured."
    );
  }

  if (signingKeyCache?.raw === raw) return signingKeyCache;

  let jwk: JWK;
  try {
    jwk = JSON.parse(raw) as JWK;
  } catch {
    throw new HttpError(500, "DATA_TOKEN_SIGNING_INVALID", "XOOS data private JWK is not valid JSON.");
  }

  if (!jwk.kty || !jwk.kid) {
    throw new HttpError(500, "DATA_TOKEN_SIGNING_INVALID", "XOOS data private JWK must contain kty and kid.");
  }

  try {
    const key = await importJWK(jwk, jwk.alg || inferAlgorithm(jwk));
    signingKeyCache = { raw, key, jwk };
    return signingKeyCache;
  } catch {
    throw new HttpError(500, "DATA_TOKEN_SIGNING_INVALID", "XOOS data private JWK could not be imported.");
  }
}

function inferAlgorithm(jwk: JWK): string {
  if (jwk.kty === "EC") return "ES256";
  if (jwk.kty === "RSA") return "RS256";
  throw new HttpError(500, "DATA_TOKEN_SIGNING_INVALID", `Unsupported signing key type '${jwk.kty}'.`);
}
