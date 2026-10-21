export interface RuntimeBffConfig {
  jwksUrl: string;
  issuer: string;
  audience: string;
  xoAuthFunctionsBaseUrl: string;
  supabaseUrl: string;
  supabaseSecretKey: string;
  servicesUrl: string;
  servicesSecretKey: string;
  runtimeVersion: string;
  minimumRuntimeVersion: string;
  microappSignedUrlTtlSeconds: number;
  authorizationSnapshotTtlSeconds: number;
  dataJwtPrivateJwk?: string;
  dataJwtIssuer?: string;
  dataJwtAudience?: string;
  dataJwtTtlSeconds?: number;
}

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`Missing environment variable: ${name}`);
  return value;
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

export function loadConfig(): RuntimeBffConfig {
  return {
    jwksUrl: required("XO_AUTH_JWKS_URL"),
    issuer: required("XO_AUTH_ISSUER"),
    audience: process.env.XO_AUTH_AUDIENCE?.trim() || "xo-api",
    xoAuthFunctionsBaseUrl: required("XO_AUTH_FUNCTIONS_BASE_URL").replace(/\/+$/, ""),
    supabaseUrl: required("SUPABASE_URL"),
    supabaseSecretKey: required("SUPABASE_SECRET_KEY"),
    servicesUrl: required("SERVICES_URL"),
    servicesSecretKey: required("SERVICES_SECRET_KEY"),
    runtimeVersion: process.env.XOOS_RUNTIME_VERSION?.trim() || "1.2.0",
    minimumRuntimeVersion: process.env.XOOS_MINIMUM_RUNTIME_VERSION?.trim() || "1.0.0",
    microappSignedUrlTtlSeconds: boundedInteger(
      process.env.XOOS_MICROAPP_SIGNED_URL_TTL_SECONDS,
      300,
      30,
      300
    ),
    authorizationSnapshotTtlSeconds: boundedInteger(
      process.env.XOOS_AUTHORIZATION_SNAPSHOT_TTL_SECONDS,
      45,
      10,
      120
    ),
    dataJwtPrivateJwk: process.env.XOOS_DATA_JWT_PRIVATE_JWK?.trim(),
    dataJwtIssuer: process.env.XOOS_DATA_JWT_ISSUER?.trim() || "xoos-data",
    dataJwtAudience: process.env.XOOS_DATA_JWT_AUDIENCE?.trim() || "authenticated",
    dataJwtTtlSeconds: Number.parseInt(process.env.XOOS_DATA_JWT_TTL_SECONDS || "600", 10)
  };
}
