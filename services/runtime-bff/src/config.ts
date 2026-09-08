export interface RuntimeBffConfig {
  jwksUrl: string;
  issuer: string;
  audience: string;
  supabaseUrl: string;
  supabaseSecretKey: string;
  runtimeVersion: string;
  minimumRuntimeVersion: string;
  environment: string;
  allowedOrigins: string[];
}

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`Missing environment variable: ${name}`);
  return value;
}

export function loadConfig(): RuntimeBffConfig {
  return {
    jwksUrl: required("XO_AUTH_JWKS_URL"),
    issuer: required("XO_AUTH_ISSUER"),
    audience: process.env.XO_AUTH_AUDIENCE?.trim() || "xo-api",
    supabaseUrl: required("SUPABASE_URL"),
    supabaseSecretKey: required("SUPABASE_SECRET_KEY"),
    runtimeVersion: process.env.XOOS_RUNTIME_VERSION?.trim() || "0.1.0",
    minimumRuntimeVersion: process.env.XOOS_MINIMUM_RUNTIME_VERSION?.trim() || "0.1.0",
    environment: process.env.XOOS_RUNTIME_ENVIRONMENT?.trim() || "development",
    allowedOrigins: (process.env.XOOS_ALLOWED_ORIGINS || "")
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean)
  };
}
