import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import type { RuntimeBffConfig } from "./config";

export interface XOIdentity {
  userId: string;
  tenantId: string | null;
  tokenClientId: string | null;
  role: string | null;
  scopes: string[];
  claims: JWTPayload;
}

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

export async function authenticateRequest(request: Request, config: RuntimeBffConfig): Promise<XOIdentity> {
  const header = request.headers.get("authorization") ?? "";
  if (!header.startsWith("Bearer ")) throw new HttpError(401, "AUTH_TOKEN_MISSING", "Bearer token is required.");

  const token = header.slice(7).trim();
  const jwks = jwksCache.get(config.jwksUrl) ?? createRemoteJWKSet(new URL(config.jwksUrl));
  jwksCache.set(config.jwksUrl, jwks);

  try {
    const { payload } = await jwtVerify(token, jwks, {
      issuer: config.issuer,
      audience: config.audience,
      algorithms: ["RS256"]
    });

    if (!payload.sub) throw new HttpError(401, "AUTH_SUBJECT_MISSING", "Token subject is missing.");
    const rawScopes = typeof payload.scope === "string" ? payload.scope.split(/\s+/).filter(Boolean) : [];
    return {
      userId: payload.sub,
      tenantId: typeof payload.tenant_id === "string" ? payload.tenant_id : null,
      tokenClientId: typeof payload.client_id === "string" ? payload.client_id : null,
      role: typeof payload.role === "string" ? payload.role : null,
      scopes: rawScopes,
      claims: payload
    };
  } catch (error) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(401, "AUTH_TOKEN_INVALID", "XO access token could not be verified.");
  }
}

export class HttpError extends Error {
  constructor(public readonly status: number, public readonly code: string, message: string) {
    super(message);
  }
}
