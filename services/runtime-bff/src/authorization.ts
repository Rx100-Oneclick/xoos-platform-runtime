import type { SupabaseClient } from "@supabase/supabase-js";
import { HttpError } from "./auth";

export type MicroappSource = "XOOS" | "CLIENT";

export interface AuthorizedMicroapp {
  source: MicroappSource;
  microappKey: string;
  permissions: string[];
}

export interface EffectiveAuthorization {
  roles: string[];
  microapps: AuthorizedMicroapp[];
}

export async function resolveApplicationAuthorization(
  servicesDb: SupabaseClient,
  input: {
    userId: string;
    tenantId: string;
    applicationId: string;
  }
): Promise<EffectiveAuthorization> {
  const { data, error } = await servicesDb.rpc("resolve_application_authorization", {
    p_user_id: input.userId,
    p_tenant_id: input.tenantId,
    p_application_id: input.applicationId
  });

  if (error) {
    console.error("Services authorization RPC failed", {
      applicationId: input.applicationId,
      code: error.code,
      message: error.message
    });
    throw new HttpError(
      502,
      "AUTHORIZATION_RESOLUTION_FAILED",
      "Unable to resolve application authorization."
    );
  }

  return normalizeAuthorization(data);
}

export function findAuthorizedMicroapp(
  authorization: EffectiveAuthorization,
  microappKey: string,
  source?: MicroappSource
): AuthorizedMicroapp | undefined {
  const key = microappKey.trim();
  return authorization.microapps.find(
    (item) => item.microappKey === key && (!source || item.source === source)
  );
}

export function hasMicroappPermission(
  authorization: EffectiveAuthorization,
  microappKey: string,
  action: string,
  source?: MicroappSource
): boolean {
  const item = findAuthorizedMicroapp(authorization, microappKey, source);
  if (!item) return false;
  const normalized = action.trim().toUpperCase();
  return item.permissions.includes(normalized);
}

function normalizeAuthorization(value: unknown): EffectiveAuthorization {
  if (!isRecord(value)) {
    throw new HttpError(
      502,
      "AUTHORIZATION_RESPONSE_INVALID",
      "Services returned an invalid authorization response."
    );
  }

  const roles = Array.isArray(value.roles)
    ? [...new Set(value.roles.filter(isNonEmptyString).map((role) => role.trim()))].sort()
    : [];

  const microapps: AuthorizedMicroapp[] = [];
  if (Array.isArray(value.microapps)) {
    for (const raw of value.microapps) {
      if (!isRecord(raw) || !isNonEmptyString(raw.microappKey) || !isNonEmptyString(raw.source)) {
        continue;
      }

      const source = raw.source.trim().toUpperCase();
      if (source !== "XOOS" && source !== "CLIENT") continue;

      const permissions = Array.isArray(raw.permissions)
        ? [...new Set(
            raw.permissions
              .filter(isNonEmptyString)
              .map((permission) => permission.trim().toUpperCase())
          )].sort()
        : [];

      microapps.push({
        source,
        microappKey: raw.microappKey.trim(),
        permissions
      });
    }
  }

  microapps.sort((a, b) => {
    const sourceOrder = a.source.localeCompare(b.source);
    return sourceOrder !== 0 ? sourceOrder : a.microappKey.localeCompare(b.microappKey);
  });

  return { roles, microapps };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}
