import { HttpError } from "./auth";
import type { CapabilityContext } from "./capabilities";

type XOApplicationAccess = "owned" | "consumer";

interface XOListInput {
  limit?: number;
  offset?: number;
  access?: XOApplicationAccess;
}

interface ParsedXOListInput {
  limit: number;
  offset: number;
  access?: XOApplicationAccess;
}

function normalizeInteger(
  value: unknown,
  fallback: number,
  min: number,
  max: number
): number {
  if (value === undefined || value === null || value === "") return fallback;
  const parsed = typeof value === "number" ? value : Number(value);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw new HttpError(
      400,
      "CAPABILITY_INPUT_INVALID",
      `Expected an integer between ${min} and ${max}.`
    );
  }
  return parsed;
}

function normalizeApplicationAccess(value: unknown): XOApplicationAccess | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string") {
    throw new HttpError(
      400,
      "CAPABILITY_INPUT_INVALID",
      "Application access filter must be 'owned' or 'consumer'."
    );
  }

  const normalized = value.trim().toLowerCase();
  if (normalized === "owned" || normalized === "consumer") {
    return normalized;
  }

  throw new HttpError(
    400,
    "CAPABILITY_INPUT_INVALID",
    "Application access filter must be 'owned' or 'consumer'."
  );
}

function parseListInput(input: unknown): ParsedXOListInput {
  if (input === undefined || input === null) {
    return { limit: 50, offset: 0 };
  }

  if (typeof input !== "object" || Array.isArray(input)) {
    throw new HttpError(
      400,
      "CAPABILITY_INPUT_INVALID",
      "Capability input must be an object."
    );
  }

  const value = input as Record<string, unknown>;
  return {
    limit: normalizeInteger(value.limit, 50, 1, 100),
    offset: normalizeInteger(value.offset, 0, 0, 100000),
    access: normalizeApplicationAccess(value.access)
  };
}

export async function proxyXOAuthList(
  context: CapabilityContext,
  functionName: "xo-applications" | "xo-organization-members",
  input: unknown
): Promise<unknown> {
  const { limit, offset, access } = parseListInput(input);
  const url = new URL(
    `${context.xoAuthFunctionsBaseUrl.replace(/\/+$/, "")}/${functionName}`
  );
  url.searchParams.set("limit", String(limit));
  url.searchParams.set("offset", String(offset));

  // Only the applications resource supports access-mode filtering. Keeping this
  // explicit prevents unrelated XO Auth list capabilities from receiving an
  // unsupported query parameter.
  if (functionName === "xo-applications" && access) {
    url.searchParams.set("access", access);
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15_000);

  try {
    const response = await fetch(url, {
      method: "GET",
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${context.identity.accessToken}`,
        "X-Request-Id": context.traceId
      }
    });

    const text = await response.text();
    let body: any = null;

    if (text) {
      try {
        body = JSON.parse(text);
      } catch {
        throw new HttpError(
          502,
          "XO_AUTH_RESPONSE_INVALID",
          "XO Auth returned an invalid response."
        );
      }
    }

    if (!response.ok) {
      const code =
        typeof body?.error === "string"
          ? body.error
          : `XO_AUTH_HTTP_${response.status}`;

      const message =
        typeof body?.error_description === "string"
          ? body.error_description
          : `XO Auth request failed (${response.status}).`;

      throw new HttpError(response.status, code, message);
    }

    return body;
  } catch (error) {
    if (error instanceof HttpError) throw error;

    if (error instanceof DOMException && error.name === "AbortError") {
      throw new HttpError(
        504,
        "XO_AUTH_TIMEOUT",
        "XO Auth request timed out."
      );
    }

    throw new HttpError(
      502,
      "XO_AUTH_UNAVAILABLE",
      "XO Auth resource API is unavailable."
    );
  } finally {
    clearTimeout(timeout);
  }
}

interface XOOrganizationMemberUpdateInput {
  memberId?: unknown;
  roleId?: unknown;
  status?: unknown;
  activationDetails?: unknown;
  expiryDetails?: unknown;
}

function parseOrganizationMemberUpdateInput(input: unknown): Record<string, unknown> {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new HttpError(
      400,
      "CAPABILITY_INPUT_INVALID",
      "Organization-member update input must be an object."
    );
  }

  const value = input as XOOrganizationMemberUpdateInput;
  if (typeof value.memberId !== "string" || !value.memberId.trim()) {
    throw new HttpError(
      400,
      "CAPABILITY_INPUT_INVALID",
      "memberId is required."
    );
  }

  const payload: Record<string, unknown> = {
    memberId: value.memberId.trim()
  };

  if (Object.prototype.hasOwnProperty.call(value, "roleId")) {
    payload.roleId = value.roleId;
  }
  if (Object.prototype.hasOwnProperty.call(value, "status")) {
    payload.status = value.status;
  }
  if (Object.prototype.hasOwnProperty.call(value, "activationDetails")) {
    payload.activationDetails = value.activationDetails;
  }
  if (Object.prototype.hasOwnProperty.call(value, "expiryDetails")) {
    payload.expiryDetails = value.expiryDetails;
  }

  if (Object.keys(payload).length === 1) {
    throw new HttpError(
      400,
      "CAPABILITY_INPUT_INVALID",
      "At least one organization-member field must be supplied."
    );
  }

  return payload;
}

export async function proxyXOAuthOrganizationMemberUpdate(
  context: CapabilityContext,
  input: unknown
): Promise<unknown> {
  const payload = parseOrganizationMemberUpdateInput(input);
  const url = new URL(
    `${context.xoAuthFunctionsBaseUrl.replace(/\/+$/, "")}/xo-organization-members`
  );

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15_000);

  try {
    const response = await fetch(url, {
      method: "PATCH",
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        Authorization: `Bearer ${context.identity.accessToken}`,
        "X-Request-Id": context.traceId
      },
      body: JSON.stringify(payload)
    });

    const text = await response.text();
    let body: any = null;

    if (text) {
      try {
        body = JSON.parse(text);
      } catch {
        throw new HttpError(
          502,
          "XO_AUTH_RESPONSE_INVALID",
          "XO Auth returned an invalid response."
        );
      }
    }

    if (!response.ok) {
      const code =
        typeof body?.error === "string"
          ? body.error
          : `XO_AUTH_HTTP_${response.status}`;

      const message =
        typeof body?.error_description === "string"
          ? body.error_description
          : `XO Auth request failed (${response.status}).`;

      throw new HttpError(response.status, code, message);
    }

    return body;
  } catch (error) {
    if (error instanceof HttpError) throw error;

    if (error instanceof DOMException && error.name === "AbortError") {
      throw new HttpError(
        504,
        "XO_AUTH_TIMEOUT",
        "XO Auth request timed out."
      );
    }

    throw new HttpError(
      502,
      "XO_AUTH_UNAVAILABLE",
      "XO Auth resource API is unavailable."
    );
  } finally {
    clearTimeout(timeout);
  }
}
