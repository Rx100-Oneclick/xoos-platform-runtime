import { HttpError } from "./auth";
import type { CapabilityContext } from "./capabilities";

interface XOListInput {
  limit?: number;
  offset?: number;
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

function parseListInput(input: unknown): Required<XOListInput> {
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
    offset: normalizeInteger(value.offset, 0, 0, 100000)
  };
}

export async function proxyXOAuthList(
  context: CapabilityContext,
  functionName: "xo-applications" | "xo-organization-members",
  input: unknown
): Promise<unknown> {
  const { limit, offset } = parseListInput(input);
  const url = new URL(
    `${context.xoAuthFunctionsBaseUrl.replace(/\/+$/, "")}/${functionName}`
  );
  url.searchParams.set("limit", String(limit));
  url.searchParams.set("offset", String(offset));

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
