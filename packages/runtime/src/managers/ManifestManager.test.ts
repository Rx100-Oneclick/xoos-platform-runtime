import { afterEach, describe, expect, it, vi } from "vitest";
import { XOOSRuntimeError } from "../errors/XOOSRuntimeError";
import { ManifestManager } from "./ManifestManager";

describe("ManifestManager", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("treats Supabase signed URL 400 responses as expired access", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("expired", { status: 400 }))
    );

    const manager = new ManifestManager();

    await expect(
      manager.resolve("https://storage.example/manifest", "app@1.0.0")
    ).rejects.toMatchObject({
      code: "MICROAPP_SIGNED_URL_EXPIRED"
    } satisfies Partial<XOOSRuntimeError>);
  });

  it("caches a manifest by release identity instead of signed URL", async () => {
    const fetchMock = vi.fn(async () =>
      new Response(
        JSON.stringify({
          schemaVersion: "1",
          microappKey: "application-mgmt",
          version: "1.0.0",
          elementName: "xoos-application-management",
          entry: "xoos-microapp.js",
          deliveryType: "native_esm",
          contractVersion: "1",
          minimumRuntimeVersion: "1.0.0"
        }),
        {
          status: 200,
          headers: { "Content-Type": "application/json" }
        }
      )
    );

    vi.stubGlobal("fetch", fetchMock);

    const manager = new ManifestManager();
    const cacheKey = "application-mgmt@1.0.0@sha256:test";

    await manager.resolve("https://storage.example/first", cacheKey);
    await manager.resolve("https://storage.example/second", cacheKey);

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
