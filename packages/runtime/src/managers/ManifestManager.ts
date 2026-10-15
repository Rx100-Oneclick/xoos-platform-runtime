import type { XOOSMicroappManifest } from "@xoos/contracts";
import { XOOSRuntimeError } from "../errors/XOOSRuntimeError";

export class ManifestManager {
  private readonly cache = new Map<string, Promise<XOOSMicroappManifest>>();

  resolve(url: string): Promise<XOOSMicroappManifest> {
    const existing = this.cache.get(url);
    if (existing) return existing;

    const request = fetch(url, { cache: "no-store" })
      .then(async (response) => {
        if (response.status === 401 || response.status === 403) {
          throw new XOOSRuntimeError(
            "MICROAPP_SIGNED_URL_EXPIRED",
            "Microapp manifest access URL is no longer valid."
          );
        }
        if (!response.ok) {
          throw new XOOSRuntimeError("MANIFEST_LOAD_FAILED", `Manifest request failed (${response.status}).`);
        }
        const manifest = (await response.json()) as XOOSMicroappManifest;
        this.validate(manifest);
        return manifest;
      })
      .catch((error) => {
        this.cache.delete(url);
        if (error instanceof XOOSRuntimeError) throw error;
        throw new XOOSRuntimeError("MANIFEST_LOAD_FAILED", "Unable to load Microapp manifest.", error);
      });

    this.cache.set(url, request);
    return request;
  }

  clear(): void {
    this.cache.clear();
  }

  private validate(manifest: XOOSMicroappManifest): void {
    const integrity = manifest.integrity;
    const integrityInvalid =
      integrity !== undefined &&
      (integrity.algorithm !== "sha256" || !/^[0-9a-f]{64}$/i.test(integrity.value));

    if (
      manifest.schemaVersion !== "1" ||
      !manifest.microappKey ||
      !manifest.version ||
      !manifest.elementName ||
      !manifest.entry ||
      (manifest.deliveryType !== undefined && manifest.deliveryType !== "native_esm") ||
      integrityInvalid
    ) {
      throw new XOOSRuntimeError("MANIFEST_INVALID", "Microapp manifest is invalid.");
    }
  }
}
