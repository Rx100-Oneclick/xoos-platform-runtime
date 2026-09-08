import type { XOOSMicroappManifest } from "@xoos/contracts";
import { XOOSRuntimeError } from "../errors/XOOSRuntimeError";

export class ManifestManager {
  private readonly cache = new Map<string, Promise<XOOSMicroappManifest>>();

  resolve(url: string): Promise<XOOSMicroappManifest> {
    const existing = this.cache.get(url);
    if (existing) return existing;

    const request = fetch(url)
      .then(async (response) => {
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

  private validate(manifest: XOOSMicroappManifest): void {
    if (
      manifest.schemaVersion !== "1" ||
      !manifest.microappKey ||
      !manifest.version ||
      !manifest.elementName ||
      !manifest.entry
    ) {
      throw new XOOSRuntimeError("MANIFEST_INVALID", "Microapp manifest is invalid.");
    }
  }
}
