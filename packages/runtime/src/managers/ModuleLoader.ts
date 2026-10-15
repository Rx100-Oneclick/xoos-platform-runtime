import { XOOSRuntimeError } from "../errors/XOOSRuntimeError";

function parseSha256Integrity(integrity: string): string {
  const match = /^sha256:([0-9a-f]{64})$/i.exec(integrity.trim());
  if (!match) {
    throw new XOOSRuntimeError(
      "MICROAPP_INTEGRITY_INVALID",
      "Microapp integrity must use sha256:<64-hex>."
    );
  }
  return match[1].toLowerCase();
}

async function sha256Hex(bytes: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export class ModuleLoader {
  private readonly cache = new Map<string, Promise<unknown>>();

  async load(entryUrl: string, integrity: string, cacheKey?: string): Promise<unknown> {
    const expectedHash = parseSha256Integrity(integrity);
    const stableKey = cacheKey ?? `${expectedHash}:${entryUrl}`;
    const existing = this.cache.get(stableKey);
    if (existing) return existing;

    const request = this.fetchVerifyAndImport(entryUrl, expectedHash).catch((error) => {
      this.cache.delete(stableKey);
      if (error instanceof XOOSRuntimeError) throw error;
      throw new XOOSRuntimeError(
        "MODULE_LOAD_FAILED",
        "Unable to load verified Microapp module.",
        error
      );
    });

    this.cache.set(stableKey, request);
    return request;
  }

  clear(): void {
    this.cache.clear();
  }

  private async fetchVerifyAndImport(entryUrl: string, expectedHash: string): Promise<unknown> {
    let response: Response;
    try {
      response = await fetch(entryUrl, { cache: "no-store" });
    } catch (error) {
      throw new XOOSRuntimeError(
        "MICROAPP_DOWNLOAD_FAILED",
        "Unable to download Microapp artifact.",
        error
      );
    }

    if (response.status === 401 || response.status === 403) {
      throw new XOOSRuntimeError(
        "MICROAPP_SIGNED_URL_EXPIRED",
        "Microapp artifact access URL is no longer valid."
      );
    }

    if (!response.ok) {
      throw new XOOSRuntimeError(
        "MICROAPP_DOWNLOAD_FAILED",
        `Microapp download failed (${response.status}).`
      );
    }

    const bytes = await response.arrayBuffer();
    const actualHash = await sha256Hex(bytes);

    if (actualHash !== expectedHash) {
      throw new XOOSRuntimeError(
        "MICROAPP_ARTIFACT_INTEGRITY_FAILED",
        "Microapp artifact integrity verification failed."
      );
    }

    const verifiedModuleUrl = URL.createObjectURL(
      new Blob([bytes], { type: "text/javascript" })
    );

    try {
      return await import(/* @vite-ignore */ verifiedModuleUrl);
    } catch (error) {
      throw new XOOSRuntimeError(
        "MODULE_LOAD_FAILED",
        "Unable to execute verified Microapp module.",
        error
      );
    } finally {
      URL.revokeObjectURL(verifiedModuleUrl);
    }
  }
}
