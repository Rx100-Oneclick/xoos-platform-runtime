import { XOOSRuntimeError } from "../errors/XOOSRuntimeError";

function parseSha256Integrity(integrity: string): string {
  const match = /^sha256:([0-9a-f]{64})$/i.exec(integrity.trim());
  const digest = match?.[1];

  if (!digest) {
    throw new XOOSRuntimeError(
      "MICROAPP_INTEGRITY_INVALID",
      "Microapp integrity must use sha256:<64-hex>."
    );
  }

  return digest.toLowerCase();
}

async function sha256Hex(bytes: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);

  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export class ModuleLoader {
  private readonly cache = new Map<string, Promise<unknown>>();

  async load(
    entryUrl: string,
    integrity: string,
    cacheKey?: string
  ): Promise<unknown> {
    const expectedHash = parseSha256Integrity(integrity);

    const stableKey =
      cacheKey ??
      `${expectedHash}:${entryUrl}`;

    const existing =
      this.cache.get(stableKey);

    if (existing) {
      return existing;
    }

    const request =
      this.fetchVerifyAndImport(
        entryUrl,
        expectedHash
      ).catch((error: unknown) => {
        /*
         * Failed loads must not remain cached.
         *
         * This allows a retry after:
         * - signed URL refresh
         * - transient network failure
         * - corrected deployment metadata
         */
        this.cache.delete(stableKey);

        if (
          error instanceof
          XOOSRuntimeError
        ) {
          throw error;
        }

        throw new XOOSRuntimeError(
          "MODULE_LOAD_FAILED",
          "Unable to load verified Microapp module.",
          error
        );
      });

    this.cache.set(
      stableKey,
      request
    );

    return request;
  }

  clear(): void {
    this.cache.clear();
  }

  private async fetchVerifyAndImport(
    entryUrl: string,
    expectedHash: string
  ): Promise<unknown> {
    let response: Response;

    /* =====================================================
     * Step 1
     * Download exact Microapp bytes
     * =================================================== */

    try {
      response =
        await fetch(
          entryUrl,
          {
            /*
             * Signed artifact responses must not be reused
             * from an intermediate browser cache.
             */
            cache: "no-store"
          }
        );
    } catch (error: unknown) {
      throw new XOOSRuntimeError(
        "MICROAPP_DOWNLOAD_FAILED",
        "Unable to download Microapp artifact.",
        error
      );
    }

    /* =====================================================
     * Step 2
     * Detect expired/invalid signed URL
     * =================================================== */

    if (
      response.status === 401 ||
      response.status === 403
    ) {
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

    /* =====================================================
     * Step 3
     * Read EXACT downloaded bytes
     * =================================================== */

    let bytes: ArrayBuffer;

    try {
      bytes =
        await response.arrayBuffer();
    } catch (error: unknown) {
      throw new XOOSRuntimeError(
        "MICROAPP_DOWNLOAD_FAILED",
        "Unable to read downloaded Microapp artifact.",
        error
      );
    }

    /* =====================================================
     * Step 4
     * SHA-256 verification
     * =================================================== */

    let actualHash: string;

    try {
      actualHash =
        await sha256Hex(bytes);
    } catch (error: unknown) {
      throw new XOOSRuntimeError(
        "MICROAPP_INTEGRITY_VERIFICATION_FAILED",
        "Unable to calculate Microapp artifact integrity.",
        error
      );
    }

    if (
      actualHash !==
      expectedHash
    ) {
      throw new XOOSRuntimeError(
        "MICROAPP_ARTIFACT_INTEGRITY_FAILED",
        "Microapp artifact integrity verification failed."
      );
    }

    /* =====================================================
     * Step 5
     *
     * Execute exactly the bytes that were verified.
     *
     * Do NOT import entryUrl directly after verification,
     * because that would perform another network request and
     * could execute different bytes.
     * =================================================== */

    let verifiedModuleUrl: string;

    try {
      verifiedModuleUrl =
        URL.createObjectURL(
          new Blob(
            [bytes],
            {
              type:
                "text/javascript"
            }
          )
        );
    } catch (error: unknown) {
      throw new XOOSRuntimeError(
        "MODULE_LOAD_FAILED",
        "Unable to prepare verified Microapp module.",
        error
      );
    }

    try {
      /*
       * @vite-ignore is required because the module URL
       * is created dynamically at runtime.
       */
      return await import(
        /* @vite-ignore */
        verifiedModuleUrl
      );
    } catch (error: unknown) {
      throw new XOOSRuntimeError(
        "MODULE_LOAD_FAILED",
        "Unable to execute verified Microapp module.",
        error
      );
    } finally {
      URL.revokeObjectURL(
        verifiedModuleUrl
      );
    }
  }
}