import type {
  XOOSFeedMicroapp,
  XOOSMicroappArtifactAccess
} from "@xoos/contracts";
import { describe, expect, it } from "vitest";
import { XOOSRuntime } from "./XOOSRuntime";
import { XOOSRuntimeError } from "./errors/XOOSRuntimeError";

const HASH = `sha256:${"a".repeat(64)}`;

const feedEntry: XOOSFeedMicroapp = {
  microappKey: "application-mgmt",
  displayName: "Application Management",
  elementName: "xoos-application-management",
  deliveryType: "native_esm",
  version: "1.0.12",
  integrity: HASH,
  contractVersion: "1",
  minimumRuntimeVersion: "1.0.0"
};

const artifactAccess: XOOSMicroappArtifactAccess = {
  microappKey: "application-mgmt",
  version: "1.0.12",
  manifestUrl: "https://storage.example/manifest",
  entryUrl: "https://storage.example/entry",
  integrity: HASH,
  expiresIn: 300
};

type ArtifactValidator = {
  validateArtifactAccess(
    feedEntry: XOOSFeedMicroapp,
    artifacts: XOOSMicroappArtifactAccess
  ): void;
};

function validator(): ArtifactValidator {
  const runtime = new XOOSRuntime({
    clientId: "client-test",
    apiBaseUrl: "https://runtime.example",
    getAccessToken: async () => "token"
  });

  return runtime as unknown as ArtifactValidator;
}

function expectRuntimeErrorCode(action: () => void, expectedCode: string): void {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(XOOSRuntimeError);
    expect((error as XOOSRuntimeError).code).toBe(expectedCode);
    return;
  }

  throw new Error(`Expected XOOSRuntimeError '${expectedCode}'.`);
}

describe("XOOSRuntime artifact access validation", () => {
  it("accepts matching artifact access metadata", () => {
    expect(() =>
      validator().validateArtifactAccess(feedEntry, artifactAccess)
    ).not.toThrow();
  });

  it("rejects a Microapp key mismatch", () => {
    expectRuntimeErrorCode(
      () =>
        validator().validateArtifactAccess(feedEntry, {
          ...artifactAccess,
          microappKey: "different-app"
        }),
      "MICROAPP_ARTIFACT_MISMATCH"
    );
  });

  it("rejects a deployment version mismatch", () => {
    expectRuntimeErrorCode(
      () =>
        validator().validateArtifactAccess(feedEntry, {
          ...artifactAccess,
          version: "9.9.9"
        }),
      "MICROAPP_ARTIFACT_VERSION_MISMATCH"
    );
  });

  it("rejects an integrity mismatch", () => {
    expectRuntimeErrorCode(
      () =>
        validator().validateArtifactAccess(feedEntry, {
          ...artifactAccess,
          integrity: `sha256:${"b".repeat(64)}`
        }),
      "MICROAPP_ARTIFACT_INTEGRITY_MISMATCH"
    );
  });
});
