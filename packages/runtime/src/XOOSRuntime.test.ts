import type {
  XOOSFeedMicroapp,
  XOOSMicroappArtifactAccess
} from "@xoos/contracts";
import { describe, expect, it } from "vitest";
import { XOOSRuntime } from "./XOOSRuntime";

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

describe("XOOSRuntime artifact access validation", () => {
  it("accepts matching artifact access metadata", () => {
    expect(() =>
      validator().validateArtifactAccess(feedEntry, artifactAccess)
    ).not.toThrow();
  });

  it("rejects a Microapp key mismatch", () => {
    expect(() =>
      validator().validateArtifactAccess(feedEntry, {
        ...artifactAccess,
        microappKey: "different-app"
      })
    ).toThrowError(
      expect.objectContaining({
        code: "MICROAPP_ARTIFACT_MISMATCH"
      })
    );
  });

  it("rejects a deployment version mismatch", () => {
    expect(() =>
      validator().validateArtifactAccess(feedEntry, {
        ...artifactAccess,
        version: "9.9.9"
      })
    ).toThrowError(
      expect.objectContaining({
        code: "MICROAPP_ARTIFACT_VERSION_MISMATCH"
      })
    );
  });

  it("rejects an integrity mismatch", () => {
    expect(() =>
      validator().validateArtifactAccess(feedEntry, {
        ...artifactAccess,
        integrity: `sha256:${"b".repeat(64)}`
      })
    ).toThrowError(
      expect.objectContaining({
        code: "MICROAPP_ARTIFACT_INTEGRITY_MISMATCH"
      })
    );
  });
});
