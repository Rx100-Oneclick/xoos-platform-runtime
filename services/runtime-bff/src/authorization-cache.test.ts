import { describe, expect, it, vi } from "vitest";
import { AuthorizationSnapshotCache } from "./authorization-cache";

const key = {
  sessionId: "session-1",
  userId: "user-1",
  tenantId: "tenant-1",
  applicationId: "application-1"
};

const authorization = {
  roles: ["APP_ADMIN"],
  microapps: [
    {
      source: "XOOS" as const,
      microappKey: "approval-inbox",
      permissions: ["READ"]
    }
  ]
};

describe("AuthorizationSnapshotCache", () => {
  it("reuses a snapshot within the TTL", async () => {
    const cache = new AuthorizationSnapshotCache(60);
    const resolver = vi.fn(async () => authorization);

    expect(await cache.getOrResolve(key, resolver)).toEqual(authorization);
    expect(await cache.getOrResolve(key, resolver)).toEqual(authorization);
    expect(resolver).toHaveBeenCalledTimes(1);
  });
});
