import type { EffectiveAuthorization } from "./authorization";

export interface AuthorizationSnapshotKey {
  sessionId: string;
  userId: string;
  tenantId: string;
  applicationId: string;
}

type Snapshot = {
  expiresAt: number;
  authorization: EffectiveAuthorization;
};

export class AuthorizationSnapshotCache {
  private readonly snapshots = new Map<string, Snapshot>();
  private readonly inFlight = new Map<string, Promise<EffectiveAuthorization>>();

  constructor(private readonly ttlSeconds: number) {}

  get(key: AuthorizationSnapshotKey): EffectiveAuthorization | null {
    const cacheKey = serializeKey(key);
    const snapshot = this.snapshots.get(cacheKey);
    if (!snapshot) return null;

    if (snapshot.expiresAt <= Date.now()) {
      this.snapshots.delete(cacheKey);
      return null;
    }

    return snapshot.authorization;
  }

  set(key: AuthorizationSnapshotKey, authorization: EffectiveAuthorization): void {
    this.snapshots.set(serializeKey(key), {
      expiresAt: Date.now() + this.ttlSeconds * 1000,
      authorization
    });
  }

  async getOrResolve(
    key: AuthorizationSnapshotKey,
    resolver: () => Promise<EffectiveAuthorization>
  ): Promise<EffectiveAuthorization> {
    const cached = this.get(key);
    if (cached) return cached;

    const cacheKey = serializeKey(key);
    const pending = this.inFlight.get(cacheKey);
    if (pending) return pending;

    const promise = resolver()
      .then((authorization) => {
        this.set(key, authorization);
        return authorization;
      })
      .finally(() => {
        this.inFlight.delete(cacheKey);
      });

    this.inFlight.set(cacheKey, promise);
    return promise;
  }

  clear(): void {
    this.snapshots.clear();
    this.inFlight.clear();
  }
}

function serializeKey(key: AuthorizationSnapshotKey): string {
  return [key.sessionId, key.userId, key.tenantId, key.applicationId].join(":");
}
