import type { XOOSDataAccessSession, XOOSDataSourceConfig } from "@xoos/contracts";
import { XOOSRuntimeError } from "../errors/XOOSRuntimeError";
import { HttpClient } from "./HttpClient";

interface CachedDataSession extends XOOSDataAccessSession {}

export class DataTokenManager {
  private readonly cache = new Map<string, CachedDataSession>();
  private readonly inFlight = new Map<string, Promise<CachedDataSession>>();

  constructor(
    private readonly http: HttpClient,
    private readonly refreshSkewMs = 60_000
  ) {}

  async getAccessToken(projectKey: string): Promise<string> {
    return (await this.getSession(projectKey)).accessToken;
  }

  async getProjectConfig(projectKey: string): Promise<XOOSDataSourceConfig> {
    return (await this.getSession(projectKey)).dataSource;
  }

  clear(): void {
    this.cache.clear();
    this.inFlight.clear();
  }

  private async getSession(projectKey: string): Promise<CachedDataSession> {
    const key = projectKey.trim();
    if (!key) throw new XOOSRuntimeError("DATA_PROJECT_KEY_REQUIRED", "XOOS data projectKey is required.");

    const cached = this.cache.get(key);
    if (cached && cached.expiresAt > Date.now() + this.refreshSkewMs) return cached;

    const existing = this.inFlight.get(key);
    if (existing) return existing;

    const pending = this.refresh(key).finally(() => this.inFlight.delete(key));
    this.inFlight.set(key, pending);
    return pending;
  }

  private async refresh(projectKey: string): Promise<CachedDataSession> {
    const session = await this.http.post<XOOSDataAccessSession>("/v1/data/token", { projectKey });

    if (!session.accessToken || !Number.isFinite(session.expiresAt)) {
      throw new XOOSRuntimeError("DATA_TOKEN_RESPONSE_INVALID", "XOOS data token response is invalid.");
    }

    if (!session.dataSource?.supabaseUrl || !session.dataSource?.publishableKey) {
      throw new XOOSRuntimeError("DATA_SOURCE_CONFIG_INVALID", "XOOS data source configuration is invalid.");
    }

    this.cache.set(projectKey, session);
    return session;
  }
}
