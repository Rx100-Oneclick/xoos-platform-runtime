import { XOOSRuntimeError } from "../errors/XOOSRuntimeError";
import { AuthManager } from "./AuthManager";

export class HttpClient {
  constructor(
    private readonly baseUrl: string,
    private readonly clientId: string,
    private readonly auth: AuthManager,
    private readonly timeoutMs = 15000
  ) {}

  async get<T>(path: string): Promise<T> {
    return this.request<T>(path, { method: "GET" });
  }

  async post<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
  }

  private async request<T>(path: string, init: RequestInit): Promise<T> {
    const token = await this.auth.getAccessToken();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    const traceId = crypto.randomUUID();

    try {
      const response = await fetch(`${this.baseUrl.replace(/\/$/, "")}${path}`, {
        ...init,
        signal: controller.signal,
        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${token}`,
          "X-XO-Client-Id": this.clientId,
          "X-XO-Trace-Id": traceId,
          ...(init.headers ?? {})
        }
      });

      const text = await response.text();
      const body = text ? JSON.parse(text) : null;

      if (!response.ok) {
        const code = body?.error?.code ?? body?.code ?? `HTTP_${response.status}`;
        const message = body?.error?.message ?? body?.message ?? `XOOS request failed (${response.status}).`;
        throw new XOOSRuntimeError(code, message);
      }

      return body as T;
    } catch (error) {
      if (error instanceof XOOSRuntimeError) throw error;
      if (error instanceof DOMException && error.name === "AbortError") {
        throw new XOOSRuntimeError("REQUEST_TIMEOUT", "XOOS request timed out.", error);
      }
      throw new XOOSRuntimeError("NETWORK_ERROR", "XOOS request failed.", error);
    } finally {
      clearTimeout(timeout);
    }
  }
}
