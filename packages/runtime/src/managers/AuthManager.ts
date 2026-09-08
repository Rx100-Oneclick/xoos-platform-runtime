import { XOOSRuntimeError } from "../errors/XOOSRuntimeError";

export class AuthManager {
  constructor(private readonly provider: () => Promise<string | null>) {}

  async getAccessToken(): Promise<string> {
    const token = await this.provider();
    if (!token) {
      throw new XOOSRuntimeError("AUTH_TOKEN_MISSING", "XO access token is unavailable.");
    }
    return token;
  }
}
