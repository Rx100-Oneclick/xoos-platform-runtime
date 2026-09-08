import { XOOSRuntimeError } from "../errors/XOOSRuntimeError";

export class ModuleLoader {
  private readonly cache = new Map<string, Promise<unknown>>();

  async load(entryUrl: string): Promise<unknown> {
    const existing = this.cache.get(entryUrl);
    if (existing) return existing;

    const request = import(/* @vite-ignore */ entryUrl).catch((error) => {
      this.cache.delete(entryUrl);
      throw new XOOSRuntimeError("MODULE_LOAD_FAILED", `Unable to load Microapp module: ${entryUrl}`, error);
    });

    this.cache.set(entryUrl, request);
    return request;
  }
}
