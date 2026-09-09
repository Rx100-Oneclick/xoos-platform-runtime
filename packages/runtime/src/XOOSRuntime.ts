import type {
  XOOSCapabilityResponse,
  XOOSMicroappBridge,
  XOOSRuntimeContext,
  XOOSRuntimeFeed,
  XOOSTelemetryEvent
} from "@xoos/contracts";
import { XOOSRuntimeError } from "./errors/XOOSRuntimeError";
import { AuthManager } from "./managers/AuthManager";
import { EventManager } from "./managers/EventManager";
import { HttpClient } from "./managers/HttpClient";
import { ManifestManager } from "./managers/ManifestManager";
import { ModuleLoader } from "./managers/ModuleLoader";
import type {
  XOOSMountedMicroapp,
  XOOSMountOptions,
  XOOSRuntimeElement,
  XOOSRuntimeOptions
} from "./types/runtime";

export class XOOSRuntime {
  static readonly version = "0.1.0";

  private initialized = false;
  private context: XOOSRuntimeContext | null = null;
  private feed: XOOSRuntimeFeed | null = null;
  private readonly mounted = new Map<string, HTMLElement>();
  private readonly auth: AuthManager;
  private readonly http: HttpClient;
  private readonly events = new EventManager();
  private readonly manifests = new ManifestManager();
  private readonly modules = new ModuleLoader();

  constructor(private readonly options: XOOSRuntimeOptions) {
    if (!options.clientId) throw new XOOSRuntimeError("CLIENT_ID_REQUIRED", "XOOS clientId is required.");
    if (!options.apiBaseUrl) throw new XOOSRuntimeError("API_BASE_URL_REQUIRED", "XOOS apiBaseUrl is required.");
    this.auth = new AuthManager(options.getAccessToken);
    this.http = new HttpClient(
      options.apiBaseUrl,
      options.clientId,
      this.auth,
      options.requestTimeoutMs
    );
  }

  async initialize(): Promise<void> {
    if (this.initialized) return;
    try {
      this.context = await this.http.get<XOOSRuntimeContext>("/v1/runtime/context");
      this.feed = await this.http.get<XOOSRuntimeFeed>("/v1/runtime/feed");
      this.initialized = true;
    } catch (error) {
      this.report(error);
      throw error;
    }
  }

  getContext(): XOOSRuntimeContext {
    this.ensureInitialized();
    return this.context!;
  }

  getFeed(): XOOSRuntimeFeed {
    this.ensureInitialized();
    return this.feed!;
  }

  async mount(microappKey: string, options: XOOSMountOptions): Promise<XOOSMountedMicroapp> {
    this.ensureInitialized();
    if (!options.target) throw new XOOSRuntimeError("MOUNT_TARGET_INVALID", "A mount target is required.");

    const feedEntry = this.feed!.microapps.find((item) => item.microappKey === microappKey);
    if (!feedEntry) {
      throw new XOOSRuntimeError("MICROAPP_NOT_ENTITLED", `Microapp '${microappKey}' is not in this client feed.`);
    }
    if (feedEntry.deliveryType !== "native_esm") {
      throw new XOOSRuntimeError("DELIVERY_TYPE_UNSUPPORTED", `Runtime V1 supports native_esm only: ${microappKey}`);
    }

    const manifest = await this.manifests.resolve(feedEntry.manifestUrl);
    if (manifest.microappKey !== microappKey) {
      throw new XOOSRuntimeError("MANIFEST_MISMATCH", "Feed and manifest Microapp keys do not match.");
    }

    await this.modules.load(manifest.entry);
    if (!customElements.get(manifest.elementName)) {
      throw new XOOSRuntimeError("ELEMENT_NOT_REGISTERED", `Custom element '${manifest.elementName}' was not registered.`);
    }

    const element = document.createElement(manifest.elementName) as XOOSRuntimeElement;
    element.xoos = this.createBridge();
    element.xoosProps = options.props;
    options.target.replaceChildren(element);
    this.mounted.set(microappKey, element);

    return {
      microappKey,
      element,
      unmount: async () => this.unmount(microappKey)
    };
  }

  async unmount(microappKey: string): Promise<void> {
    this.mounted.get(microappKey)?.remove();
    this.mounted.delete(microappKey);
  }

  async navigate(microappKey: string, target?: HTMLElement): Promise<void> {
    const destination = target ?? this.firstMountedParent();
    if (!destination) {
      throw new XOOSRuntimeError("NAVIGATION_TARGET_MISSING", "No target is available for Runtime navigation.");
    }
    await this.mount(microappKey, { target: destination });
  }

  async requestCapability<T>(capability: string, input: unknown = {}, microappKey?: string): Promise<T> {
    this.ensureInitialized();
    const response = await this.http.post<XOOSCapabilityResponse<T>>(
      `/v1/capabilities/${encodeURIComponent(capability)}`,
      { input, microappKey }
    );
    if (!response.ok) {
      throw new XOOSRuntimeError(
        response.error?.code ?? "CAPABILITY_FAILED",
        response.error?.message ?? `Capability '${capability}' failed.`
      );
    }
    return response.data as T;
  }

  async trackTelemetry(
    event: string,
    attributes?: Record<string, string | number | boolean | null>,
    microappKey?: string
  ): Promise<void> {
    this.ensureInitialized();
    const payload: XOOSTelemetryEvent = {
      event,
      microappKey,
      occurredAt: new Date().toISOString(),
      attributes
    };
    try {
      await this.http.post<{ ok: boolean; traceId?: string }>("/v1/telemetry", payload);
    } catch (error) {
      // Telemetry is best-effort and must never break Microapp execution.
      this.report(error);
    }
  }

  async destroy(): Promise<void> {
    for (const key of [...this.mounted.keys()]) await this.unmount(key);
    this.events.clear();
    this.context = null;
    this.feed = null;
    this.initialized = false;
  }

  private createBridge(): XOOSMicroappBridge {
    return {
      context: this.context!,
      navigation: { navigate: (microappKey, target) => this.navigate(microappKey, target) },
      events: {
        emit: (event, payload) => this.events.emit(event, payload),
        on: (event, handler) => this.events.on(event, handler)
      },
      services: {
        request: <T>(capability: string, input?: unknown, microappKey?: string) =>
          this.requestCapability<T>(capability, input, microappKey)
      },
      telemetry: {
        track: (event, attributes, microappKey) => this.trackTelemetry(event, attributes, microappKey)
      }
    };
  }

  private firstMountedParent(): HTMLElement | null {
    const element = this.mounted.values().next().value as HTMLElement | undefined;
    return element?.parentElement ?? null;
  }

  private ensureInitialized(): void {
    if (!this.initialized || !this.context || !this.feed) {
      throw new XOOSRuntimeError("RUNTIME_NOT_INITIALIZED", "Call runtime.initialize() before using the Runtime.");
    }
  }

  private report(error: unknown): void {
    if (error instanceof Error) this.options.onError?.(error);
  }
}
