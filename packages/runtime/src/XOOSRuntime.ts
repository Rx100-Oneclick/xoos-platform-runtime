import type {
  XOOSCapabilityResponse,
  XOOSFeedMicroapp,
  XOOSMicroappArtifactAccess,
  XOOSMicroappBridge,
  XOOSMicroappManifest,
  XOOSNavigationOptions,
  XOOSRuntimeContext,
  XOOSRuntimeFeed,
  XOOSTelemetryEvent
} from "@xoos/contracts";
import { XOOSRuntimeError } from "./errors/XOOSRuntimeError";
import { AuthManager } from "./managers/AuthManager";
import { DataTokenManager } from "./managers/DataTokenManager";
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
  static readonly version = "1.2.0";

  private initialized = false;
  private context: XOOSRuntimeContext | null = null;
  private feed: XOOSRuntimeFeed | null = null;
  private readonly mounted = new Map<string, HTMLElement>();
  private readonly loadedReleases = new Map<string, XOOSMicroappManifest>();
  private readonly auth: AuthManager;
  private readonly http: HttpClient;
  private readonly data: DataTokenManager;
  private readonly events = new EventManager();
  private readonly manifests = new ManifestManager();
  private readonly modules = new ModuleLoader();

  constructor(private readonly options: XOOSRuntimeOptions) {
    if (!options.clientId) throw new XOOSRuntimeError("CLIENT_ID_REQUIRED", "XOOS clientId is required.");
    if (!options.apiBaseUrl) throw new XOOSRuntimeError("API_BASE_URL_REQUIRED", "XOOS apiBaseUrl is required.");
    this.auth = new AuthManager(options.getAccessToken);
    this.http = new HttpClient(options.apiBaseUrl, options.clientId, this.auth, options.requestTimeoutMs);
    this.data = new DataTokenManager(this.http);
  }

  async initialize(): Promise<void> {
    if (this.initialized) return;

    try {
      const [context, feed] = await Promise.all([
        this.http.get<XOOSRuntimeContext>("/v1/runtime/context"),
        this.http.get<XOOSRuntimeFeed>("/v1/runtime/feed")
      ]);

      this.context = context;
      this.feed = feed;
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

    const { manifest } = await this.loadMicroappRelease(microappKey);

    if (!customElements.get(manifest.elementName)) {
      throw new XOOSRuntimeError(
        "ELEMENT_NOT_REGISTERED",
        `Custom element '${manifest.elementName}' was not registered.`
      );
    }

    const element = document.createElement(manifest.elementName) as XOOSRuntimeElement;
    element.xoos = this.createBridge();
    element.xoosProps = options.props;

    this.clearMountedAtTarget(options.target);
    options.target.replaceChildren(element);
    this.mounted.set(microappKey, element);
    return { microappKey, element, unmount: async () => this.unmount(microappKey) };
  }

  async unmount(microappKey: string): Promise<void> {
    this.mounted.get(microappKey)?.remove();
    this.mounted.delete(microappKey);
  }

  async navigate(
    microappKey: string,
    targetOrOptions?: HTMLElement | XOOSNavigationOptions
  ): Promise<void> {
    const navigationOptions: XOOSNavigationOptions =
      targetOrOptions instanceof HTMLElement
        ? { target: targetOrOptions }
        : targetOrOptions ?? {};

    const destination = navigationOptions.target ?? this.firstMountedParent();
    if (!destination) {
      throw new XOOSRuntimeError(
        "NAVIGATION_TARGET_MISSING",
        "No target is available for Runtime navigation."
      );
    }

    await this.mount(microappKey, {
      target: destination,
      props: navigationOptions.props
    });
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
      this.report(error);
    }
  }

  async destroy(): Promise<void> {
    for (const key of [...this.mounted.keys()]) await this.unmount(key);
    this.events.clear();
    this.data.clear();
    this.manifests.clear();
    this.modules.clear();
    this.loadedReleases.clear();
    this.context = null;
    this.feed = null;
    this.initialized = false;
  }

  private async loadMicroappRelease(
    microappKey: string
  ): Promise<{ feedEntry: XOOSFeedMicroapp; manifest: XOOSMicroappManifest }> {
    const feedEntry = this.findFeedEntry(microappKey);
    this.validateFeedEntry(feedEntry);

    const releaseKey = this.releaseKey(feedEntry);
    const cachedManifest = this.loadedReleases.get(releaseKey);
    if (cachedManifest) {
      return { feedEntry, manifest: cachedManifest };
    }

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const artifacts = await this.getArtifactAccess(microappKey);
      this.validateArtifactAccess(feedEntry, artifacts);

      try {
        const manifest = await this.manifests.resolve(
          artifacts.manifestUrl,
          releaseKey
        );

        this.validateManifestAgainstFeed(feedEntry, manifest);

        await this.modules.load(
          artifacts.entryUrl,
          artifacts.integrity,
          `${feedEntry.microappKey}@${feedEntry.version}@${artifacts.integrity.toLowerCase()}`
        );

        this.loadedReleases.set(releaseKey, manifest);
        return { feedEntry, manifest };
      } catch (error) {
        if (
          attempt === 0 &&
          error instanceof XOOSRuntimeError &&
          error.code === "MICROAPP_SIGNED_URL_EXPIRED"
        ) {
          this.manifests.delete(releaseKey);
          continue;
        }

        throw error;
      }
    }

    throw new XOOSRuntimeError(
      "MICROAPP_SIGNED_URL_EXPIRED",
      "Unable to obtain valid Microapp artifact access."
    );
  }

  private async getArtifactAccess(
    microappKey: string
  ): Promise<XOOSMicroappArtifactAccess> {
    return this.http.post<XOOSMicroappArtifactAccess>(
      `/v1/runtime/microapps/${encodeURIComponent(microappKey)}/artifacts`,
      {}
    );
  }

  private findFeedEntry(microappKey: string): XOOSFeedMicroapp {
    const feedEntry = this.feed!.microapps.find((item) => item.microappKey === microappKey);
    if (!feedEntry) {
      throw new XOOSRuntimeError(
        "MICROAPP_NOT_ENTITLED",
        `Microapp '${microappKey}' is not in this client feed.`
      );
    }
    return feedEntry;
  }

  private validateFeedEntry(feedEntry: XOOSFeedMicroapp): void {
    if (feedEntry.deliveryType !== "native_esm") {
      throw new XOOSRuntimeError(
        "DELIVERY_TYPE_UNSUPPORTED",
        `Runtime supports native_esm only: ${feedEntry.microappKey}`
      );
    }

    if (!feedEntry.elementName) {
      throw new XOOSRuntimeError(
        "MANIFEST_ELEMENT_MISMATCH",
        `Native ESM Microapp '${feedEntry.microappKey}' does not declare an element name.`
      );
    }

    if (!feedEntry.integrity) {
      throw new XOOSRuntimeError(
        "MICROAPP_INTEGRITY_MISSING",
        `Microapp '${feedEntry.microappKey}' does not have a trusted integrity digest.`
      );
    }

    if (!/^sha256:[0-9a-f]{64}$/i.test(feedEntry.integrity)) {
      throw new XOOSRuntimeError(
        "MICROAPP_INTEGRITY_INVALID",
        `Microapp '${feedEntry.microappKey}' has an invalid integrity digest.`
      );
    }
  }

  private validateArtifactAccess(
    feedEntry: XOOSFeedMicroapp,
    artifacts: XOOSMicroappArtifactAccess
  ): void {
    if (artifacts.microappKey !== feedEntry.microappKey) {
      throw new XOOSRuntimeError(
        "MICROAPP_ARTIFACT_MISMATCH",
        "Artifact access Microapp key does not match the Runtime feed."
      );
    }

    if (artifacts.version !== feedEntry.version) {
      throw new XOOSRuntimeError(
        "MICROAPP_ARTIFACT_VERSION_MISMATCH",
        "Artifact access version does not match the Runtime feed."
      );
    }

    if (!artifacts.manifestUrl || !artifacts.entryUrl) {
      throw new XOOSRuntimeError(
        "MICROAPP_ARTIFACT_ACCESS_INVALID",
        "Microapp artifact access URLs are missing."
      );
    }

    if (!/^sha256:[0-9a-f]{64}$/i.test(artifacts.integrity)) {
      throw new XOOSRuntimeError(
        "MICROAPP_INTEGRITY_INVALID",
        "Microapp artifact integrity is invalid."
      );
    }

    if (artifacts.integrity.toLowerCase() !== feedEntry.integrity.toLowerCase()) {
      throw new XOOSRuntimeError(
        "MICROAPP_ARTIFACT_INTEGRITY_MISMATCH",
        "Artifact integrity does not match the trusted Runtime feed."
      );
    }

    if (
      !Number.isFinite(artifacts.expiresIn) ||
      artifacts.expiresIn <= 0
    ) {
      throw new XOOSRuntimeError(
        "MICROAPP_ARTIFACT_ACCESS_INVALID",
        "Microapp artifact access expiry is invalid."
      );
    }
  }

  private validateManifestAgainstFeed(
    feedEntry: XOOSFeedMicroapp,
    manifest: XOOSMicroappManifest
  ): void {
    if (manifest.microappKey !== feedEntry.microappKey) {
      throw new XOOSRuntimeError(
        "MANIFEST_MISMATCH",
        "Feed and manifest Microapp keys do not match."
      );
    }

    if (manifest.version !== feedEntry.version) {
      throw new XOOSRuntimeError(
        "MANIFEST_VERSION_MISMATCH",
        "Feed and manifest versions do not match."
      );
    }

    if (manifest.elementName !== feedEntry.elementName) {
      throw new XOOSRuntimeError(
        "MANIFEST_ELEMENT_MISMATCH",
        "Feed and manifest element names do not match."
      );
    }

    if (manifest.deliveryType && manifest.deliveryType !== feedEntry.deliveryType) {
      throw new XOOSRuntimeError(
        "MANIFEST_DELIVERY_TYPE_MISMATCH",
        "Feed and manifest delivery types do not match."
      );
    }

    if (manifest.integrity) {
      const expected = feedEntry.integrity.replace(/^sha256:/i, "").toLowerCase();
      const manifestHash = manifest.integrity.value.toLowerCase();

      if (manifestHash !== expected) {
        throw new XOOSRuntimeError(
          "MANIFEST_INTEGRITY_MISMATCH",
          "Manifest integrity does not match the trusted deployment integrity."
        );
      }
    }
  }

  private releaseKey(feedEntry: XOOSFeedMicroapp): string {
    return `${feedEntry.microappKey}@${feedEntry.version}@${feedEntry.integrity.toLowerCase()}`;
  }

  private createBridge(): XOOSMicroappBridge {
    return {
      context: this.context!,
      navigation: {
        navigate: (microappKey, targetOrOptions) =>
          this.navigate(microappKey, targetOrOptions)
      },
      events: {
        emit: (event, payload) => this.events.emit(event, payload),
        on: (event, handler) => this.events.on(event, handler)
      },
      services: {
        request: <T>(capability: string, input?: unknown, microappKey?: string) =>
          this.requestCapability<T>(capability, input, microappKey)
      },
      data: {
        getAccessToken: (projectKey) => this.data.getAccessToken(projectKey),
        getProjectConfig: (projectKey) => this.data.getProjectConfig(projectKey)
      },
      telemetry: {
        track: (event, attributes, microappKey) =>
          this.trackTelemetry(event, attributes, microappKey)
      }
    };
  }

  private clearMountedAtTarget(target: HTMLElement): void {
    for (const [key, element] of this.mounted.entries()) {
      if (element.parentElement === target || !element.isConnected) {
        this.mounted.delete(key);
      }
    }
  }

  private firstMountedParent(): HTMLElement | null {
    for (const element of this.mounted.values()) {
      if (element.parentElement) return element.parentElement;
    }
    return null;
  }

  private ensureInitialized(): void {
    if (!this.initialized || !this.context || !this.feed) {
      throw new XOOSRuntimeError(
        "RUNTIME_NOT_INITIALIZED",
        "Call runtime.initialize() before using the Runtime."
      );
    }
  }

  private report(error: unknown): void {
    if (error instanceof Error) this.options.onError?.(error);
  }
}
