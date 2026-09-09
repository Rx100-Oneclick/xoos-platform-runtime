export type XOOSDeliveryType = "native_esm" | "isolated_iframe" | "legacy_iframe";

export interface XOOSRuntimeContext {
  user: { id: string };
  tenant: { id: string | null };
  client: { id: string };
  runtime: { minimumVersion: string };
  scopes: string[];
}

export interface XOOSFeedMicroapp {
  microappKey: string;
  displayName: string;
  elementName: string | null;
  deliveryType: XOOSDeliveryType;
  version: string;
  manifestUrl: string;
  contractVersion: string | null;
  minimumRuntimeVersion: string | null;
}

export interface XOOSRuntimeFeed {
  schemaVersion: "1";
  clientId: string;
  runtimeVersion: string;
  generatedAt: string;
  microapps: XOOSFeedMicroapp[];
}

export interface XOOSMicroappManifest {
  schemaVersion: "1";
  microappKey: string;
  version: string;
  elementName: string;
  entry: string;
  contractVersion: string;
  minimumRuntimeVersion: string;
}

export interface XOOSCapabilityRequest<T = unknown> {
  input: T;
  microappKey?: string;
}

export interface XOOSCapabilityResponse<T = unknown> {
  ok: boolean;
  data?: T;
  error?: { code: string; message: string };
  traceId: string;
}

export interface XOOSTelemetryEvent {
  event: string;
  microappKey?: string;
  traceId?: string;
  occurredAt: string;
  attributes?: Record<string, string | number | boolean | null>;
}

export interface XOOSMicroappBridge {
  context: XOOSRuntimeContext;
  navigation: {
    navigate: (microappKey: string, target?: HTMLElement) => Promise<void>;
  };
  events: {
    emit: (event: string, payload?: unknown) => void;
    on: (event: string, handler: (payload: unknown) => void) => () => void;
  };
  services: {
    request: <T>(capability: string, input?: unknown, microappKey?: string) => Promise<T>;
  };
  telemetry: {
    track: (
      event: string,
      attributes?: Record<string, string | number | boolean | null>,
      microappKey?: string
    ) => Promise<void>;
  };
}

export interface XOOSMicroappElement extends HTMLElement {
  xoos?: XOOSMicroappBridge;
  xoosProps?: Record<string, unknown>;
}
