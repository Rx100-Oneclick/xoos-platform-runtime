import type { XOOSRuntimeContext } from "@xoos/contracts";

export interface XOOSRuntimeOptions {
  clientId: string;
  apiBaseUrl: string;
  getAccessToken: () => Promise<string | null>;
  environment?: "development" | "staging" | "production";
  requestTimeoutMs?: number;
  onError?: (error: Error) => void;
}

export interface XOOSMountOptions {
  target: HTMLElement;
  props?: Record<string, unknown>;
}

export interface XOOSMountedMicroapp {
  microappKey: string;
  element: HTMLElement;
  unmount: () => Promise<void>;
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
}

export interface XOOSRuntimeElement extends HTMLElement {
  xoos?: XOOSMicroappBridge;
  xoosProps?: Record<string, unknown>;
}
