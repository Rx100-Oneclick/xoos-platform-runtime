import type { XOOSMicroappElement } from "@xoos/contracts";

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

/** @deprecated Import XOOSMicroappBridge from @xoos/contracts. */
export type { XOOSMicroappBridge } from "@xoos/contracts";

/** @deprecated Import XOOSMicroappElement from @xoos/contracts. */
export type XOOSRuntimeElement = XOOSMicroappElement;
