import { useXOOS } from "../context/XOOSContext";
import type { XOOSPermissionHelpers } from "../types";

export function useXOOSContext() {
  return useXOOS().context;
}

export function useXOOSNavigation() {
  return useXOOS().navigation;
}

export function useXOOSEvents() {
  return useXOOS().events;
}

export function useXOOSServices() {
  return useXOOS().services;
}

export function useXOOSTelemetry() {
  return useXOOS().telemetry;
}

export function useXOOSPermissions(): XOOSPermissionHelpers {
  const scopes = useXOOS().context.scopes;
  const hasScope = (scope: string) => scopes.includes(scope);

  // UI helper only. Runtime BFF must enforce real authorization.
  return {
    hasScope,
    hasAnyScope: (requiredScopes: string[]) => requiredScopes.some(hasScope),
    hasAllScopes: (requiredScopes: string[]) => requiredScopes.every(hasScope)
  };
}
