import { useXOOS } from "../context/XOOSContext";

export { useXOOSPermissions } from "./useXOOSPermissions";

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
