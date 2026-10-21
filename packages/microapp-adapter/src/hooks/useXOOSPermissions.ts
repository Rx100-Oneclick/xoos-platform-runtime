import { useXOOS } from "../context/XOOSContext";
import type { XOOSPermissionHelpers } from "../types";

export function useXOOSPermissions(): XOOSPermissionHelpers {
  const xoos = useXOOS();
  const scopes = xoos.context.scopes;
  const hasScope = (scope: string) => scopes.includes(scope);

  return {
    list: () => xoos.permissions.list(),
    can: (action: string) => xoos.permissions.can(action),
    require: (action: string) => xoos.permissions.require(action),
    hasScope,
    hasAnyScope: (requiredScopes: string[]) => requiredScopes.some(hasScope),
    hasAllScopes: (requiredScopes: string[]) => requiredScopes.every(hasScope)
  };
}
