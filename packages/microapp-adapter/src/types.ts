import type { ComponentType } from "react";
import type { XOOSPermissionsBridge } from "@xoos/contracts";

export interface DefineXOOSMicroappOptions<
  TProps extends Record<string, unknown> = Record<string, unknown>
> {
  id: string;
  element: string;
  App: ComponentType<TProps>;
  shadowDom?: boolean;
  styles?: string;
  onError?: (error: Error) => void;
}

/**
 * Application/Microapp actions come from Runtime RBAC.
 * OAuth scope helpers remain for backward compatibility only.
 */
export interface XOOSPermissionHelpers extends XOOSPermissionsBridge {
  hasScope: (scope: string) => boolean;
  hasAnyScope: (scopes: string[]) => boolean;
  hasAllScopes: (scopes: string[]) => boolean;
}
