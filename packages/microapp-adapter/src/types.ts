import type { ComponentType } from "react";

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

export interface XOOSPermissionHelpers {
  hasScope: (scope: string) => boolean;
  hasAnyScope: (scopes: string[]) => boolean;
  hasAllScopes: (scopes: string[]) => boolean;
}
