import { createContext, useContext, type ReactNode } from "react";

const XOOSPortalContext = createContext<HTMLElement | null>(null);

export function XOOSPortalProvider(props: { value: HTMLElement | null; children: ReactNode }) {
  return (
    <XOOSPortalContext.Provider value={props.value}>
      {props.children}
    </XOOSPortalContext.Provider>
  );
}

export function useXOOSPortalRoot(): HTMLElement | null {
  return useContext(XOOSPortalContext);
}
