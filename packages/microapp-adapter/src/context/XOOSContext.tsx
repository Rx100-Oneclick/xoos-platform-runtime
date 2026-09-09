import { createContext, useContext } from "react";
import type { XOOSMicroappBridge } from "@xoos/contracts";
import { XOOSMicroappError } from "../errors/XOOSMicroappError";

export const XOOSContext = createContext<XOOSMicroappBridge | null>(null);

export function useXOOS(): XOOSMicroappBridge {
  const value = useContext(XOOSContext);
  if (!value) {
    throw new XOOSMicroappError(
      "XOOS_CONTEXT_MISSING",
      "XOOS Microapp is not mounted inside the XOOS Runtime."
    );
  }
  return value;
}
