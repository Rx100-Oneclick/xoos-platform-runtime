import { useMemo } from "react";
import { useXOOS } from "../context/XOOSContext";
import { XOAuthClient } from "../xo-auth/client";

export function useXOAuth(): XOAuthClient {
  const bridge = useXOOS();
  return useMemo(() => new XOAuthClient(bridge), [bridge]);
}
