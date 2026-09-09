import React, { type ErrorInfo, type ReactNode } from "react";
import type { XOOSMicroappBridge } from "@xoos/contracts";

interface Props {
  microappKey: string;
  bridge: XOOSMicroappBridge;
  onError?: (error: Error) => void;
  children: ReactNode;
}

interface State {
  hasError: boolean;
}

export class XOOSMicroappErrorBoundary extends React.Component<Props, State> {
  state: State = { hasError: false };

  static getDerivedStateFromError(): State {
    return { hasError: true };
  }

  componentDidCatch(error: Error, _info: ErrorInfo): void {
    this.props.onError?.(error);
    void this.props.bridge.telemetry
      .track("microapp.error", { microappKey: this.props.microappKey }, this.props.microappKey)
      .catch(() => undefined);
  }

  render(): ReactNode {
    if (this.state.hasError) {
      return <div role="alert">This XOOS component could not be loaded.</div>;
    }
    return this.props.children;
  }
}
