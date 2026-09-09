import { createRoot, type Root } from "react-dom/client";
import type { XOOSMicroappBridge, XOOSMicroappElement } from "@xoos/contracts";
import { XOOSContext } from "./context/XOOSContext";
import { XOOSMicroappError } from "./errors/XOOSMicroappError";
import { XOOSMicroappErrorBoundary } from "./errors/XOOSMicroappErrorBoundary";
import { XOOSPortalProvider } from "./portal/PortalContext";
import type { DefineXOOSMicroappOptions } from "./types";

export function defineXOOSMicroapp<TProps extends Record<string, unknown>>(
  options: DefineXOOSMicroappOptions<TProps>
): void {
  const { id, element, App, styles = "", shadowDom = true, onError } = options;

  if (!id.trim()) throw new XOOSMicroappError("MICROAPP_ID_REQUIRED", "XOOS Microapp id is required.");
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)+$/.test(element)) {
    throw new XOOSMicroappError(
      "ELEMENT_NAME_INVALID",
      "XOOS custom element name must be lowercase, hyphenated, and contain at least one hyphen."
    );
  }

  if (customElements.get(element)) return;

  class XOOSReactMicroappElement extends HTMLElement implements XOOSMicroappElement {
    private reactRoot: Root | null = null;
    private mountNode: HTMLDivElement | null = null;
    private portalNode: HTMLDivElement | null = null;
    private bridge: XOOSMicroappBridge | undefined;
    private props: Record<string, unknown> = {};
    private mountedTelemetrySent = false;

    set xoos(value: XOOSMicroappBridge | undefined) {
      this.bridge = value;
      if (this.isConnected) this.renderMicroapp();
    }

    get xoos(): XOOSMicroappBridge | undefined {
      return this.bridge;
    }

    set xoosProps(value: Record<string, unknown> | undefined) {
      this.props = value ?? {};
      if (this.isConnected) this.renderMicroapp();
    }

    get xoosProps(): Record<string, unknown> {
      return this.props;
    }

    connectedCallback(): void {
      this.mountMicroapp();
    }

    disconnectedCallback(): void {
      this.unmountMicroapp();
    }

    private mountMicroapp(): void {
      if (this.reactRoot) return;

      const container: ShadowRoot | HTMLElement = shadowDom
        ? this.shadowRoot ?? this.attachShadow({ mode: "open" })
        : this;

      if (styles && !container.querySelector("style[data-xoos-adapter-styles]")) {
        const style = document.createElement("style");
        style.setAttribute("data-xoos-adapter-styles", id);
        style.textContent = styles;
        container.appendChild(style);
      }

      this.mountNode = document.createElement("div");
      this.mountNode.setAttribute("data-xoos-microapp", id);
      container.appendChild(this.mountNode);

      this.portalNode = document.createElement("div");
      this.portalNode.setAttribute("data-xoos-portal-root", id);
      container.appendChild(this.portalNode);

      this.reactRoot = createRoot(this.mountNode);
      this.renderMicroapp();
      this.emitMountTelemetry();
    }

    private renderMicroapp(): void {
      if (!this.reactRoot || !this.bridge) return;

      this.reactRoot.render(
        <XOOSMicroappErrorBoundary microappKey={id} bridge={this.bridge} onError={onError}>
          <XOOSContext.Provider value={this.bridge}>
            <XOOSPortalProvider value={this.portalNode}>
              <App {...(this.props as TProps)} />
            </XOOSPortalProvider>
          </XOOSContext.Provider>
        </XOOSMicroappErrorBoundary>
      );
    }

    private emitMountTelemetry(): void {
      if (!this.bridge || this.mountedTelemetrySent) return;
      this.mountedTelemetrySent = true;
      void this.bridge.telemetry
        .track("microapp.mount", { microappKey: id }, id)
        .catch(() => undefined);
    }

    private unmountMicroapp(): void {
      if (this.bridge && this.mountedTelemetrySent) {
        void this.bridge.telemetry
          .track("microapp.unmount", { microappKey: id }, id)
          .catch(() => undefined);
      }

      this.reactRoot?.unmount();
      this.reactRoot = null;
      this.mountNode = null;
      this.portalNode = null;
      this.mountedTelemetrySent = false;
    }
  }

  customElements.define(element, XOOSReactMicroappElement);
}
