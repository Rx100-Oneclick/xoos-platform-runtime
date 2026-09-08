export { createRuntimeBffHandler } from "./app";
export { loadConfig } from "./config";
export { registerCapability } from "./capabilities";
export type { XOIdentity } from "./auth";

// Node/Worker/Supabase adapters should call createRuntimeBffHandler(loadConfig())
// and pass each incoming Request to the returned handler. Keeping the core on
// the Web Request/Response standard makes the BFF portable across runtimes.
