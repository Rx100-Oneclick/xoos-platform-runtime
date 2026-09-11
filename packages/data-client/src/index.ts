import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import type { XOOSDataBridge, XOOSDataSourceConfig } from "@xoos/contracts";

export interface CreateXOOSDataClientOptions {
  projectKey: string;
  bridge: XOOSDataBridge;
}

export interface XOOSDataClient {
  projectKey: string;
  config: XOOSDataSourceConfig;
  supabase: SupabaseClient;
}

export async function createXOOSDataClient(
  options: CreateXOOSDataClientOptions
): Promise<XOOSDataClient> {
  const projectKey = options.projectKey.trim();
  if (!projectKey) throw new Error("XOOS projectKey is required.");

  const config = await options.bridge.getProjectConfig(projectKey);
  if (config.provider !== "supabase") {
    throw new Error(`Unsupported XOOS data provider '${config.provider}'.`);
  }

  const supabase = createClient(config.supabaseUrl, config.publishableKey, {
    accessToken: async () => options.bridge.getAccessToken(projectKey),
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false
    }
  });

  return { projectKey, config, supabase };
}

export async function createXOOSSupabaseClient(
  options: CreateXOOSDataClientOptions
): Promise<SupabaseClient> {
  return (await createXOOSDataClient(options)).supabase;
}

export type { XOOSDataBridge, XOOSDataSourceConfig } from "@xoos/contracts";
