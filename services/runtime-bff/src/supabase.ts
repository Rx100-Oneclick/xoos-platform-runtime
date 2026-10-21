import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import type { RuntimeBffConfig } from "./config";

function createBackendClient(url: string, secretKey: string): SupabaseClient {
  return createClient(url, secretKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false
    }
  });
}

export function createRegistryClient(config: RuntimeBffConfig): SupabaseClient {
  return createBackendClient(config.supabaseUrl, config.supabaseSecretKey);
}

export function createServicesClient(config: RuntimeBffConfig): SupabaseClient {
  return createBackendClient(config.servicesUrl, config.servicesSecretKey);
}
