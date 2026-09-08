import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import type { RuntimeBffConfig } from "./config";

export function createRegistryClient(config: RuntimeBffConfig): SupabaseClient {
  return createClient(config.supabaseUrl, config.supabaseSecretKey, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false }
  });
}
