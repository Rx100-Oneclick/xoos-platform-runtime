import type { SupabaseClient } from "@supabase/supabase-js";
import type { XOOSRuntimeFeed } from "@xoos/contracts";
import type { RuntimeBffConfig } from "./config";
import { HttpError, type XOIdentity } from "./auth";

export async function buildRuntimeFeed(
  db: SupabaseClient,
  config: RuntimeBffConfig,
  identity: XOIdentity,
  clientId: string,
  environment: string
): Promise<XOOSRuntimeFeed> {
  assertClientBinding(identity, clientId);

  const { data: entitlements, error: entitlementError } = await db
    .schema("xoos_control")
    .from("xoos_client_microapp_entitlements")
    .select("microapp_id,pinned_version,version_policy")
    .eq("client_id", clientId)
    .eq("environment", environment)
    .eq("is_enabled", true);

  if (entitlementError) throw new HttpError(500, "FEED_ENTITLEMENT_LOOKUP_FAILED", entitlementError.message);
  if (!entitlements?.length) {
    return {
      schemaVersion: "1",
      clientId,
      runtimeVersion: config.runtimeVersion,
      generatedAt: new Date().toISOString(),
      microapps: []
    };
  }

  const ids = entitlements.map((row) => row.microapp_id);
  const { data: microapps, error: microappError } = await db
    .schema("xoos_control")
    .from("xoos_microapps")
    .select("uuid,microapp_key,display_name,element_name,delivery_type,contract_version,minimum_runtime_version,status,is_visible")
    .in("uuid", ids)
    .eq("status", "active")
    .eq("is_visible", true);

  if (microappError) throw new HttpError(500, "FEED_REGISTRY_LOOKUP_FAILED", microappError.message);

  const { data: deployments, error: deploymentError } = await db
    .schema("xoos_control")
    .from("xoos_microapp_deployments")
    .select("microapp_id,environment,version,manifest_url,status")
    .in("microapp_id", ids)
    .eq("environment", environment)
    .eq("status", "active");

  if (deploymentError) throw new HttpError(500, "FEED_DEPLOYMENT_LOOKUP_FAILED", deploymentError.message);

  const latestDeployment = new Map<string, { version: string; manifest_url: string }>();
  for (const deployment of deployments ?? []) {
    const current = latestDeployment.get(deployment.microapp_id);
    if (!current || compareVersions(deployment.version, current.version) > 0) {
      latestDeployment.set(deployment.microapp_id, deployment);
    }
  }

  const feedItems = (microapps ?? []).flatMap((microapp) => {
    const deployment = latestDeployment.get(microapp.uuid);
    if (!deployment) return [];
    return [{
      microappKey: microapp.microapp_key,
      displayName: microapp.display_name,
      elementName: microapp.element_name,
      deliveryType: microapp.delivery_type,
      version: deployment.version,
      manifestUrl: deployment.manifest_url,
      contractVersion: microapp.contract_version,
      minimumRuntimeVersion: microapp.minimum_runtime_version
    }];
  });

  return {
    schemaVersion: "1",
    clientId,
    runtimeVersion: config.runtimeVersion,
    generatedAt: new Date().toISOString(),
    microapps: feedItems
  };
}

export function assertClientBinding(identity: XOIdentity, requestedClientId: string): void {
  if (identity.tokenClientId && identity.tokenClientId !== requestedClientId) {
    throw new HttpError(403, "CLIENT_BINDING_MISMATCH", "XO token is not bound to the requested client.");
  }
}

function compareVersions(a: string, b: string): number {
  const aa = a.split(".").map(Number);
  const bb = b.split(".").map(Number);
  for (let i = 0; i < 3; i += 1) {
    const diff = (aa[i] ?? 0) - (bb[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}
