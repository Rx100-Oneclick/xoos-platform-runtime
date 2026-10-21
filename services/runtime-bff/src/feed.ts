import type { SupabaseClient } from "@supabase/supabase-js";
import type {
  XOOSFeedMicroapp,
  XOOSMicroappArtifactAccess,
  XOOSRuntimeFeed
} from "@xoos/contracts";
import type { RuntimeBffConfig } from "./config";
import { HttpError, type XOIdentity } from "./auth";
import {
  findAuthorizedMicroapp,
  type EffectiveAuthorization
} from "./authorization";

type DeploymentRow = {
  microapp_id: string;
  environment: string;
  version: string;
  storage_bucket: string | null;
  manifest_path: string | null;
  entry_path: string | null;
  integrity: string | null;
  status: string;
};

type EntitlementRow = {
  microapp_id: string;
  pinned_version: string | null;
  version_policy: string;
};

type MicroappRow = {
  uuid: string;
  microapp_key: string;
  display_name: string;
  element_name: string | null;
  delivery_type: XOOSFeedMicroapp["deliveryType"];
  contract_version: string | null;
  minimum_runtime_version: string | null;
};

type ResolvedDeployment = {
  microapp: MicroappRow;
  deployment: DeploymentRow;
  integrity: string;
  storageBucket: string;
  manifestPath: string;
  entryPath: string;
};

export async function buildRuntimeFeed(
  db: SupabaseClient,
  config: RuntimeBffConfig,
  identity: XOIdentity,
  clientId: string,
  environment: string,
  authorization: EffectiveAuthorization
): Promise<XOOSRuntimeFeed> {
  assertClientBinding(identity, clientId);

  const { data: entitlements, error: entitlementError } = await db
    .schema("xoos_control")
    .from("xoos_client_microapp_entitlements")
    .select("microapp_id,pinned_version,version_policy")
    .eq("client_id", clientId)
    .eq("environment", environment)
    .eq("is_enabled", true);

  if (entitlementError) {
    throw new HttpError(500, "FEED_ENTITLEMENT_LOOKUP_FAILED", "Unable to resolve Runtime entitlements.");
  }

  if (!entitlements?.length) {
    return {
      schemaVersion: "1",
      clientId,
      runtimeVersion: config.runtimeVersion,
      generatedAt: new Date().toISOString(),
      microapps: []
    };
  }

  const entitlementRows = entitlements as EntitlementRow[];
  const ids = [...new Set(entitlementRows.map((row) => row.microapp_id))];

  const [{ data: microapps, error: microappError }, { data: deployments, error: deploymentError }] =
    await Promise.all([
      db
        .schema("xoos_control")
        .from("xoos_microapps")
        .select("uuid,microapp_key,display_name,element_name,delivery_type,contract_version,minimum_runtime_version,status,is_visible")
        .in("uuid", ids)
        .eq("status", "active")
        .eq("is_visible", true),
      db
        .schema("xoos_control")
        .from("xoos_microapp_deployments")
        .select("microapp_id,environment,version,storage_bucket,manifest_path,entry_path,integrity,status")
        .in("microapp_id", ids)
        .eq("environment", environment)
        .eq("status", "active")
    ]);

  if (microappError) {
    throw new HttpError(500, "FEED_REGISTRY_LOOKUP_FAILED", "Unable to load XOOS Microapp Registry.");
  }

  if (deploymentError) {
    throw new HttpError(500, "FEED_DEPLOYMENT_LOOKUP_FAILED", "Unable to resolve Microapp deployments.");
  }

  const entitlementMap = new Map<string, EntitlementRow>();
  for (const entitlement of entitlementRows) {
    entitlementMap.set(entitlement.microapp_id, entitlement);
  }

  const deploymentMap = new Map<string, DeploymentRow[]>();
  for (const deployment of (deployments ?? []) as DeploymentRow[]) {
    const current = deploymentMap.get(deployment.microapp_id) ?? [];
    current.push(deployment);
    deploymentMap.set(deployment.microapp_id, current);
  }

  const feedItems: XOOSFeedMicroapp[] = [];

  for (const microapp of (microapps ?? []) as MicroappRow[]) {
    const entitlement = entitlementMap.get(microapp.uuid);
    if (!entitlement) continue;

    const authorized = findAuthorizedMicroapp(
      authorization,
      microapp.microapp_key,
      "XOOS"
    );
    if (!authorized || !authorized.permissions.includes("READ")) continue;

    const selected = selectDeployment(
      deploymentMap.get(microapp.uuid) ?? [],
      entitlement
    );
    if (!selected) continue;

    const secure = validateDeploymentMetadata(selected);
    if (!secure) continue;

    feedItems.push({
      microappKey: microapp.microapp_key,
      source: "XOOS",
      permissions: [...authorized.permissions],
      displayName: microapp.display_name,
      elementName: microapp.element_name,
      deliveryType: microapp.delivery_type,
      version: selected.version,
      integrity: secure.integrity,
      contractVersion: microapp.contract_version,
      minimumRuntimeVersion: microapp.minimum_runtime_version
    });
  }

  return {
    schemaVersion: "1",
    clientId,
    runtimeVersion: config.runtimeVersion,
    generatedAt: new Date().toISOString(),
    microapps: feedItems
  };
}

export async function issueMicroappArtifactAccess(
  db: SupabaseClient,
  config: RuntimeBffConfig,
  identity: XOIdentity,
  clientId: string,
  environment: string,
  microappKey: string,
  authorization: EffectiveAuthorization
): Promise<XOOSMicroappArtifactAccess> {
  assertClientBinding(identity, clientId);

  const authorized = findAuthorizedMicroapp(authorization, microappKey, "XOOS");
  if (!authorized || !authorized.permissions.includes("READ")) {
    throw new HttpError(
      403,
      "MICROAPP_ACCESS_DENIED",
      `READ permission is required for Microapp '${microappKey}'.`
    );
  }

  const resolved = await resolveAuthorizedMicroappDeployment(
    db,
    clientId,
    environment,
    microappKey
  );

  const [manifestSignedResult, entrySignedResult] = await Promise.all([
    db.storage.from(resolved.storageBucket).createSignedUrl(
      resolved.manifestPath,
      config.microappSignedUrlTtlSeconds
    ),
    db.storage.from(resolved.storageBucket).createSignedUrl(
      resolved.entryPath,
      config.microappSignedUrlTtlSeconds
    )
  ]);

  if (manifestSignedResult.error || !manifestSignedResult.data?.signedUrl) {
    console.error("Microapp manifest signing failed", {
      microappKey,
      version: resolved.deployment.version,
      bucket: resolved.storageBucket,
      path: resolved.manifestPath,
      message: manifestSignedResult.error?.message ?? "Signed URL was not returned."
    });
    throw new HttpError(
      500,
      "MICROAPP_MANIFEST_SIGNING_FAILED",
      "Unable to create temporary Microapp manifest access."
    );
  }

  if (entrySignedResult.error || !entrySignedResult.data?.signedUrl) {
    console.error("Microapp entry signing failed", {
      microappKey,
      version: resolved.deployment.version,
      bucket: resolved.storageBucket,
      path: resolved.entryPath,
      message: entrySignedResult.error?.message ?? "Signed URL was not returned."
    });
    throw new HttpError(
      500,
      "MICROAPP_ENTRY_SIGNING_FAILED",
      "Unable to create temporary Microapp artifact access."
    );
  }

  return {
    microappKey: resolved.microapp.microapp_key,
    version: resolved.deployment.version,
    manifestUrl: manifestSignedResult.data.signedUrl,
    entryUrl: entrySignedResult.data.signedUrl,
    integrity: resolved.integrity,
    expiresIn: config.microappSignedUrlTtlSeconds
  };
}

export function assertClientBinding(identity: XOIdentity, requestedClientId: string): void {
  if (identity.tokenClientId && identity.tokenClientId !== requestedClientId) {
    throw new HttpError(403, "CLIENT_BINDING_MISMATCH", "XO token is not bound to the requested client.");
  }
}

async function resolveAuthorizedMicroappDeployment(
  db: SupabaseClient,
  clientId: string,
  environment: string,
  microappKey: string
): Promise<ResolvedDeployment> {
  const key = microappKey.trim();
  if (!key) {
    throw new HttpError(400, "MICROAPP_KEY_MISSING", "Microapp key is required.");
  }

  const { data: microapp, error: microappError } = await db
    .schema("xoos_control")
    .from("xoos_microapps")
    .select("uuid,microapp_key,display_name,element_name,delivery_type,contract_version,minimum_runtime_version,status,is_visible")
    .eq("microapp_key", key)
    .eq("status", "active")
    .eq("is_visible", true)
    .maybeSingle();

  if (microappError) {
    throw new HttpError(500, "MICROAPP_LOOKUP_FAILED", "Unable to resolve Microapp.");
  }
  if (!microapp) {
    throw new HttpError(404, "MICROAPP_NOT_FOUND", `Microapp '${key}' is not available.`);
  }

  const { data: entitlement, error: entitlementError } = await db
    .schema("xoos_control")
    .from("xoos_client_microapp_entitlements")
    .select("microapp_id,pinned_version,version_policy")
    .eq("client_id", clientId)
    .eq("microapp_id", microapp.uuid)
    .eq("environment", environment)
    .eq("is_enabled", true)
    .maybeSingle();

  if (entitlementError) {
    throw new HttpError(500, "MICROAPP_ENTITLEMENT_LOOKUP_FAILED", "Unable to validate Microapp entitlement.");
  }
  if (!entitlement) {
    throw new HttpError(403, "MICROAPP_NOT_ENTITLED", `Client is not entitled to Microapp '${key}'.`);
  }

  const { data: deployments, error: deploymentError } = await db
    .schema("xoos_control")
    .from("xoos_microapp_deployments")
    .select("microapp_id,environment,version,storage_bucket,manifest_path,entry_path,integrity,status")
    .eq("microapp_id", microapp.uuid)
    .eq("environment", environment)
    .eq("status", "active");

  if (deploymentError) {
    throw new HttpError(500, "MICROAPP_DEPLOYMENT_LOOKUP_FAILED", "Unable to resolve Microapp deployment.");
  }

  const selected = selectDeployment(
    (deployments ?? []) as DeploymentRow[],
    entitlement as EntitlementRow
  );

  if (!selected) {
    throw new HttpError(
      404,
      "MICROAPP_DEPLOYMENT_NOT_FOUND",
      `No active deployment is available for Microapp '${key}'.`
    );
  }

  const secure = validateDeploymentMetadata(selected);
  if (!secure) {
    throw new HttpError(
      500,
      "MICROAPP_DEPLOYMENT_INVALID",
      "Microapp deployment is missing valid private-storage security metadata."
    );
  }

  return {
    microapp: microapp as MicroappRow,
    deployment: selected,
    ...secure
  };
}

function selectDeployment(
  deployments: DeploymentRow[],
  entitlement: EntitlementRow
): DeploymentRow | undefined {
  if (entitlement.version_policy === "pinned" && entitlement.pinned_version) {
    return deployments.find((deployment) => deployment.version === entitlement.pinned_version);
  }

  return [...deployments].sort((a, b) => compareVersions(b.version, a.version))[0];
}

function validateDeploymentMetadata(
  deployment: DeploymentRow
): {
  integrity: string;
  storageBucket: string;
  manifestPath: string;
  entryPath: string;
} | null {
  const storageBucket = deployment.storage_bucket?.trim() ?? "";
  const manifestPath = deployment.manifest_path?.trim() ?? "";
  const entryPath = deployment.entry_path?.trim() ?? "";
  const integrity = normalizeIntegrity(deployment.integrity);

  if (
    !storageBucket ||
    !manifestPath ||
    !entryPath ||
    !integrity ||
    isAbsoluteUrl(manifestPath) ||
    isAbsoluteUrl(entryPath)
  ) {
    return null;
  }

  return { integrity, storageBucket, manifestPath, entryPath };
}

function normalizeIntegrity(value: string | null | undefined): string | null {
  if (typeof value !== "string") return null;
  const match = /^sha256:([0-9a-f]{64})$/i.exec(value.trim());
  const digest = match?.[1];
  return digest ? `sha256:${digest.toLowerCase()}` : null;
}

function isAbsoluteUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

function compareVersions(a: string, b: string): number {
  const aa = a.split(".").map((value) => Number.parseInt(value, 10) || 0);
  const bb = b.split(".").map((value) => Number.parseInt(value, 10) || 0);
  const length = Math.max(aa.length, bb.length, 3);

  for (let i = 0; i < length; i += 1) {
    const diff = (aa[i] ?? 0) - (bb[i] ?? 0);
    if (diff !== 0) return diff;
  }

  return 0;
}
