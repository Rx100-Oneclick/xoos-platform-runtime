import type { SupabaseClient } from "@supabase/supabase-js";
import type {
  XOOSRuntimeBootstrap,
  XOOSRuntimeContext
} from "@xoos/contracts";
import type { XOIdentity } from "./auth";
import {
  resolveApplicationAuthorization,
  type EffectiveAuthorization
} from "./authorization";
import { AuthorizationSnapshotCache } from "./authorization-cache";
import type { RuntimeBffConfig } from "./config";
import { buildRuntimeFeed } from "./feed";
import {
  validateApplicationAccess,
  type RuntimeApplicationAccess
} from "./application-access";
import type { RuntimeClientRegistration } from "./origin";

export interface RuntimeAuthorizationState {
  access: RuntimeApplicationAccess;
  authorization: EffectiveAuthorization;
}

export async function resolveRuntimeAuthorizationState(input: {
  xoAuthDb: SupabaseClient;
  servicesDb: SupabaseClient;
  config: RuntimeBffConfig;
  identity: XOIdentity;
  clientRegistration: RuntimeClientRegistration;
  authorizationCache: AuthorizationSnapshotCache;
}): Promise<RuntimeAuthorizationState> {
  const access = await validateApplicationAccess(
    input.xoAuthDb,
    input.identity,
    input.clientRegistration
  );

  const sessionId = input.identity.sessionId!;
  const authorization = await input.authorizationCache.getOrResolve(
    {
      sessionId,
      userId: input.identity.userId,
      tenantId: access.tenantId,
      applicationId: access.applicationId
    },
    () =>
      resolveApplicationAuthorization(input.servicesDb, {
        userId: input.identity.userId,
        tenantId: access.tenantId,
        applicationId: access.applicationId
      })
  );

  return { access, authorization };
}

export function createRuntimeContext(
  identity: XOIdentity,
  clientRegistration: RuntimeClientRegistration,
  state: RuntimeAuthorizationState,
  config: RuntimeBffConfig
): XOOSRuntimeContext {
  return {
    user: { id: identity.userId },
    tenant: { id: state.access.tenantId },
    client: { id: clientRegistration.clientId },
    application: {
      id: state.access.applicationId,
      key: state.access.applicationKey
    },
    roles: state.authorization.roles,
    runtime: { minimumVersion: config.minimumRuntimeVersion },
    scopes: identity.scopes
  };
}

export async function buildRuntimeBootstrap(input: {
  xoAuthDb: SupabaseClient;
  servicesDb: SupabaseClient;
  config: RuntimeBffConfig;
  identity: XOIdentity;
  clientRegistration: RuntimeClientRegistration;
  authorizationCache: AuthorizationSnapshotCache;
}): Promise<XOOSRuntimeBootstrap> {
  const state = await resolveRuntimeAuthorizationState(input);
  const feed = await buildRuntimeFeed(
    input.xoAuthDb,
    input.config,
    input.identity,
    input.clientRegistration.clientId,
    input.clientRegistration.environment,
    state.authorization
  );

  return {
    context: createRuntimeContext(
      input.identity,
      input.clientRegistration,
      state,
      input.config
    ),
    feed
  };
}
