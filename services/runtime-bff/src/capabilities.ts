import type { SupabaseClient } from "@supabase/supabase-js";
import { getProfileViewerData } from "./profile-viewer-capability";
import { listIdentityUsers, getIdentityUser, listIdentityEvents } from "./user-identity-capabilities";
import { deleteIdentityUser } from "./identity-delete-capability";
import { deletedUsersSummary,deletedUsersList,deletedUserDetail,deletedUserTimeline,deletedUserRestore,deletedUserPurge } from "./deleted-users-capabilities";
import { listSignInLogs, getSignInLogDetail, listSignInLogTimeline } from "./signin-logs-capabilities";
import type { XOOSCapabilityResponse } from "@xoos/contracts";
import type { XOIdentity } from "./auth";
import { HttpError } from "./auth";
import {
  hasMicroappPermission,
  type EffectiveAuthorization
} from "./authorization";
import {
  proxyXOAuthList,
  proxyXOAuthOrganizationsList,
  proxyXOAuthOrganizationMemberUpdate
} from "./xo-auth-capabilities";

export interface CapabilityContext {
  identity: XOIdentity;
  xoAuthDb: SupabaseClient;
  servicesDb: SupabaseClient;
  clientId: string;
  applicationId: string;
  traceId: string;
  xoAuthFunctionsBaseUrl: string;
  authorization: EffectiveAuthorization;
  microappKey?: string;
}

type Handler = (context: CapabilityContext, input: unknown) => Promise<unknown>;

export interface CapabilityRegistration {
  handler: Handler;
  microappKey?: string;
  requiredAction?: string;
}

const handlers = new Map<string, CapabilityRegistration>();

function registerBuiltin(name: string, handler: Handler): void {
  handlers.set(name, { handler });
}

registerBuiltin("runtime.health", async (context) => ({
  status: "ok",
  userId: context.identity.userId,
  clientId: context.clientId,
  applicationId: context.applicationId
}));

registerBuiltin(
  "xo-auth.applications.list",
  (context, input) => proxyXOAuthList(context, "xo-applications", input)
);

registerBuiltin(
  "xo-auth.organizations.list",
  (context) => proxyXOAuthOrganizationsList(context)
);

registerBuiltin(
  "xo-auth.organization-members.list",
  (context, input) => proxyXOAuthList(context, "xo-organization-members", input)
);

registerBuiltin(
  "xo-auth.organization-members.update",
  (context, input) => proxyXOAuthOrganizationMemberUpdate(context, input)
);

registerCapability("xo-auth.profile.get", {
  microappKey: "profile-viewer",
  requiredAction: "READ",
  handler: (context,input) => getProfileViewerData(context,input,{
    xoAuthDb:context.xoAuthDb,servicesDb:context.servicesDb
  })
});

registerCapability("xo-auth.identity.users.list", {
  microappKey: "user-identity", requiredAction: "READ",
  handler: listIdentityUsers
});
registerCapability("xo-auth.identity.user.get", {
  microappKey: "user-identity", requiredAction: "READ",
  handler: getIdentityUser
});
registerCapability("xo-auth.identity.events.list", {
  microappKey: "user-identity", requiredAction: "READ",
  handler: listIdentityEvents
});
registerCapability("xo-auth.identity.user.delete", {
  microappKey: "user-identity", requiredAction: "DELETE",
  handler: deleteIdentityUser
});

registerCapability("xo-auth.deleted-users.summary", {microappKey:"deleted-users",requiredAction:"READ",handler:deletedUsersSummary});
registerCapability("xo-auth.deleted-users.list", {microappKey:"deleted-users",requiredAction:"READ",handler:deletedUsersList});
registerCapability("xo-auth.deleted-users.detail", {microappKey:"deleted-users",requiredAction:"READ",handler:deletedUserDetail});
registerCapability("xo-auth.deleted-users.timeline", {microappKey:"deleted-users",requiredAction:"READ",handler:deletedUserTimeline});
registerCapability("xo-auth.deleted-users.restore", {microappKey:"deleted-users",requiredAction:"UPDATE",handler:deletedUserRestore});
registerCapability("xo-auth.deleted-users.purge", {microappKey:"deleted-users",requiredAction:"DELETE",handler:deletedUserPurge});

registerCapability("xo-auth.signin-logs.list", {microappKey:"signin-logs",requiredAction:"READ",handler:listSignInLogs});
registerCapability("xo-auth.signin-logs.detail", {microappKey:"signin-logs",requiredAction:"READ",handler:getSignInLogDetail});
registerCapability("xo-auth.signin-logs.timeline", {microappKey:"signin-logs",requiredAction:"READ",handler:listSignInLogTimeline});

export function registerCapability(
  name: string,
  registration: Handler | CapabilityRegistration
): void {
  if (!name.trim()) throw new Error("Capability name is required.");

  const normalized: CapabilityRegistration =
    typeof registration === "function" ? { handler: registration } : registration;

  if (normalized.requiredAction && !normalized.microappKey?.trim()) {
    throw new Error(
      `Capability '${name}' must declare microappKey when requiredAction is configured.`
    );
  }

  handlers.set(name, normalized);
}

export async function executeCapability(
  capability: string,
  context: CapabilityContext,
  input: unknown
): Promise<XOOSCapabilityResponse> {
  const registration = handlers.get(capability);
  if (!registration) {
    throw new HttpError(
      404,
      "CAPABILITY_NOT_FOUND",
      `Capability '${capability}' is not registered.`
    );
  }

  if (registration.requiredAction && registration.microappKey) {
    if (context.microappKey !== registration.microappKey) {
      throw new HttpError(
        403,
        "CAPABILITY_MICROAPP_MISMATCH",
        "Capability is not registered for the requesting Microapp."
      );
    }

    if (
      !hasMicroappPermission(
        context.authorization,
        registration.microappKey,
        registration.requiredAction
      )
    ) {
      throw new HttpError(
        403,
        "PERMISSION_DENIED",
        `Permission '${registration.requiredAction.trim().toUpperCase()}' is required.`
      );
    }
  }

  const data = await registration.handler(context, input);
  return { ok: true, data, traceId: context.traceId };
}
