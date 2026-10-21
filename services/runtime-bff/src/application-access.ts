import type { SupabaseClient } from "@supabase/supabase-js";
import { HttpError, type XOIdentity } from "./auth";
import type { RuntimeClientRegistration } from "./origin";

export interface RuntimeApplicationAccess {
  applicationId: string;
  applicationKey: string;
  memberId: string;
  tenantId: string;
}

export async function validateApplicationAccess(
  db: SupabaseClient,
  identity: XOIdentity,
  registration: RuntimeClientRegistration
): Promise<RuntimeApplicationAccess> {
  const tenantId = identity.tenantId?.trim() ?? "";
  const sessionId = identity.sessionId?.trim() ?? "";

  if (!tenantId) {
    throw new HttpError(403, "TENANT_CONTEXT_MISSING", "XO tenant context is required.");
  }
  if (!sessionId) {
    throw new HttpError(401, "SESSION_CONTEXT_MISSING", "XO session context is required.");
  }

  const now = Date.now();

  const [
    { data: session, error: sessionError },
    { data: application, error: applicationError },
    { data: organizationApplication, error: organizationApplicationError },
    { data: memberships, error: membershipError }
  ] = await Promise.all([
    db
      .from("xo_sessions")
      .select(
        "session_id,user_id,tenant_id,client_id,application_id,status,absolute_expiry_at,inactivity_expiry_at"
      )
      .eq("session_id", sessionId)
      .maybeSingle(),
    db
      .from("xo_applications")
      .select("uuid,app_key,app_status")
      .eq("uuid", registration.applicationId)
      .maybeSingle(),
    db
      .from("organization_applications")
      .select("uuid,status")
      .eq("tenant_id", tenantId)
      .eq("application_id", registration.applicationId)
      .maybeSingle(),
    db
      .from("organization_members")
      .select("member_id,status,archived")
      .eq("tenant_id", tenantId)
      .eq("user_id", identity.userId)
      .limit(2)
  ]);

  if (sessionError) {
    throw new HttpError(500, "SESSION_LOOKUP_FAILED", "Unable to validate the XO session.");
  }

  if (
    !session ||
    session.user_id !== identity.userId ||
    session.client_id !== registration.clientId ||
    session.tenant_id !== tenantId ||
    session.status !== "active" ||
    (session.application_id && session.application_id !== registration.applicationId)
  ) {
    throw new HttpError(401, "SESSION_INACTIVE", "XO session is not active for this application.");
  }

  const absoluteExpiry = Date.parse(session.absolute_expiry_at);
  const inactivityExpiry = Date.parse(session.inactivity_expiry_at);
  if (
    !Number.isFinite(absoluteExpiry) ||
    !Number.isFinite(inactivityExpiry) ||
    absoluteExpiry <= now ||
    inactivityExpiry <= now
  ) {
    throw new HttpError(401, "SESSION_EXPIRED", "XO session has expired.");
  }

  if (applicationError) {
    throw new HttpError(500, "APPLICATION_LOOKUP_FAILED", "Unable to resolve the XO application.");
  }
  if (!application || application.app_status !== "active") {
    throw new HttpError(403, "APPLICATION_NOT_ACTIVE", "XO application is not active.");
  }

  if (organizationApplicationError) {
    throw new HttpError(
      500,
      "APPLICATION_ACCESS_LOOKUP_FAILED",
      "Unable to validate organization application access."
    );
  }
  if (!organizationApplication || organizationApplication.status !== "active") {
    throw new HttpError(
      403,
      "APPLICATION_ACCESS_DENIED",
      "Organization does not have active access to this application."
    );
  }

  if (membershipError) {
    throw new HttpError(
      500,
      "ORGANIZATION_MEMBERSHIP_LOOKUP_FAILED",
      "Unable to validate organization membership."
    );
  }

  const activeMemberships = (memberships ?? []).filter(
    (member) => member.status === "active" && member.archived !== true
  );

  if (activeMemberships.length === 0) {
    throw new HttpError(
      403,
      "ORGANIZATION_MEMBERSHIP_INACTIVE",
      "User is not an active member of this organization."
    );
  }

  if (activeMemberships.length > 1) {
    throw new HttpError(
      409,
      "ORGANIZATION_MEMBERSHIP_AMBIGUOUS",
      "Multiple active organization memberships were found for this user."
    );
  }

  const memberId = activeMemberships[0]!.member_id as string;
  const { data: memberApplication, error: memberApplicationError } = await db
    .from("organization_member_applications")
    .select("access_id,access_status")
    .eq("member_id", memberId)
    .eq("tenant_id", tenantId)
    .eq("application_id", registration.applicationId)
    .maybeSingle();

  if (memberApplicationError) {
    throw new HttpError(
      500,
      "MEMBER_APPLICATION_ACCESS_LOOKUP_FAILED",
      "Unable to validate user application access."
    );
  }

  if (!memberApplication || memberApplication.access_status !== "active") {
    throw new HttpError(
      403,
      "APPLICATION_ACCESS_DENIED",
      "User does not have active access to this application."
    );
  }

  return {
    applicationId: application.uuid,
    applicationKey: application.app_key,
    memberId,
    tenantId
  };
}
