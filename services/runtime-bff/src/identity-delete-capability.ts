import { HttpError } from "./auth";
import type { CapabilityContext } from "./capabilities";

/**
 * Deletion is scoped to an organization membership, never the global XO user.
 * All membership/access/session changes and audit writes happen in one XO Auth
 * database transaction inside the service-role-only RPC.
 */
export async function deleteIdentityUser(
  context: CapabilityContext,
  input: unknown
): Promise<unknown> {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new HttpError(400, "IDENTITY_DELETE_INPUT_INVALID", "Expected an object.");
  }
  const value = input as Record<string, unknown>;
  const memberId = value.member_id;
  if (typeof memberId !== "string" ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(memberId)) {
    throw new HttpError(400, "IDENTITY_DELETE_MEMBER_INVALID", "Valid member_id is required.");
  }
  if (value.confirm !== true) {
    throw new HttpError(400, "IDENTITY_DELETE_NOT_CONFIRMED", "Explicit confirmation is required.");
  }
  const tenantId = context.identity.tenantId;
  if (!tenantId) {
    throw new HttpError(403, "IDENTITY_DELETE_TENANT_MISSING", "Authorized tenant required.");
  }

  // Additional defense: only an active, authorized tenant administrator can
  // perform this destructive capability, never on their own membership.
  const { data: actor, error: actorError } = await context.xoAuthDb
    .from("organization_members")
    .select("member_id,user_id,status,archived")
    .eq("tenant_id", tenantId)
    .eq("member_id", memberId)
    .maybeSingle();
  if (actorError) throw new HttpError(502, "IDENTITY_DELETE_LOOKUP_FAILED", "Cannot validate target membership.");
  if (!actor || actor.status !== "active" || actor.archived === true) {
    throw new HttpError(409, "IDENTITY_DELETE_NOT_ELIGIBLE", "The selected membership is not active.");
  }
  if (!actor.user_id) {
    throw new HttpError(409, "IDENTITY_DELETE_USER_MISSING", "Target membership has no linked XO user.");
  }
  if (actor.user_id === context.identity.userId) {
    throw new HttpError(403, "IDENTITY_DELETE_SELF_DENIED", "You cannot delete your own membership.");
  }

  // Never silently delete privileged administrators using the ordinary
  // lifecycle. A separate elevated/approval flow can be added later.
  const { data: roleMember, error: roleMemberError } = await context.xoAuthDb
    .from("organization_members")
    .select("role_id")
    .eq("tenant_id", tenantId)
    .eq("member_id", memberId)
    .single();
  if (roleMemberError) throw new HttpError(502, "IDENTITY_DELETE_ROLE_FAILED", "Unable to validate target role.");
  if (!roleMember?.role_id) throw new HttpError(409, "IDENTITY_DELETE_ROLE_MISSING", "Target member role is unavailable.");
  const { data: role, error: roleError } = await context.servicesDb
    .from("roles")
    .select("name,tenant_id,role_type,system_defined,status")
    .eq("uuid", roleMember.role_id)
    .limit(2);
  if (roleError || !role?.length) {
    throw new HttpError(502, "IDENTITY_DELETE_ROLE_FAILED", "Unable to validate target role.");
  }
  const matchedRole = role.find((r) => r.tenant_id === tenantId || r.tenant_id == null);
  if (!matchedRole || typeof matchedRole.name !== "string") {
    throw new HttpError(403, "IDENTITY_DELETE_ROLE_UNVERIFIED", "Target role cannot be verified.");
  }
  if (/\b(admin|administrator|owner|superadmin|super admin)\b/i.test(matchedRole.name)) {
    throw new HttpError(403, "IDENTITY_DELETE_PROTECTED_ROLE", "Administrator accounts require a separate approval workflow.");
  }

  const correlationId = crypto.randomUUID();
  const { data, error } = await context.xoAuthDb.rpc("xoos_soft_delete_organization_member", {
    p_tenant_id: tenantId,
    p_member_id: memberId,
    p_actor_user_id: context.identity.userId,
    p_retention_days: 30,
    p_correlation_id: correlationId
  });
  if (error) {
    const code = error.code === "23505" ? "IDENTITY_ALREADY_DELETED" : "IDENTITY_DELETE_FAILED";
    // Avoid leaking database exception details to the browser.
    throw new HttpError(error.code === "23505" ? 409 : 502, code,
      error.code === "23505" ? "A deletion is already in progress." : "Unable to complete the deletion. No success was confirmed.");
  }
  if (!data || typeof data !== "object" || data.ok !== true) {
    throw new HttpError(502, "IDENTITY_DELETE_RESPONSE_INVALID", "XO Auth deletion response was invalid.");
  }
  return data;
}
