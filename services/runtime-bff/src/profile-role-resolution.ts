/**
 * XO Auth organization_members.role_id references Services roles.uuid.
 * Services system roles may be intentionally global (tenant_id = NULL).
 * Reject cross-tenant and inactive roles. A global role is acceptable only
 * when explicitly marked system-defined with role_type SYSTEM.
 */
export type ProfileRoleRow = {
  uuid: string;
  name: string | null;
  tenant_id: string | null;
  role_type: string | null;
  system_defined: boolean | null;
  status: string | null;
};

export function resolveProfileRoleName(
  roles: readonly ProfileRoleRow[],
  assignedRoleId: string | null | undefined,
  authorizedTenantId: string
): string | null {
  if (!assignedRoleId || roles.length !== 1) return null;

  const role = roles[0];
  if (role.uuid !== assignedRoleId || role.status?.toUpperCase() !== "ACTIVE") return null;

  const tenantOwned = role.tenant_id === authorizedTenantId;
  const globalSystemRole =
    role.tenant_id === null &&
    role.role_type?.toUpperCase() === "SYSTEM" &&
    role.system_defined === true;

  if (!tenantOwned && !globalSystemRole) return null;
  const name = role.name?.trim();
  return name || null;
}
