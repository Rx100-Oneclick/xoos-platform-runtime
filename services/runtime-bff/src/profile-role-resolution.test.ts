import { describe, expect, it } from "vitest";
import { resolveProfileRoleName, type ProfileRoleRow } from "./profile-role-resolution";

const tenantId = "b6e79e35-4d49-441d-87fb-1431e2f4b3be";
const base: ProfileRoleRow = {
  uuid: "6e637afd-7622-4db0-876e-df8aa646e7f5",
  name: "super admin",
  tenant_id: null,
  role_type: "SYSTEM",
  system_defined: true,
  status: "ACTIVE"
};

describe("Profile Viewer role resolution", () => {
  it("resolves active global system role with null tenant", () => {
    expect(resolveProfileRoleName([base], base.uuid, tenantId)).toBe("super admin");
  });
  it("resolves active roles owned by authorized tenant", () => {
    expect(resolveProfileRoleName([{...base, tenant_id:tenantId,role_type:"CUSTOM",system_defined:false}],base.uuid,tenantId)).toBe("super admin");
  });
  it("rejects roles owned by another tenant", () => {
    expect(resolveProfileRoleName([{...base,tenant_id:"00000000-0000-4000-8000-000000000002"}],base.uuid,tenantId)).toBeNull();
  });
  it("rejects global roles that are not explicitly system-defined", () => {
    expect(resolveProfileRoleName([{...base,system_defined:false}],base.uuid,tenantId)).toBeNull();
    expect(resolveProfileRoleName([{...base,role_type:"CUSTOM"}],base.uuid,tenantId)).toBeNull();
  });
  it("rejects inactive, mismatched, missing and ambiguous role records", () => {
    expect(resolveProfileRoleName([{...base,status:"INACTIVE"}],base.uuid,tenantId)).toBeNull();
    expect(resolveProfileRoleName([{...base,uuid:"00000000-0000-4000-8000-000000000003"}],base.uuid,tenantId)).toBeNull();
    expect(resolveProfileRoleName([],base.uuid,tenantId)).toBeNull();
    expect(resolveProfileRoleName([base,base],base.uuid,tenantId)).toBeNull();
    expect(resolveProfileRoleName([base],null,tenantId)).toBeNull();
  });
});
