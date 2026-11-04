import { describe, expect, it, vi } from "vitest";
import { deleteIdentityUser } from "./identity-delete-capability";
import type { CapabilityContext } from "./capabilities";

const ACTOR = "11111111-1111-4111-8111-111111111111";
const TARGET = "22222222-2222-4222-8222-222222222222";
const MEMBER = "33333333-3333-4333-8333-333333333333";
const TENANT = "44444444-4444-4444-8444-444444444444";

function harness(targetRole = "employee", targetUser = TARGET) {
  const rpc = vi.fn().mockResolvedValue({
    data: { ok: true, member_id: MEMBER, deletion_id: "55555555-5555-4555-8555-555555555555" },
    error: null
  });
  const xoAuthDb = {
    from: vi.fn().mockImplementation(() => ({
      select: () => ({
        eq: () => ({
          eq: () => ({
            maybeSingle: async () => ({ data: { user_id: targetUser, status: "active", archived: false }, error: null }),
            single: async () => ({ data: { role_id: "66666666-6666-4666-8666-666666666666" }, error: null })
          })
        })
      })
    })),
    rpc
  };
  const servicesDb = {
    from: vi.fn().mockImplementation(() => ({
      select: () => ({
        eq: () => ({
          limit: async () => ({ data: [{ name: targetRole, tenant_id: TENANT }], error: null })
        })
      })
    }))
  };
  const context = {
    identity: { userId: ACTOR, tenantId: TENANT },
    xoAuthDb, servicesDb
  } as unknown as CapabilityContext;
  return { context, rpc };
}

describe("identity deletion capability", () => {
  it("requires a validated member ID and explicit confirmation", async () => {
    const { context, rpc } = harness();
    await expect(deleteIdentityUser(context, { member_id: "bad", confirm: true })).rejects.toMatchObject({ status: 400 });
    await expect(deleteIdentityUser(context, { member_id: MEMBER })).rejects.toMatchObject({ status: 400 });
    expect(rpc).not.toHaveBeenCalled();
  });

  it("denies self-deletion", async () => {
    const { context, rpc } = harness("employee", ACTOR);
    await expect(deleteIdentityUser(context, { member_id: MEMBER, confirm: true })).rejects.toMatchObject({
      status: 403, code: "IDENTITY_DELETE_SELF_DENIED"
    });
    expect(rpc).not.toHaveBeenCalled();
  });

  it("denies protected administrator role", async () => {
    const { context, rpc } = harness("super admin");
    await expect(deleteIdentityUser(context, { member_id: MEMBER, confirm: true })).rejects.toMatchObject({
      status: 403, code: "IDENTITY_DELETE_PROTECTED_ROLE"
    });
    expect(rpc).not.toHaveBeenCalled();
  });

  it("calls the backend transaction for an eligible, authorized request", async () => {
    const { context, rpc } = harness();
    const result = await deleteIdentityUser(context, { member_id: MEMBER, confirm: true });
    expect(result).toMatchObject({ ok: true, member_id: MEMBER });
    expect(rpc).toHaveBeenCalledWith("xoos_soft_delete_organization_member", expect.objectContaining({
      p_tenant_id: TENANT, p_member_id: MEMBER, p_actor_user_id: ACTOR, p_retention_days: 30
    }));
  });
});
