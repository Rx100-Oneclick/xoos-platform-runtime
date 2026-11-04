-- XO Auth public tables already exist:
--   public.deleted_user_records, public.deleted_user_events
-- Install this with a reviewed migration in XO Auth (bolngokjtpjomleifuto).
-- No existing member is deleted by installing this function.
--
-- Only the Runtime's trusted XO Auth backend service key may EXECUTE it.
-- Runtime must independently validate JWT/live session, tenant, application
-- entitlement and the user-identity Microapp DELETE permission.
CREATE OR REPLACE FUNCTION public.xoos_soft_delete_organization_member(
    p_tenant_id uuid,
    p_member_id uuid,
    p_actor_user_id uuid,
    p_retention_days integer DEFAULT 30,
    p_correlation_id uuid DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    v_actor public.organization_members%ROWTYPE;
    v_member public.organization_members%ROWTYPE;
    v_deletion_id uuid;
    v_deleted_at timestamptz := transaction_timestamp();
    v_deadline timestamptz;
    v_applications_revoked integer := 0;
    v_sessions_ended integer := 0;
BEGIN
    IF p_tenant_id IS NULL OR p_member_id IS NULL OR p_actor_user_id IS NULL THEN
        RAISE EXCEPTION 'Tenant, member, and actor are required' USING ERRCODE = '22023';
    END IF;
    IF p_retention_days IS NULL OR p_retention_days NOT BETWEEN 1 AND 3650 THEN
        RAISE EXCEPTION 'Invalid retention days' USING ERRCODE = '22023';
    END IF;

    -- Verify actor is an active member of this tenant; the caller-side
    -- Runtime enforces stronger DELETE RBAC and admin authorization.
    SELECT * INTO v_actor
      FROM public.organization_members
     WHERE tenant_id = p_tenant_id
       AND user_id = p_actor_user_id
       AND status = 'active'
       AND archived IS NOT TRUE
     LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Actor not active in tenant' USING ERRCODE = '42501';
    END IF;

    SELECT * INTO v_member
      FROM public.organization_members
     WHERE tenant_id = p_tenant_id AND member_id = p_member_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Tenant membership not found' USING ERRCODE = 'P0002';
    END IF;
    IF v_member.user_id IS NULL THEN
        RAISE EXCEPTION 'Membership has no linked XO identity' USING ERRCODE = '22023';
    END IF;
    IF v_member.user_id = p_actor_user_id THEN
        RAISE EXCEPTION 'Self deletion is denied' USING ERRCODE = '42501';
    END IF;
    IF v_member.status <> 'active' OR v_member.archived IS TRUE THEN
        RAISE EXCEPTION 'Membership not eligible for deletion' USING ERRCODE = '23505';
    END IF;
    -- Unique partial index from deleted_user_records also blocks duplicates.

    v_deadline := v_deleted_at + make_interval(days => p_retention_days);

    INSERT INTO public.deleted_user_records (
        tenant_id, member_id, user_id, deleted_by, deleted_at,
        retention_days, restore_deadline_at, scheduled_purge_at,
        status, legal_hold, policy_snapshot
    ) VALUES (
        p_tenant_id, p_member_id, v_member.user_id, p_actor_user_id,
        v_deleted_at, p_retention_days, v_deadline, v_deadline,
        'retained', false,
        jsonb_build_object('policy', 'initial_fixed_retention',
                           'retention_days', p_retention_days,
                           'previous_member_status', v_member.status)
    )
    RETURNING deletion_id INTO v_deletion_id;

    -- The actual XO Auth status CHECK allows draft/active/expired/suspended.
    -- archived=true makes it ineligible for normal tenant access.
    UPDATE public.organization_members
       SET status = 'suspended', archived = true, updated_at = v_deleted_at
     WHERE tenant_id = p_tenant_id AND member_id = p_member_id;

    UPDATE public.organization_member_applications
       SET access_status = 'revoked', revoked_at = v_deleted_at,
           updated_at = v_deleted_at
     WHERE tenant_id = p_tenant_id AND member_id = p_member_id
       AND access_status <> 'revoked';
    GET DIAGNOSTICS v_applications_revoked = ROW_COUNT;

    UPDATE public.xo_sessions
       SET status = 'ended', ended_at = v_deleted_at,
           end_reason = 'user_identity_deleted', updated_at = v_deleted_at
     WHERE tenant_id = p_tenant_id AND user_id = v_member.user_id
       AND status = 'active';
    GET DIAGNOSTICS v_sessions_ended = ROW_COUNT;

    INSERT INTO public.deleted_user_events (
        deletion_id, tenant_id, event_type, actor_user_id,
        event_at, correlation_id, metadata
    ) VALUES (
        v_deletion_id, p_tenant_id, 'user_deleted',
        p_actor_user_id, v_deleted_at, p_correlation_id,
        jsonb_build_object('action', 'organization_membership_soft_delete',
                           'applications_revoked', v_applications_revoked,
                           'sessions_ended', v_sessions_ended)
    );

    INSERT INTO public.auth_audit_logs (
        event_type, tenant_id, user_id, actor_user_id, target_user_id,
        severity, details, created_at
    ) VALUES (
        'organization_member_deleted', p_tenant_id, v_member.user_id,
        p_actor_user_id, v_member.user_id, 'warning',
        jsonb_build_object('deletion_id', v_deletion_id,
                           'member_id', p_member_id,
                           'correlation_id', p_correlation_id),
        v_deleted_at
    );

    RETURN jsonb_build_object(
        'ok', true, 'deletion_id', v_deletion_id,
        'member_id', p_member_id, 'deleted_at', v_deleted_at,
        'restore_deadline_at', v_deadline,
        'applications_revoked', v_applications_revoked,
        'sessions_ended', v_sessions_ended
    );
END;
$$;

REVOKE ALL ON FUNCTION public.xoos_soft_delete_organization_member(
    uuid, uuid, uuid, integer, uuid
) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.xoos_soft_delete_organization_member(
    uuid, uuid, uuid, integer, uuid
) TO service_role;

COMMENT ON FUNCTION public.xoos_soft_delete_organization_member(
    uuid, uuid, uuid, integer, uuid
) IS 'Backend-only transactional tenant membership deletion with retention, access/session revocation and immutable audit events.';
