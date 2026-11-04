-- XO Auth / public schema. Backend-only lifecycle RPCs.
-- Review in staging before applying. Does not mutate records until invoked.
-- Restore reactivates membership only; never reactivates old sessions/app access.
CREATE OR REPLACE FUNCTION public.xoos_restore_organization_member(
 p_tenant_id uuid,p_deletion_id uuid,p_actor_user_id uuid,p_correlation_id uuid DEFAULT NULL
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
DECLARE r public.deleted_user_records%ROWTYPE; m public.organization_members%ROWTYPE;
BEGIN
 IF p_tenant_id IS NULL OR p_deletion_id IS NULL OR p_actor_user_id IS NULL THEN
  RAISE EXCEPTION 'Missing restoration identity' USING ERRCODE='22023';
 END IF;
 PERFORM 1 FROM public.organization_members
  WHERE tenant_id=p_tenant_id AND user_id=p_actor_user_id
    AND status='active' AND archived IS NOT TRUE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Actor not active in tenant' USING ERRCODE='42501'; END IF;
 SELECT * INTO r FROM public.deleted_user_records
  WHERE tenant_id=p_tenant_id AND deletion_id=p_deletion_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Deletion not found' USING ERRCODE='P0002'; END IF;
 IF r.status NOT IN ('retained','restore_requested') OR r.restore_deadline_at<=transaction_timestamp()
    OR r.purged_at IS NOT NULL THEN
  RAISE EXCEPTION 'Restoration not eligible' USING ERRCODE='23514';
 END IF;
 SELECT * INTO m FROM public.organization_members
  WHERE tenant_id=p_tenant_id AND member_id=r.member_id FOR UPDATE;
 IF NOT FOUND OR m.user_id IS DISTINCT FROM r.user_id OR m.archived IS NOT TRUE THEN
  RAISE EXCEPTION 'Original membership unavailable' USING ERRCODE='23514';
 END IF;
 UPDATE public.organization_members SET status='active',archived=false,updated_at=transaction_timestamp()
  WHERE tenant_id=p_tenant_id AND member_id=r.member_id;
 UPDATE public.deleted_user_records SET status='restored',restored_at=transaction_timestamp(),
  restored_by=p_actor_user_id WHERE deletion_id=r.deletion_id AND tenant_id=p_tenant_id;
 INSERT INTO public.deleted_user_events(deletion_id,tenant_id,event_type,actor_user_id,event_at,correlation_id,metadata)
 VALUES(r.deletion_id,p_tenant_id,'user_restored',p_actor_user_id,transaction_timestamp(),p_correlation_id,
  '{"application_access":"requires_regrant","sessions":"new_signin_required"}'::jsonb);
 RETURN jsonb_build_object('ok',true,'status','restored','deletion_id',r.deletion_id,'member_id',r.member_id);
END;$$;
REVOKE ALL ON FUNCTION public.xoos_restore_organization_member(uuid,uuid,uuid,uuid) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.xoos_restore_organization_member(uuid,uuid,uuid,uuid) TO service_role;

-- This is a tenant-membership purge, not global xo_users deletion.
-- It scrubs local membership PII after retention, but any other linked XOOS
-- source systems require independent lifecycle cleanup under policy.
CREATE OR REPLACE FUNCTION public.xoos_purge_organization_member(
 p_tenant_id uuid,p_deletion_id uuid,p_actor_user_id uuid,p_correlation_id uuid DEFAULT NULL
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
DECLARE r public.deleted_user_records%ROWTYPE; m public.organization_members%ROWTYPE;
BEGIN
 IF p_tenant_id IS NULL OR p_deletion_id IS NULL OR p_actor_user_id IS NULL THEN
  RAISE EXCEPTION 'Missing purge identity' USING ERRCODE='22023';
 END IF;
 PERFORM 1 FROM public.organization_members
  WHERE tenant_id=p_tenant_id AND user_id=p_actor_user_id AND status='active' AND archived IS NOT TRUE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Actor not active in tenant' USING ERRCODE='42501'; END IF;
 SELECT * INTO r FROM public.deleted_user_records
  WHERE tenant_id=p_tenant_id AND deletion_id=p_deletion_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Deletion not found' USING ERRCODE='P0002'; END IF;
 IF r.status NOT IN ('retained','restore_requested','purge_pending','purge_failed') OR r.legal_hold
   OR r.scheduled_purge_at>transaction_timestamp() OR r.purged_at IS NOT NULL THEN
  RAISE EXCEPTION 'Purge not eligible' USING ERRCODE='23514';
 END IF;
 SELECT * INTO m FROM public.organization_members
  WHERE tenant_id=p_tenant_id AND member_id=r.member_id FOR UPDATE;
 IF NOT FOUND OR m.archived IS NOT TRUE OR m.user_id IS DISTINCT FROM r.user_id THEN
  RAISE EXCEPTION 'Original archived membership unavailable' USING ERRCODE='23514';
 END IF;
 -- No session revival; remove any remaining grants.
 DELETE FROM public.organization_member_applications
  WHERE tenant_id=p_tenant_id AND member_id=r.member_id;
 -- Preserve stable membership ID for relational integrity, but scrub personal
 -- membership fields and unlink global XO identity.
 UPDATE public.organization_members SET
  email='purged-'||member_id::text||'@deleted.invalid',
  full_name='Purged member',
  mobile_number=NULL,designation=NULL,business_unit=NULL,reporting_manager=NULL,
  avatar_url=NULL,email_lookup=NULL,activation_details=NULL,expiry_details=NULL,
  user_id=NULL, archived=true,status='suspended',updated_at=transaction_timestamp()
 WHERE member_id=r.member_id AND tenant_id=p_tenant_id;
 UPDATE public.deleted_user_records SET status='purged',purged_at=transaction_timestamp(),
  purged_by=p_actor_user_id WHERE deletion_id=r.deletion_id AND tenant_id=p_tenant_id;
 INSERT INTO public.deleted_user_events(deletion_id,tenant_id,event_type,actor_user_id,event_at,correlation_id,metadata)
 VALUES(r.deletion_id,p_tenant_id,'user_permanently_deleted',p_actor_user_id,transaction_timestamp(),
  p_correlation_id,'{"scope":"tenant_membership_local_pii","global_user":"preserved"}'::jsonb);
 RETURN jsonb_build_object('ok',true,'status','purged','scope','tenant_membership',
  'deletion_id',r.deletion_id,'member_id',r.member_id);
END;$$;
REVOKE ALL ON FUNCTION public.xoos_purge_organization_member(uuid,uuid,uuid,uuid) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.xoos_purge_organization_member(uuid,uuid,uuid,uuid) TO service_role;
