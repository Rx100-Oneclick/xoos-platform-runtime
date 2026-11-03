import type { SupabaseClient } from "@supabase/supabase-js";
import { HttpError } from "./auth";
import type { CapabilityContext } from "./capabilities";
import { resolveProfileRoleName, type ProfileRoleRow } from "./profile-role-resolution";

type ProfileDeps = { xoAuthDb: SupabaseClient; servicesDb: SupabaseClient };
const db = async <T>(request: PromiseLike<{data:T|null;error:any}>):Promise<T> => {
  const { data,error } = await request;
  if (error) throw new HttpError(502,"PROFILE_DATASOURCE_UNAVAILABLE","Unable to retrieve profile information.");
  return data as T;
};
const isRecord = (value:unknown):value is Record<string,unknown> =>
  !!value && typeof value==="object" && !Array.isArray(value);

export async function getProfileViewerData(
  context: CapabilityContext,
  input: unknown,
  { xoAuthDb, servicesDb }: ProfileDeps
):Promise<unknown> {
  if(input != null && (!isRecord(input) || Object.keys(input).length)) {
    throw new HttpError(400,"PROFILE_INPUT_INVALID","Self profile does not accept identity parameters.");
  }
  const {userId,tenantId,accessToken}=context.identity;
  if(!userId || !tenantId) throw new HttpError(403,"PROFILE_TENANT_REQUIRED","Tenant context is required.");

  // XO Auth userinfo enforces token validity, active XO session, tenant binding,
  // scopes and encrypted name/email decryption. Never read ciphertext into UI.
  const userInfoResponse=await fetch(
    context.xoAuthFunctionsBaseUrl.replace(/\/+$/,"")+"/oauth-userinfo",
    {headers:{Authorization:"Bearer "+accessToken,Accept:"application/json","X-Request-Id":context.traceId},signal:AbortSignal.timeout(12000)}
  ).catch(()=>{throw new HttpError(502,"XO_AUTH_UNAVAILABLE","Profile identity service unavailable.");});
  if(!userInfoResponse.ok){
    throw new HttpError(userInfoResponse.status===403?403:502,"PROFILE_IDENTITY_UNAVAILABLE","Unable to validate profile identity and scopes.");
  }
  const identity=await userInfoResponse.json() as Record<string,unknown>;
  if(identity.sub!==userId || identity.tenant_id!==tenantId || !isRecord(identity.organization)){
    throw new HttpError(403,"PROFILE_IDENTITY_MISMATCH","Authorized tenant profile is unavailable.");
  }

  const memberRows=await db<any[]>(xoAuthDb.from("organization_members")
    .select("member_id,role_id,designation,business_unit,mobile_number,created_at,assigned_on,status,avatar_url")
    .eq("tenant_id",tenantId).eq("user_id",userId).eq("archived",false).limit(2));
  if(memberRows.length!==1 || memberRows[0].status?.toLowerCase()!=="active"){
    throw new HttpError(403,"PROFILE_MEMBERSHIP_DENIED","Active tenant membership is required.");
  }
  const member=memberRows[0];
  const [globalUsers, grants, catalog, tenantRoles, userAppRoles, sessions, factors] = await Promise.all([
    db<any[]>(xoAuthDb.from("xo_users").select("created_at,email_verified,status").eq("user_id",userId).limit(1)),
    db<any[]>(xoAuthDb.from("organization_member_applications").select("application_id,access_status,granted_by,activated_at")
      .eq("tenant_id",tenantId).eq("member_id",member.member_id)),
    db<any[]>(xoAuthDb.from("xo_applications").select("uuid,app_name").eq("tenant_id",tenantId)),
    member.role_id ? db<ProfileRoleRow[]>(servicesDb.from("roles").select("uuid,name,tenant_id,role_type,system_defined,status").eq("uuid",member.role_id).limit(2)):Promise.resolve([]),
    db<any[]>(servicesDb.from("user_application_roles").select("application_id,role_id").eq("user_id",userId).eq("tenant_id",tenantId)),
    db<any[]>(xoAuthDb.from("xo_sessions").select("login_at").eq("user_id",userId).eq("tenant_id",tenantId).order("login_at",{ascending:false}).limit(1)),
    db<any[]>(xoAuthDb.from("mfa_factors").select("type,verified,is_active").eq("user_id",userId).eq("tenant_id",tenantId))
  ]);
  const roleIds=[...new Set(userAppRoles.map(r=>r.role_id).filter(Boolean))];
  const appRoles=roleIds.length?await db<any[]>(servicesDb.from("application_roles")
    .select("uuid,application_id,role_name").eq("tenant_id",tenantId).in("uuid",roleIds)):[];
  const appNames=new Map(catalog.map(a=>[a.uuid,a.app_name]));
  const roleNames=new Map(appRoles.map(r=>[r.application_id+"|"+r.uuid,r.role_name]));
  const access=grants.map(grant=>({
    application_id:grant.application_id,
    application_name:appNames.get(grant.application_id)??null,
    app_role:userAppRoles.filter(r=>r.application_id===grant.application_id)
      .map(r=>roleNames.get(r.application_id+"|"+r.role_id)).filter(Boolean).join(", ")||null,
    status:grant.access_status,granted_by:grant.granted_by,activated_at:grant.activated_at
  }));
  const activeFactors=factors.filter(f=>f.verified===true && f.is_active===true);
  return {
    user_information:{
      user_id:userId,tenant_id:tenantId,member_id:member.member_id,
      full_name:typeof identity.name==="string"?identity.name:null,
      email:typeof identity.email==="string"?identity.email:null,
      // Encrypted member mobile_number requires authorized XO Crypto decryption.
      phone:null,role:resolveProfileRoleName(tenantRoles, member.role_id, tenantId),designation:member.designation,
      business_unit:member.business_unit,join_date:member.assigned_on??member.created_at,
      last_login:sessions[0]?.login_at??null,
      organization_name:typeof identity.organization.name==="string"?identity.organization.name:null,
      avatar_url:member.avatar_url??null
    },
    application_access:access,
    account_status:{
      status:member.status,account_created:globalUsers[0]?.created_at??null,
      email_verified:globalUsers[0]?.email_verified??false,
      mfa_status:activeFactors.length?"enabled":"not_configured"
    },
    security_details:{
      authentication:activeFactors.map(f=>f.type).join(", ")||null,
      // Authoritative password-change and login-failure audit taxonomies not yet verified.
      password_last_changed:null,failed_login_attempts:null,failed_login_window_days:30
    }
  };
}
