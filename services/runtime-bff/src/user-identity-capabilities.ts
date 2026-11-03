import { HttpError } from "./auth";
import type { CapabilityContext } from "./capabilities";
import { resolveProfileRoleName, type ProfileRoleRow } from "./profile-role-resolution";

type RecordValue = Record<string, any>;
type Member = { memberId: string; userId: string|null; roleId:string|null; fullName:string; email:string; status:string; avatarUrl:string|null; assignedOn:string|null; createdAt:string|null };
type ListInput = { limit:number; offset:number; search:string; status:"all"|"active"|"inactive" };
const CAP=1000;
function asObject(value:unknown):Record<string,unknown>{
 if(!value || typeof value!=="object" || Array.isArray(value))throw new HttpError(400,"IDENTITY_INPUT_INVALID","Expected object input.");
 return value as Record<string,unknown>;
}
function int(value:unknown,defaultValue:number,max:number):number {
 if(value==null)return defaultValue;
 if(typeof value!=="number"||!Number.isInteger(value)||value<0||value>max)throw new HttpError(400,"IDENTITY_INPUT_INVALID","Invalid pagination.");
 return value;
}
function uuid(value:unknown):string {
 if(typeof value!=="string"||!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value))throw new HttpError(400,"IDENTITY_MEMBER_INVALID","Valid member_id required.");
 return value;
}
function listInput(input:unknown):ListInput {
 const v=input==null?{}:asObject(input);
 const limit=int(v.limit,25,100),offset=int(v.offset,0,100000);
 if(limit<1)throw new HttpError(400,"IDENTITY_INPUT_INVALID","Limit must be positive.");
 const search=v.search??"",status=v.status??"all";
 if(typeof search!=="string"||search.length>120||!["all","active","inactive"].includes(String(status)))throw new HttpError(400,"IDENTITY_INPUT_INVALID","Invalid filter.");
 return {limit,offset,search:search.trim().toLocaleLowerCase("en-US"),status:status as ListInput["status"]};
}
async function rows<T=RecordValue>(request:PromiseLike<{data:T[]|null;error:any}>):Promise<T[]>{
 const {data,error}=await request;
 if(error)throw new HttpError(502,"IDENTITY_DATASOURCE_FAILED","Unable to retrieve tenant identity data.");
 return data??[];
}
async function xoResource(context:CapabilityContext,endpoint:string,query?:URLSearchParams):Promise<any>{
 const u=new URL(context.xoAuthFunctionsBaseUrl.replace(/\/+$/,"")+"/"+endpoint);
 query?.forEach((value,key)=>u.searchParams.set(key,value));
 let response:Response;
 try {
  response=await fetch(u,{headers:{Authorization:"Bearer "+context.identity.accessToken,Accept:"application/json","X-Request-Id":context.traceId},signal:AbortSignal.timeout(20000)});
 }catch{throw new HttpError(502,"XO_AUTH_UNAVAILABLE","XO Auth identity service unavailable.");}
 if(!response.ok)throw new HttpError(response.status===401?401:response.status===403?403:502,"XO_AUTH_RESOURCE_FAILED","Authorized XO Auth resource unavailable.");
 try{return await response.json();}catch{throw new HttpError(502,"XO_AUTH_RESPONSE_INVALID","Invalid XO Auth response.");}
}
/** Existing XO Auth function performs validated session/tenant membership and decrypts email/name. */
async function tenantMembers(context:CapabilityContext):Promise<Member[]>{
 let result:Member[]=[];let offset=0;
 while(true){
  const q=new URLSearchParams({limit:"100",offset:String(offset)});
  const payload=await xoResource(context,"xo-organization-members",q);
  if(payload.tenantId!==context.identity.tenantId||!Array.isArray(payload.members))
   throw new HttpError(403,"IDENTITY_TENANT_MISMATCH","Invalid tenant response.");
  const batch=payload.members as Member[];
  result.push(...batch);
  const total=Number(payload.pagination?.total??result.length);
  if(!Number.isFinite(total)||total>CAP)throw new HttpError(413,"IDENTITY_DIRECTORY_LIMIT","Directory exceeds the currently supported safe listing size.");
  if(!batch.length||result.length>=total)break;
  offset+=batch.length;
 }
 return result;
}
async function tenantOrganization(context:CapabilityContext){
 const result=await xoResource(context,"xo-organizations");
 const list=Array.isArray(result.organizations)?result.organizations:[];
 const current=list.find((o:any)=>o.id===context.identity.tenantId);
 if(!current)throw new HttpError(403,"IDENTITY_ORGANIZATION_MISSING","Authorized organization is unavailable.");
 return {id:current.id,name:current.name??null,type:current.type??null,logo:current.logo??null};
}
async function roleNames(context:CapabilityContext,members:Member[]):Promise<Map<string,string>>{
 const ids=[...new Set(members.map(m=>m.roleId).filter((id):id is string=>typeof id==="string"))];
 if(!ids.length)return new Map();
 const roles=await rows<ProfileRoleRow>(context.servicesDb.from("roles")
  .select("uuid,name,tenant_id,role_type,system_defined,status").in("uuid",ids));
 const answer=new Map<string,string>();
 for(const id of ids){const name=resolveProfileRoleName(roles.filter(r=>r.uuid===id),id,context.identity.tenantId);if(name)answer.set(id,name);}
 return answer;
}
async function lastLogins(context:CapabilityContext,users:Member[]):Promise<Map<string,string>>{
 const ids=[...new Set(users.map(m=>m.userId).filter((id):id is string=>!!id))];
 if(!ids.length)return new Map();
 const sessions=await rows(context.xoAuthDb.from("xo_sessions").select("user_id,login_at")
  .eq("tenant_id",context.identity.tenantId).in("user_id",ids).order("login_at",{ascending:false}).limit(3000));
 const map=new Map<string,string>();
 for(const s of sessions)if(s.user_id&&!map.has(s.user_id))map.set(s.user_id,s.login_at);
 return map;
}
const normalize=(s:string)=>String(s||"").toLowerCase();
export async function listIdentityUsers(context:CapabilityContext,input:unknown):Promise<unknown>{
 const {limit,offset,search,status}=listInput(input);
 const [members,organization]=await Promise.all([tenantMembers(context),tenantOrganization(context)]);
 const [roles,logins]=await Promise.all([roleNames(context,members),lastLogins(context,members)]);
 const all=members.map(m=>({member_id:m.memberId,user_id:m.userId,name:m.fullName,email:m.email,avatar_url:m.avatarUrl,role:roles.get(m.roleId??"")??null,status:normalize(m.status),last_login:m.userId?logins.get(m.userId)??null:null}));
 const filtered=all.filter(m=>(status==="all"||m.status===status) && (!search||[m.name,m.email,m.role??""].some(x=>x.toLocaleLowerCase("en-US").includes(search))));
 return {organization,stats:{total:all.length,active:all.filter(m=>m.status==="active").length,inactive:all.filter(m=>m.status==="inactive").length},users:filtered.slice(offset,offset+limit),pagination:{limit,offset,total:filtered.length}};
}
function selectedMember(members:Member[],id:string):Member{
 const member=members.find(m=>m.memberId===id);
 if(!member)throw new HttpError(404,"IDENTITY_MEMBER_NOT_FOUND","Selected user is not in the authorized tenant.");
 return member;
}
export async function getIdentityUser(context:CapabilityContext,input:unknown):Promise<unknown>{
 const id=uuid(asObject(input).member_id);
 const members=await tenantMembers(context);
 const member=selectedMember(members,id);
 const [roleMap,metadata,grantRows,logins]=await Promise.all([
  roleNames(context,[member]),
  rows(context.xoAuthDb.from("organization_members").select("member_id,designation,business_unit,reporting_manager,mobile_number,assigned_on,created_at")
   .eq("tenant_id",context.identity.tenantId).eq("member_id",id).eq("archived",false).limit(1)),
  rows(context.xoAuthDb.from("organization_member_applications").select("application_id,access_status,granted_by,activated_at")
   .eq("tenant_id",context.identity.tenantId).eq("member_id",id)),
  lastLogins(context,[member])
 ]);
 if(metadata.length!==1)throw new HttpError(404,"IDENTITY_MEMBER_NOT_FOUND","Selected member was not found.");
 const info=metadata[0];
 const appIds=[...new Set(grantRows.map(a=>a.application_id).filter(Boolean))];
 const [apps, assignedRoles]=await Promise.all([
  appIds.length?rows(context.xoAuthDb.from("xo_applications").select("uuid,app_name").eq("tenant_id",context.identity.tenantId).in("uuid",appIds)):Promise.resolve([]),
  member.userId?rows(context.servicesDb.from("user_application_roles").select("application_id,role_id").eq("tenant_id",context.identity.tenantId).eq("user_id",member.userId)):Promise.resolve([])
 ]);
 const appRoleIds=[...new Set(assignedRoles.map(r=>r.role_id).filter(Boolean))];
 const roleRows=appRoleIds.length?await rows(context.servicesDb.from("application_roles").select("uuid,application_id,role_name")
  .eq("tenant_id",context.identity.tenantId).in("uuid",appRoleIds)):[];
 const appMap=new Map(apps.map(a=>[a.uuid,a.app_name]));
 const roleMapByPair=new Map(roleRows.map(r=>[r.application_id+"|"+r.uuid,r.role_name]));
 const names=new Map(members.filter(m=>m.userId).map(m=>[m.userId,m.fullName]));
 const grants=grantRows.map(g=>({
  application_id:g.application_id,application_name:appMap.get(g.application_id)??null,
  app_role:assignedRoles.filter(r=>r.application_id===g.application_id)
    .map(r=>roleMapByPair.get(r.application_id+"|"+r.role_id)).filter(Boolean).join(", ")||null,
  status:normalize(g.access_status),granted_by:names.get(g.granted_by)??null,activated_at:g.activated_at??null
 }));
 return {
  member_id:id,user_id:member.userId,name:member.fullName,email:member.email,
  avatar_url:member.avatarUrl,status:normalize(member.status),role:roleMap.get(member.roleId??"")??null,
  designation:info.designation??null,business_unit:info.business_unit??null,
  // XO Auth member-list endpoint currently decrypts only email/full_name; don't return ciphertext.
  phone:null,
  // reporting_manager is text; do not interpret ciphertext as a manager name.
  reporting_manager:typeof info.reporting_manager==="string" && !info.reporting_manager.startsWith("xoenc:")?info.reporting_manager:null,
  join_date:info.assigned_on??info.created_at??member.createdAt??null,
  last_login:member.userId?logins.get(member.userId)??null:null,
  application_access:grants
 };
}
const EVENT_TITLES:Record<string,string>={
 login_success:"Logged in",login_failed:"Failed login",email_verified:"Email verified",
 mfa_setup_verified:"MFA enabled",mfa_login_verified:"MFA verified",
 signup_created:"Account created",organization_invitation_email_sent:"Organization invitation sent",
 consent_granted:"Consent granted",password_reset_completed:"Password reset"
};
export async function listIdentityEvents(context:CapabilityContext,input:unknown):Promise<unknown>{
 const v=asObject(input);
 const memberId=uuid(v.member_id);
 const limit=int(v.limit,20,50),offset=int(v.offset,0,100000);
 if(limit<1)throw new HttpError(400,"IDENTITY_INPUT_INVALID","Invalid events limit.");
 const member=selectedMember(await tenantMembers(context),memberId);
 if(!member.userId)return {events:[],pagination:{limit,offset,total:0}};
 // Only verified events about the selected identity, not unrelated actor actions.
 const q=context.xoAuthDb.from("auth_audit_logs")
  .select("log_id,event_type,created_at,user_id,target_user_id", {count:"exact"})
  .eq("tenant_id",context.identity.tenantId)
  .in("event_type",Object.keys(EVENT_TITLES))
  .or("user_id.eq."+member.userId+",target_user_id.eq."+member.userId)
  .order("created_at",{ascending:false}).range(offset,offset+limit-1);
 const {data,error,count}=await q;
 if(error)throw new HttpError(502,"IDENTITY_EVENTS_UNAVAILABLE","Unable to load identity lifecycle.");
 return {events:(data??[]).map(e=>({id:e.log_id,type:e.event_type,title:EVENT_TITLES[e.event_type]??"Identity event",time:e.created_at,detail:null})),pagination:{limit,offset,total:count??0}};
}
