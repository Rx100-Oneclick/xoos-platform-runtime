import { HttpError } from "./auth";
import type { CapabilityContext } from "./capabilities";
import { resolveProfileRoleName, type ProfileRoleRow } from "./profile-role-resolution";

type Row = Record<string, any>;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ACTIVE=["retained","restore_requested","purge_pending","purge_failed"];
function obj(v:unknown):Record<string,unknown> {
 if(v==null)return {};
 if(typeof v!=="object"||Array.isArray(v))throw new HttpError(400,"DELETED_USERS_BAD_INPUT","Expected object input.");
 return v as Record<string,unknown>;
}
function id(v:unknown):string {
 if(typeof v!=="string"||!UUID.test(v))throw new HttpError(400,"DELETED_USERS_INVALID_ID","Valid deletion_id required.");
 return v;
}
function num(v:unknown,def:number,max:number) {
 if(v==null)return def;
 if(typeof v!=="number"||!Number.isInteger(v)||v<0||v>max)throw new HttpError(400,"DELETED_USERS_PAGE_INVALID","Invalid pagination.");
 return v;
}
function tenant(c:CapabilityContext):string {
 if(!c.identity.tenantId)throw new HttpError(403,"DELETED_USERS_NO_TENANT","Tenant required.");
 return c.identity.tenantId;
}
async function rows<T=Row>(p:PromiseLike<{data:T[]|null,error:any}>):Promise<T[]> {
 const {data,error}=await p;
 if(error)throw new HttpError(502,"DELETED_USERS_READ_FAILED","Unable to fetch tenant deletion data.");
 return data??[];
}
function eligible(x:Row) {
 const ms=Date.parse(x.restore_deadline_at)-Date.now();
 const purgeMs=Date.parse(x.scheduled_purge_at)-Date.now();
 const can_restore=["retained","restore_requested"].includes(x.status)&&ms>0&&!x.purged_at;
 const can_purge=ACTIVE.includes(x.status)&&purgeMs<=0&&!x.legal_hold;
 return {can_restore,can_purge,remaining_days:Math.max(0,Math.ceil(ms/86400000)),
   expiring_soon:ACTIVE.includes(x.status)&&ms>0&&ms<=7*86400000};
}
async function all(c:CapabilityContext) {
 return rows(c.xoAuthDb.from("deleted_user_records")
   .select("deletion_id,tenant_id,member_id,user_id,deleted_by,deleted_at,retention_days,restore_deadline_at,scheduled_purge_at,status,restored_at,purged_at,legal_hold,policy_snapshot")
   .eq("tenant_id",tenant(c)).order("deleted_at",{ascending:false}).limit(2000));
}
function summary(allRows:Row[]) {
 const open=allRows.filter(x=>ACTIVE.includes(x.status));
 return {deleted_users:allRows.length,
   within_retention:open.filter(x=>Date.parse(x.restore_deadline_at)>Date.now()).length,
   ready_to_restore:open.filter(x=>eligible(x).can_restore).length,
   expiring_soon:open.filter(x=>eligible(x).expiring_soon).length};
}
const clear=(v:any):string|null=>
 typeof v==="string"&&v.trim()&&!v.startsWith("xoenc")?v:null;
async function enrich(c:CapabilityContext,items:Row[]) {
 const ids=[...new Set(items.map(x=>x.member_id))];
 const actorIds=[...new Set(items.map(x=>x.deleted_by))];
 const [members,actors]=await Promise.all([
  ids.length?rows(c.xoAuthDb.from("organization_members")
   .select("member_id,user_id,full_name,email,avatar_url,business_unit,role_id")
   .eq("tenant_id",tenant(c)).in("member_id",ids)):Promise.resolve([]),
  actorIds.length?rows(c.xoAuthDb.from("organization_members")
   .select("user_id,full_name").eq("tenant_id",tenant(c)).in("user_id",actorIds)):Promise.resolve([])
 ]);
 const rolesIds=[...new Set(members.map(m=>m.role_id).filter(Boolean))];
 const roles=rolesIds.length?await rows<ProfileRoleRow>(c.servicesDb.from("roles")
   .select("uuid,name,tenant_id,role_type,system_defined,status").in("uuid",rolesIds)):[];
 const byMember=new Map(members.map(m=>[m.member_id,m]));
 const byActor=new Map(actors.map(m=>[m.user_id,m]));
 return items.map(x=>{
  const m=byMember.get(x.member_id);
  const name=m?.role_id?resolveProfileRoleName(roles.filter(r=>r.uuid===m.role_id),m.role_id,tenant(c)):null;
  return {...x,...eligible(x),name:clear(m?.full_name),email:clear(m?.email),role:name,
   business_unit:clear(m?.business_unit),avatar_url:clear(m?.avatar_url),
   deleted_by_name:clear(byActor.get(x.deleted_by)?.full_name)};
 });
}
export async function deletedUsersSummary(c:CapabilityContext) {
 return {stats:summary(await all(c))};
}
export async function deletedUsersList(c:CapabilityContext,input:unknown) {
 const v=obj(input),limit=num(v.limit,20,100),offset=num(v.offset,0,100000);
 const status=v.status??"all",retention=v.retention??"all",search=v.search??"";
 if(limit<1||typeof status!=="string"||
  !["all","retained","restore_requested","restored","purge_pending","purged","purge_failed"].includes(status)
  ||!["all","within","expired","expiring"].includes(String(retention))
  ||typeof search!=="string"||search.length>120)
    throw new HttpError(400,"DELETED_USERS_FILTER_INVALID","Invalid filter.");
 const source=await all(c),enriched=await enrich(c,source);
 const needle=search.trim().toLowerCase();
 const filtered=enriched.filter(x=>(status==="all"||x.status===status)
  &&(retention==="all"||(retention==="within"&&x.remaining_days>0)
   ||(retention==="expired"&&x.remaining_days===0)||(retention==="expiring"&&x.expiring_soon))
  &&(!needle||[x.name,x.email,x.role,x.deleted_by_name].some(v=>typeof v==="string"&&v.toLowerCase().includes(needle))));
 return {organization:null,stats:summary(source),users:filtered.slice(offset,offset+limit),
  pagination:{limit,offset,total:filtered.length}};
}
async function one(c:CapabilityContext,recordId:string) {
 const result=await rows(c.xoAuthDb.from("deleted_user_records").select("*")
   .eq("tenant_id",tenant(c)).eq("deletion_id",recordId).limit(1));
 if(result.length!==1)throw new HttpError(404,"DELETED_USER_MISSING","Record not found.");
 return result[0];
}
export async function deletedUserDetail(c:CapabilityContext,input:unknown) {
 const record=await one(c,id(obj(input).deletion_id));
 const [user]=await enrich(c,[record]);
 return {user};
}
export async function deletedUserTimeline(c:CapabilityContext,input:unknown) {
 const v=obj(input),recordId=id(v.deletion_id),limit=num(v.limit,30,100),offset=num(v.offset,0,100000);
 await one(c,recordId);
 const {data,error,count}=await c.xoAuthDb.from("deleted_user_events")
  .select("event_id,deletion_id,event_type,actor_user_id,event_at,correlation_id,metadata",{count:"exact"})
  .eq("tenant_id",tenant(c)).eq("deletion_id",recordId).order("event_at",{ascending:false})
  .order("event_id",{ascending:false}).range(offset,offset+limit-1);
 if(error)throw new HttpError(502,"DELETED_USER_TIMELINE_FAILED","Unable to read timeline.");
 return {events:data??[],pagination:{limit,offset,total:count??0}};
}
async function mutate(c:CapabilityContext,input:unknown,action:"restore"|"purge") {
 const v=obj(input),recordId=id(v.deletion_id);
 if(v.confirm!==true)throw new HttpError(400,"DELETED_USER_CONFIRM_REQUIRED","Confirmation required.");
 const x=await one(c,recordId),ability=eligible(x);
 if(action==="restore"&&!ability.can_restore)throw new HttpError(409,"RESTORE_NOT_ALLOWED","Restore is not available.");
 if(action==="purge"&&!ability.can_purge)throw new HttpError(409,"PURGE_NOT_ALLOWED","Purge is not yet eligible.");
 const {data,error}=await c.xoAuthDb.rpc(action==="restore"?"xoos_restore_organization_member":"xoos_purge_organization_member",{
  p_tenant_id:tenant(c),p_deletion_id:recordId,p_actor_user_id:c.identity.userId,p_correlation_id:crypto.randomUUID()
 });
 if(error)throw new HttpError(502,"DELETED_USER_MUTATION_FAILED","Lifecycle change could not be completed.");
 return data;
}
export const deletedUserRestore=(c:CapabilityContext,v:unknown)=>mutate(c,v,"restore");
export const deletedUserPurge=(c:CapabilityContext,v:unknown)=>mutate(c,v,"purge");
