import type { CapabilityContext } from "./capabilities";
import { HttpError } from "./auth";
import { enrichSignInEvents, type Enrichment } from "./signin-logs-enrichment";

/**
 * Sign-in log capabilities. Only tenant-attributed audit records are returned.
 * Failed login records with tenant_id=NULL cannot safely be attributed to a tenant.
 * Events and session metadata are joined ONLY by an explicit session identifier.
 */
type AuditEvent = {
  log_id:string; event_type:string; user_id:string|null; target_user_id:string|null;
  tenant_id:string|null; client_id:string|null; ip_address:string|null;
  user_agent:string|null; details:Record<string,unknown>|null; created_at:string;
};
type Member = {memberId:string;userId:string|null;fullName:string;email:string;avatarUrl:string|null};
const LOG_EVENTS=["login_success","login_failed"] as const;
const TIMELINE_LABELS:Record<string,string>={
  login_success:"Logged in",login_failed:"Failed sign-in",
  mfa_login_verified:"MFA verified",login_mfa_required:"MFA challenge required",
  trusted_device_recognized:"Trusted device recognized",
  oauth_session_reused:"OAuth session reused",
  oauth_sso_application_session_created:"Application session created",
};
type Filters={limit:number;offset:number;status:"all"|"success"|"failed";search:string;date_from:string|null;date_until:string|null};
function obj(value:unknown):Record<string,unknown> {
  if(value==null)return {};
  if(typeof value!=="object"||Array.isArray(value))throw new HttpError(400,"SIGNIN_INPUT_INVALID","Expected object parameters.");
  return value as Record<string,unknown>;
}
function uuid(value:unknown):string {
  if(typeof value!=="string"||!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value))
    throw new HttpError(400,"SIGNIN_LOG_ID_INVALID","Valid sign-in log ID required.");
  return value;
}
function number(value:unknown,fallback:number,max:number):number {
  if(value==null)return fallback;
  if(typeof value!=="number"||!Number.isSafeInteger(value)||value<0||value>max)
    throw new HttpError(400,"SIGNIN_INPUT_INVALID","Invalid pagination.");
  return value;
}
function dates(value:unknown):string|null {
  if(value==null||value==="")return null;
  if(typeof value!=="string"||! /^\d{4}-\d{2}-\d{2}$/.test(value) || !Number.isFinite(Date.parse(value+"T00:00:00Z")))
    throw new HttpError(400,"SIGNIN_DATE_INVALID","Dates must be YYYY-MM-DD.");
  return value;
}
function filters(input:unknown):Filters {
  const v=obj(input);const status=v.status??"all", search=v.search??"";
  if(!["all","success","failed"].includes(String(status))||typeof search!=="string"||search.length>120)
    throw new HttpError(400,"SIGNIN_INPUT_INVALID","Invalid filter values.");
  const limit=number(v.limit,10,25),offset=number(v.offset,0,10000);
  if(!limit)throw new HttpError(400,"SIGNIN_INPUT_INVALID","Limit must be greater than zero.");
  const date_from=dates(v.date_from), date_until=dates(v.date_until);
  if(date_from&&date_until&&date_from>date_until)throw new HttpError(400,"SIGNIN_DATE_INVALID","Invalid date range.");
  return {limit,offset,status:status as Filters["status"],search:search.trim().toLowerCase(),date_from,date_until};
}
async function rows<T=any>(query:PromiseLike<{data:T[]|null;error:any}>):Promise<T[]> {
  const {data,error}=await query;
  if(error)throw new HttpError(502,"SIGNIN_DATASOURCE_FAILED","Unable to load sign-in records.");
  return data??[];
}
async function authorizedEndpoint(context:CapabilityContext,endpoint:string,query?:URLSearchParams):Promise<any>{
  const u=new URL(context.xoAuthFunctionsBaseUrl.replace(/\/+$/,"")+"/"+endpoint);
  query?.forEach((v,k)=>u.searchParams.set(k,v));
  let response:Response;
  try{
    response=await fetch(u,{headers:{Authorization:"Bearer "+context.identity.accessToken,Accept:"application/json","X-Request-Id":context.traceId},signal:AbortSignal.timeout(20000)});
  }catch{throw new HttpError(502,"SIGNIN_IDENTITY_UNAVAILABLE","XO Auth identity service unavailable.");}
  if(!response.ok)throw new HttpError(response.status===403?403:response.status===401?401:502,"SIGNIN_IDENTITY_UNAVAILABLE","Authorized XO Auth identity resource unavailable.");
  try{return await response.json();}catch{throw new HttpError(502,"SIGNIN_IDENTITY_RESPONSE_INVALID","Invalid XO Auth identity response.");}
}
async function members(context:CapabilityContext):Promise<Member[]> {
  const list:Member[]=[];let offset=0;
  for(let attempt=0;attempt<10;attempt++){
    const q=new URLSearchParams({limit:"100",offset:String(offset)});
    const response=await authorizedEndpoint(context,"xo-organization-members",q);
    if(response.tenantId!==context.identity.tenantId||!Array.isArray(response.members))
      throw new HttpError(403,"SIGNIN_TENANT_MISMATCH","XO Auth tenant mismatch.");
    const batch=response.members as Member[];
    list.push(...batch);
    const total=Number(response.pagination?.total??list.length);
    if(!Number.isSafeInteger(total)||total>1000)throw new HttpError(413,"SIGNIN_MEMBER_LIMIT","Tenant directory exceeds current authorized lookup limit.");
    if(!batch.length||list.length>=total)return list;
    offset+=batch.length;
  }
  throw new HttpError(413,"SIGNIN_MEMBER_LIMIT","Tenant directory exceeds current authorized lookup limit.");
}
async function organization(context:CapabilityContext):Promise<{name:string|null;type:string|null;logo:string|null}>{
  const response=await authorizedEndpoint(context,"xo-organizations");
  const found=(Array.isArray(response.organizations)?response.organizations:[]).find((x:any)=>x.id===context.identity.tenantId);
  if(!found)throw new HttpError(403,"SIGNIN_ORGANIZATION_NOT_FOUND","Tenant organization unavailable.");
  return {name:found.name??null,type:found.type??null,logo:found.logo??null};
}
const eventStatus=(x:AuditEvent)=>x.event_type==="login_success"?"success":"failed";
function windowed(q:any,f:Filters){
  if(f.date_from)q=q.gte("created_at",f.date_from+"T00:00:00.000Z");
  if(f.date_until){
    const until=new Date(f.date_until+"T00:00:00.000Z");
    until.setUTCDate(until.getUTCDate()+1);
    q=q.lt("created_at",until.toISOString());
  }
  return q;
}
async function auditCount(context:CapabilityContext,type:string,f:Filters){
  let q=context.xoAuthDb.from("auth_audit_logs").select("log_id",{count:"exact",head:true})
    .eq("tenant_id",context.identity.tenantId).eq("event_type",type);
  q=windowed(q,f);
  const {count,error}=await q;
  if(error)throw new HttpError(502,"SIGNIN_COUNT_FAILED","Unable to count sign-in events.");
  return count??0;
}
async function auditEvents(context:CapabilityContext,f:Filters) {
  let q=context.xoAuthDb.from("auth_audit_logs")
    .select("log_id,event_type,user_id,target_user_id,tenant_id,client_id,ip_address,user_agent,details,created_at")
    .eq("tenant_id",context.identity.tenantId).in("event_type",f.status==="success"?["login_success"]:f.status==="failed"?["login_failed"]:[...LOG_EVENTS])
    .order("created_at",{ascending:false}).order("log_id",{ascending:false})
    .limit(2001);
  q=windowed(q,f);
  const result=await rows<AuditEvent>(q);
  if(result.length>2000)throw new HttpError(413,"SIGNIN_EVENT_LIMIT","Too many audit events for this date window. Narrow the date range.");
  return result;
}
function summarize(e:AuditEvent,byUser:Map<string,Member>,extra:Enrichment|null){
  const member=byUser.get(e.user_id??"")??null;
  return {log_id:e.log_id,user_id:e.user_id,name:member?.fullName??null,email:member?.email??null,
    avatar_url:member?.avatarUrl??null,status:eventStatus(e),application:extra?.application??null,
    location:extra?.location??null,sign_in_time:e.created_at,mfa_verified:extra?.session?.mfa_verified??null};
}
export async function listSignInLogs(context:CapabilityContext,input:unknown):Promise<unknown>{
  const f=filters(input);
  const [org,memberRows,successCount,failedCount,mfaCount,events]=await Promise.all([
    organization(context),members(context),auditCount(context,"login_success",f),auditCount(context,"login_failed",f),
    auditCount(context,"mfa_login_verified",f),auditEvents(context,f)
  ]);
  const byUser=new Map(memberRows.filter(m=>m.userId).map(m=>[m.userId as string,m]));
  const filtered=events.filter(e=>{
    if(!f.search)return true;
    const m=byUser.get(e.user_id??"");
    return [m?.fullName,m?.email].some(v=>typeof v==="string"&&v.toLowerCase().includes(f.search));
  });
  // Enrich only the visible page using exact audit details.session_id correlation.
  const page=filtered.slice(f.offset,f.offset+f.limit);
  const enriched=await enrichSignInEvents(context,page);
  return {
    organization:{...org,user_count:memberRows.length},
    stats:{total:successCount+failedCount,success:successCount,failed:failedCount,mfa_verified:mfaCount,
      failed_count_complete:false,failed_count_note:"Historical failed logins without verified tenant attribution are excluded."},
    logs:page.map(e=>summarize(e,byUser,enriched.get(e.log_id)??null)),
    pagination:{limit:f.limit,offset:f.offset,total:filtered.length},
    metadata:{session_details_may_be_unavailable:true,unattributed_failed_logins_excluded:true}
  };
}
async function selectedEvent(context:CapabilityContext,input:unknown):Promise<AuditEvent>{
  const logId=uuid(obj(input).log_id);
  const result=await rows<AuditEvent>(context.xoAuthDb.from("auth_audit_logs")
    .select("log_id,event_type,user_id,target_user_id,tenant_id,client_id,ip_address,user_agent,details,created_at")
    .eq("tenant_id",context.identity.tenantId).eq("log_id",logId).in("event_type",[...LOG_EVENTS]).limit(1));
  if(result.length!==1)throw new HttpError(404,"SIGNIN_EVENT_NOT_FOUND","Sign-in event not found in authorized tenant.");
  return result[0];
}
export async function getSignInLogDetail(context:CapabilityContext,input:unknown):Promise<unknown>{
 const event=await selectedEvent(context,input);
 const [memberList,enriched]=await Promise.all([members(context),enrichSignInEvents(context,[event])]);
 const member=memberList.find(m=>m.userId===event.user_id)??null;
 const extra=enriched.get(event.log_id)??null;
 const session=extra?.session??null;
 return {
  log_id:event.log_id,user:{name:member?.fullName??null,email:member?.email??null,avatar_url:member?.avatarUrl??null},
  status:eventStatus(event),application:extra?.application??null,device:extra?.device??null,
  ip_address:extra?.ip_address??null,location:extra?.location??null,sign_in_time:event.created_at,
  authentication_method:session?.mfa_method??null,mfa_verified:session?.mfa_verified??null,
  security:{risk_level:session?.risk_level??null,new_device:null,suspicious_ip:null,
    session_status:session?.status??null,trusted_device:null},
  metadata:{correlated_session:!!session}
 };
}
export async function listSignInLogTimeline(context:CapabilityContext,input:unknown):Promise<unknown>{
  const v=obj(input);const selected=await selectedEvent(context,input);
  const limit=number(v.limit,5,25),offset=number(v.offset,0,10000);
  if(!limit)throw new HttpError(400,"SIGNIN_INPUT_INVALID","Limit must be positive.");
  if(!selected.user_id)return {events:[],pagination:{limit,offset,total:0}};
  const q=context.xoAuthDb.from("auth_audit_logs")
    .select("log_id,event_type,created_at",{count:"exact"})
    .eq("tenant_id",context.identity.tenantId).eq("user_id",selected.user_id)
    .in("event_type",Object.keys(TIMELINE_LABELS))
    .order("created_at",{ascending:false}).range(offset,offset+limit-1);
  const {data,error,count}=await q;
  if(error)throw new HttpError(502,"SIGNIN_TIMELINE_FAILED","Unable to load related sign-in history.");
  return {scope:"user_recent_access",events:(data??[]).map(e=>({id:e.log_id,title:TIMELINE_LABELS[e.event_type]??"Authentication event",type:e.event_type,time:e.created_at})),
    pagination:{limit,offset,total:count??0}};
}
