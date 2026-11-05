import {type XOIdentity,type RuntimeAuthorizationState} from "../types.ts";
import {RuntimeError as HttpError} from "../shared/errors.ts";
import {supabase,servicesSupabase} from "../config.ts";
import {identityTenant,identityInput} from "./user-identity.ts";
type CapabilityContext={identity:XOIdentity;xoAuthDb:typeof supabase;servicesDb:typeof servicesSupabase;traceId:string};
type Source="XO_AUTH"|"SERVICES"|"SECURITY";
type Row=Record<string,any>;
const SOURCES:Source[]=["XO_AUTH","SERVICES","SECURITY"];
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function input(value:unknown):Row{if(value==null)return {};if(!value||typeof value!=="object"||Array.isArray(value))throw new HttpError(400,"AUDIT_INPUT_INVALID","Expected object.");const o=value as Row;if("tenant_id" in o||"user_id" in o)throw new HttpError(400,"AUDIT_TENANT_HINT_REJECTED","Tenant identity is server-derived.");return o}
function tenant(c:CapabilityContext){if(!c.identity.tenantId||!UUID.test(c.identity.tenantId))throw new HttpError(403,"AUDIT_TENANT_MISSING","Authorized tenant required.");return c.identity.tenantId}
function iso(v:any){return typeof v==="string"&&!Number.isNaN(Date.parse(v))?v:null}
function scope(v:Row){const dateRange=v.dateRange??"last_7_days";const days=dateRange==="last_24_hours"?1:dateRange==="last_7_days"?7:dateRange==="last_30_days"?30:null;if(days===null)throw new HttpError(400,"AUDIT_DATE_INVALID","Unsupported date range.");return new Date(Date.now()-days*86400000).toISOString()}
function filters(v:Row){const source=v.source??"all",status=v.status??"all",category=v.category??"all",search=v.search??"";if(!["all",...SOURCES].includes(source)||!["all","success","failed","rejected","unknown"].includes(status)||!["all","Authentication","MFA","Microapp","RBAC","Crypto"].includes(category)||typeof search!=="string"||search.length>120)throw new HttpError(400,"AUDIT_FILTER_INVALID","Invalid audit filter.");return {source,status,category,search:search.toLowerCase().trim(),since:scope(v)}}
function outcome(type:string):"success"|"failed"|"unknown"{if(/failed|failure|denied|rejected|error/i.test(type))return "failed";if(/success|verified|completed|granted|created|assigned|updated|deleted|started|submitted|resolved|reused/i.test(type))return "success";return "unknown"}
function category(source:Source,type:string){if(source==="SECURITY")return "Crypto";if(/mfa/i.test(type))return "MFA";if(/role|permission|policy|rbac/i.test(type))return "RBAC";return source==="XO_AUTH"?"Authentication":"Microapp"}
function title(type:string){const value=type.replace(/[_\.]+/g," ").trim();return value?value.charAt(0).toUpperCase()+value.slice(1):"Audit event"}
function normalize(source:Source,r:Row){const type=String(source==="SECURITY"?r.operation:r.event_type||"unknown");const when=String(source==="SERVICES"?r.occurred_at:r.created_at);const id=String(source==="XO_AUTH"?r.log_id:source==="SERVICES"?r.audit_event_id:r.audit_id);const status=source==="SECURITY"?(r.result==="failure"?"failed":r.result==="rejected"?"rejected":r.result==="success"?"success":"unknown"):source==="SERVICES"&&typeof r.context?.status==="string"?outcome(String(r.context.status)):outcome(type);
 const actor=source==="XO_AUTH"?(r.actor_user_id||r.user_id):source==="SERVICES"?(r.actor?.user_id||r.actor?.actor_id||r.actor?.xo_subject):r.user_id;
 return {id:source+":"+id,source,timestamp:when,title:title(type),event_type:type,category:category(source,type),status,severity:source==="XO_AUTH"?(r.severity||"unknown"):status==="failed"?"warning":"info",actor_user_id:typeof actor==="string"&&UUID.test(actor)?actor:null,actor_display_name:null,application_name:null,trace_id:source==="SERVICES"?r.trace_id:source==="SECURITY"?r.trace_id:typeof r.details?.trace_id==="string"?r.details.trace_id:null,summary:title(type)+" ("+source.replace("_"," ")+")",client_id:r.client_id??null,application_id:r.application_id??null};
}
type Event=ReturnType<typeof normalize>;
function cursorEncode(e:Event){return btoa(JSON.stringify({t:e.timestamp,s:e.source,id:e.id.slice(e.source.length+1)}))}
function cursorDecode(v:any){if(!v)return null;if(typeof v!=="string"||v.length>512)throw new HttpError(400,"AUDIT_CURSOR_INVALID","Invalid cursor.");try{const x=JSON.parse(atob(v));if(!iso(x.t)||!SOURCES.includes(x.s)||!UUID.test(x.id))throw Error();return x as {t:string;s:Source;id:string}}catch{throw new HttpError(400,"AUDIT_CURSOR_INVALID","Invalid cursor.")}}
function compare(a:Event,b:Event){return b.timestamp.localeCompare(a.timestamp)||b.source.localeCompare(a.source)||b.id.localeCompare(a.id)}
function before(e:Event,c:{t:string;s:Source;id:string}){return e.timestamp<c.t||(e.timestamp===c.t&&(e.source<c.s||(e.source===c.s&&e.id.slice(e.source.length+1)<c.id)))}
async function read(p:PromiseLike<{data:any,error:any}>){const x=await p;if(x.error)throw new Error("Audit source query failed");return x.data??[]}
function query(c:CapabilityContext,src:Source,tenantId:string,since:string,limit:number){
 if(src==="XO_AUTH")return c.xoAuthDb.from("auth_audit_logs").select("log_id,event_type,actor_user_id,user_id,client_id,severity,created_at").eq("tenant_id",tenantId).gte("created_at",since).order("created_at",{ascending:false}).order("log_id",{ascending:false}).limit(limit);
 return c.servicesDb.from("audit_events").select("audit_event_id,event_type,trace_id,request_id,source_system,actor,subject,context,occurred_at").eq("tenant_id",tenantId).gte("occurred_at",since).order("occurred_at",{ascending:false}).order("audit_event_id",{ascending:false}).limit(limit);
}
async function security(tenantId:string,since:string,limit:number,cursor:any,mode:"list"|"summary"|"detail",id?:string){
 const url=Deno.env.get("SECURITY_AUDIT_READER_URL")?.trim(),token=Deno.env.get("SECURITY_AUDIT_READER_TOKEN")?.trim();
 if(!url||!token)return {state:"unavailable" as const,rows:[] as Row[],count:0};
 const controller=new AbortController(),timeout=setTimeout(()=>controller.abort(),3000);
 try{const response=await fetch(url,{method:"POST",headers:{"Content-Type":"application/json",Authorization:"Bearer "+token},body:JSON.stringify({action:mode,tenant_id:tenantId,from:since,limit,cursor,id}),signal:controller.signal});
 if(!response.ok)throw Error("Security reader unavailable");
 const payload=await response.json() as Row;
 if(!Array.isArray(payload.events)&&mode==="list")throw Error("Invalid Security reader");
 const rows=(payload.events??[]) as Row[];
 if(rows.some(r=>r.tenant_id!==tenantId))throw Error("Security reader tenant mismatch");
 return {state:"ok" as const,rows,count:Number.isInteger(payload.count)?payload.count:0};
 }catch{return {state:"error" as const,rows:[] as Row[],count:0}}finally{clearTimeout(timeout)}
}
async function enrich(c:CapabilityContext,events:Event[]){const ids=[...new Set(events.map(x=>x.actor_user_id).filter((id):id is string=>!!id))];const clients=[...new Set(events.filter(e=>e.source==="XO_AUTH").map(e=>e.client_id).filter((x):x is string=>typeof x==="string"&&!!x))];
 const [userRows,oauth]=await Promise.all([ids.length?read(c.xoAuthDb.from("xo_users").select("user_id,name,email").in("user_id",ids)):Promise.resolve([]),clients.length?read(c.xoAuthDb.from("oauth_clients").select("client_id,application_id").in("client_id",clients)):Promise.resolve([])]);
 const appIds=[...new Set(oauth.map((r:Row)=>r.application_id).filter(Boolean))];const apps=appIds.length?await read(c.xoAuthDb.from("xo_applications").select("uuid,app_name").eq("tenant_id",tenant(c)).in("uuid",appIds)):[];
 const byApp=new Map(apps.map((r:Row)=>[r.uuid,r.app_name]));const byClient=new Map(oauth.map((r:Row)=>[r.client_id,byApp.get(r.application_id)||null]));
 // Platform-scoped xo_users names are encrypted; decrypt on trusted backend only.
 const names=new Map<string,string>();
 const cryptoBase=Deno.env.get("XO_CRYPTO_RUNTIME_URL")?.replace(/\/+$/,"");const url=cryptoBase?cryptoBase+"/decrypt":null;
 const secret=Deno.env.get("XO_XOO_CRYPTO_CLIENT_SECRET"),config=Deno.env.get("XO_CRYPTO_XO_USERS_CONFIGURATION_ID");
 if(url&&secret&&config){
  const values=userRows.filter((r:Row)=>typeof r.name==="string"&&r.name.startsWith("xoenc:v1:"));
  for(let i=0;i<values.length;i+=8)await Promise.all(values.slice(i,i+8).map(async(r:Row)=>{
   try{
    const body=JSON.stringify({configuration_id:config,record_id:r.user_id,fields:{name:r.name}});
    const sha=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(body));
    const digest=Array.from(new Uint8Array(sha),n=>n.toString(16).padStart(2,"0")).join("");
    const response=await fetch(url,{method:"POST",headers:{"Content-Type":"application/json","X-XO-Client-Id":Deno.env.get("XO_CRYPTO_CLIENT_ID")||"","X-XO-Client-Secret":secret,"X-XO-App-Id":Deno.env.get("XO_CRYPTO_APP_ID")||"","X-XO-Project-Binding-Id":Deno.env.get("XO_CRYPTO_PROJECT_BINDING_ID")||"","X-XO-Timestamp":String(Math.floor(Date.now()/1000)),"X-XO-Nonce":crypto.randomUUID(),"X-XO-Body-SHA256":digest,"X-XO-Trace-Id":c.traceId},body,signal:AbortSignal.timeout(1800)});
    if(!response.ok)return;const payload=await response.json() as Row;
    const value=payload.decrypted?.name;if(typeof value==="string"&&!value.startsWith("xoenc:"))names.set(r.user_id,value);
   }catch{/* Do not leak ciphertext or block the audit list on identity decryption. */}
  }));
 }
 return events.map(e=>({...e,actor_display_name:e.actor_user_id?names.get(e.actor_user_id)||null:null,application_name:e.source==="XO_AUTH"?byClient.get(e.client_id)||null:null,client_id:undefined,application_id:undefined}));
}
export async function auditList(c:CapabilityContext,value:unknown){
 const v=input(value),f=filters(v),tid=tenant(c),limit=v.limit===undefined?20:Number(v.limit);
 if(!Number.isInteger(limit)||limit<1||limit>50)throw new HttpError(400,"AUDIT_LIMIT_INVALID","Limit out of range");
 const cursor=cursorDecode(v.cursor);
 const src=SOURCES.filter(x=>f.source==="all"||x===f.source);
 const states:Record<Source,"ok"|"unavailable"|"error">={XO_AUTH:"unavailable",SERVICES:"unavailable",SECURITY:"unavailable"};
 const out=await Promise.all(src.map(async(source)=>{
  if(source==="SECURITY"){const r=await security(tid,f.since,limit+25,cursor,"list");states.SECURITY=r.state;return r.rows.map(row=>normalize(source,row))}
  try{const rows=await read(query(c,source,tid,f.since,limit+25));states[source]="ok";return rows.map((row:Row)=>normalize(source,row));}catch{states[source]="error";return [] as Event[];}
 }));
 let combined=out.flat().sort(compare);
 if(cursor)combined=combined.filter(e=>before(e,cursor));
 const needle=f.search;
 combined=combined.filter(e=>(f.category==="all"||e.category===f.category)&&(f.status==="all"||e.status===f.status)&&(!needle||[e.title,e.event_type,e.category,e.trace_id].some(x=>typeof x==="string"&&x.toLowerCase().includes(needle))));
 const page=combined.slice(0,limit),events=await enrich(c,page);
 return {events,pagination:{limit,hasMore:combined.length>limit,nextCursor:combined.length>limit&&page.length?cursorEncode(page[page.length-1]):null},sources:states,partial:src.some(x=>states[x]!=="ok")};
}
async function count(c:CapabilityContext,table:"auth_audit_logs"|"audit_events",time:string,since:string){
 const db=table==="auth_audit_logs"?c.xoAuthDb:c.servicesDb;
 const r=await db.from(table).select("*",{count:"exact",head:true}).eq("tenant_id",tenant(c)).gte(time,since);
 if(r.error)throw Error("Count unavailable");return r.count??0;
}
export async function auditSummary(c:CapabilityContext,v:unknown){
 const f=filters(input(v));let a=0,s=0,k=0;
 const states:Record<Source,string>={XO_AUTH:"unavailable",SERVICES:"unavailable",SECURITY:"unavailable"};
 const tasks=await Promise.allSettled([count(c,"auth_audit_logs","created_at",f.since),count(c,"audit_events","occurred_at",f.since),security(tenant(c),f.since,0,null,"summary")]);
 if(tasks[0].status==="fulfilled"){a=tasks[0].value as number;states.XO_AUTH="ok"}else states.XO_AUTH="error";
 if(tasks[1].status==="fulfilled"){s=tasks[1].value as number;states.SERVICES="ok"}else states.SERVICES="error";
 if(tasks[2].status==="fulfilled"){const res=tasks[2].value as Awaited<ReturnType<typeof security>>;k=res.count;states.SECURITY=res.state}
 return {stats:{total:a+s+k,authentication:a,microapp_actions:s,cryptography:k},sources:states,partial:Object.values(states).some(x=>x!=="ok")};
}
export async function auditDetail(c:CapabilityContext,value:unknown){
 const v=input(value),raw=v.id;
 if(typeof raw!=="string")throw new HttpError(400,"AUDIT_ID_INVALID","Event id required");
 const [src,uuid]=raw.split(":");
 if(!SOURCES.includes(src as Source)||!UUID.test(uuid))throw new HttpError(400,"AUDIT_ID_INVALID","Invalid audit id");
 const tid=tenant(c);let record:Row|null=null;
 if(src==="XO_AUTH"){const q=await c.xoAuthDb.from("auth_audit_logs").select("log_id,event_type,actor_user_id,user_id,client_id,severity,created_at,details").eq("tenant_id",tid).eq("log_id",uuid).maybeSingle();if(q.error)throw new HttpError(502,"AUDIT_DETAIL_FAILED","Unable to read event");record=q.data;}
 else if(src==="SERVICES"){const q=await c.servicesDb.from("audit_events").select("audit_event_id,event_type,trace_id,actor,subject,source_system,occurred_at").eq("tenant_id",tid).eq("audit_event_id",uuid).maybeSingle();if(q.error)throw new HttpError(502,"AUDIT_DETAIL_FAILED","Unable to read event");record=q.data;}
 else {const r=await security(tid,scope({dateRange:"last_30_days"}),1,null,"detail",uuid);record=r.rows[0]||null;}
 if(!record)throw new HttpError(404,"AUDIT_NOT_FOUND","Audit event not found or source unavailable.");
 const [event]=await enrich(c,[normalize(src as Source,record)]);
 return {event};
}
export async function auditFilters(){return {categories:["Authentication","MFA","Microapp","RBAC","Crypto"],statuses:["success","failed","rejected","unknown"],sources:SOURCES}}

export async function auditLogsCapability(action:"list"|"summary"|"detail"|"filters",identity:XOIdentity,body:Record<string,unknown>,traceId:string,state:RuntimeAuthorizationState){
 identityTenant(identity,state);
 const request=identityInput(body);
 const context:CapabilityContext={identity,traceId,xoAuthDb:supabase,servicesDb:servicesSupabase};
 const data=action==="list"?await auditList(context,request):action==="summary"?await auditSummary(context,request):action==="detail"?await auditDetail(context,request):await auditFilters();
 return {ok:true,data,traceId};
}
