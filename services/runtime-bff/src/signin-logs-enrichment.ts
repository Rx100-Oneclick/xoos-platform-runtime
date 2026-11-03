import type { CapabilityContext } from "./capabilities";
import { HttpError } from "./auth";

export type AuditRef={log_id:string;user_id:string|null;details:Record<string,unknown>|null};
type Session={session_id:string;user_id:string;client_id:string|null;location_event_id:string|null;ip_address:string|null;user_agent:string|null;mfa_verified:boolean|null;mfa_method:string|null;status:string|null;risk_level:string|null};
type Location={location_event_id:string;user_id:string|null;formatted_address:string|null;city:string|null;state:string|null;region:string|null;country:string|null;ip_city:string|null;ip_region:string|null;ip_country:string|null};
export type Enrichment={application:string|null;location:string|null;ip_address:string|null;device:string|null;session:Session|null};
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const isCipher=(s:unknown)=>typeof s==="string"&&s.startsWith("xoenc:");
const safe=(s:unknown):string|null=>typeof s==="string"&&s.trim()&&!isCipher(s)?s.trim():null;
const uniq=(items:(string|null|undefined)[]):string[]=>[...new Set(items.filter((x):x is string=>!!x))];
async function db<T>(q:PromiseLike<{data:T[]|null;error:any}>):Promise<T[]>{
 const {data,error}=await q;
 if(error)throw new HttpError(502,"SIGNIN_ENRICHMENT_FAILED","Unable to resolve authorized sign-in metadata.");
 return data??[];
}
function sessionId(e:AuditRef):string|null{
 const x=e.details?.session_id;return typeof x==="string"&&UUID.test(x)?x:null;
}
function hex(bytes:ArrayBuffer):string{return [...new Uint8Array(bytes)].map(v=>v.toString(16).padStart(2,"0")).join("");}
async function signedDecryption(tableName:"xo_sessions"|"auth_location_events",data:{id:string;fields:Record<string,string|null>}[]):Promise<Map<string,Record<string,string|null>>>{
 const encrypted=data.map(r=>({id:r.id,fields:Object.fromEntries(Object.entries(r.fields).filter(([,v])=>isCipher(v)))})).filter(r=>Object.keys(r.fields).length);
 const result=new Map<string,Record<string,string|null>>();
 if(!encrypted.length)return result;
 const endpoint=process.env.SERVICES_DECRYPT_ENDPOINT;
 const secret=process.env.XO_AUTH_SERVICES_SHARED_SECRET;
 const platformTenant=process.env.XO_AUTH_PLATFORM_TENANT_ID;
 if(!endpoint||!secret||!platformTenant||!UUID.test(platformTenant))
  throw new HttpError(503,"SIGNIN_DECRYPT_NOT_CONFIGURED","XO Auth decryption is not configured.");
 const body=JSON.stringify({tenant_id:platformTenant,table_name:tableName,records:encrypted,reason:"signin_logs_authorized_display"});
 const encoder=new TextEncoder();
 const bodyHash=hex(await crypto.subtle.digest("SHA-256",encoder.encode(body)));
 const timestamp=Date.now().toString(),nonce=crypto.randomUUID();
 const hmacKey=await crypto.subtle.importKey("raw",encoder.encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
 const signature=hex(await crypto.subtle.sign("HMAC",hmacKey,encoder.encode(timestamp+"."+nonce+"."+bodyHash)));
 let response:Response;
 try {
  response=await fetch(endpoint,{method:"POST",headers:{"Content-Type":"application/json","X-XO-Source":"xo-auth","X-XO-Timestamp":timestamp,"X-XO-Nonce":nonce,"X-XO-Signature":signature},body,signal:AbortSignal.timeout(8000)});
 }catch{throw new HttpError(502,"SIGNIN_DECRYPT_UNAVAILABLE","XO Auth decryption service unavailable.");}
 if(!response.ok)throw new HttpError(502,"SIGNIN_DECRYPT_FAILED","Unable to decrypt authorized sign-in metadata.");
 const json=await response.json().catch(()=>null);
 if(!json||!Array.isArray(json.records)||json.records.length!==encrypted.length)
  throw new HttpError(502,"SIGNIN_DECRYPT_INVALID","Invalid decrypted data response.");
 const expected=new Map(encrypted.map(r=>[r.id,Object.keys(r.fields)]));
 for(const rec of json.records){
  if(!rec||typeof rec.id!=="string"||!expected.has(rec.id)||result.has(rec.id)||!rec.fields||typeof rec.fields!=="object")
   throw new HttpError(502,"SIGNIN_DECRYPT_INVALID","Invalid decrypted data response.");
  const fields:Record<string,string|null>={};
  for(const key of expected.get(rec.id)!){
   const val=rec.fields[key];
   if(val!==null&&typeof val!=="string")throw new HttpError(502,"SIGNIN_DECRYPT_INVALID","Invalid decrypted data response.");
   fields[key]=safe(val);
  }
  result.set(rec.id,fields);
 }
 return result;
}
function locationName(v:Location):string|null{
 const formatted=safe(v.formatted_address);
 if(formatted)return formatted;
 const parts=[safe(v.city)??safe(v.ip_city),safe(v.state)??safe(v.region)??safe(v.ip_region),safe(v.country)??safe(v.ip_country)].filter(Boolean);
 return parts.length?parts.join(", "):null;
}
function deviceName(ua:string|null):string|null{
 if(!ua)return null;
 if(/iPhone|iPad/i.test(ua))return "iOS";
 if(/Android/i.test(ua))return "Android";
 if(/Macintosh|Mac OS X/i.test(ua))return "macOS";
 if(/Windows/i.test(ua))return "Windows";
 if(/Linux/i.test(ua))return "Linux";
 return null;
}
/** Correlate an audit event to ONLY its explicit session. Never infer sessions using user_id or time. */
export async function enrichSignInEvents(context:CapabilityContext,events:AuditRef[]):Promise<Map<string,Enrichment>>{
 const out=new Map<string,Enrichment>();
 if(!events.length)return out;
 const ids=uniq(events.map(sessionId));
 const sessions=ids.length?await db<Session>(context.xoAuthDb.from("xo_sessions")
  .select("session_id,user_id,client_id,location_event_id,ip_address,user_agent,mfa_verified,mfa_method,status,risk_level")
  .eq("tenant_id",context.identity.tenantId).in("session_id",ids)):[];
 const sessionsById=new Map(sessions.map(s=>[s.session_id,s]));
 const clientIds=uniq(sessions.map(s=>s.client_id));
 const clients=clientIds.length?await db<{client_id:string;application_id:string|null}>(context.xoAuthDb.from("oauth_clients")
  .select("client_id,application_id").in("client_id",clientIds)):[];
 const appIds=uniq(clients.map(x=>x.application_id));
 const apps=appIds.length?await db<{uuid:string;app_name:string}>(context.xoAuthDb.from("xo_applications")
  .select("uuid,app_name").eq("tenant_id",context.identity.tenantId).in("uuid",appIds)):[];
 const appNames=new Map(apps.map(a=>[a.uuid,a.app_name]));
 const clientNames=new Map(clients.map(c=>[c.client_id,c.application_id?appNames.get(c.application_id)??null:null]));
 const locationIds=uniq(sessions.map(s=>s.location_event_id));
 const locations=locationIds.length?await db<Location>(context.xoAuthDb.from("auth_location_events")
  .select("location_event_id,user_id,formatted_address,city,state,region,country,ip_city,ip_region,ip_country")
  .eq("tenant_id",context.identity.tenantId).in("location_event_id",locationIds)):[];
 const locationById=new Map(locations.map(l=>[l.location_event_id,l]));
 const [decodedSessions,decodedLocations]=await Promise.all([
  signedDecryption("xo_sessions",sessions.map(s=>({id:s.session_id,fields:{ip_address:s.ip_address,user_agent:s.user_agent}}))),
  signedDecryption("auth_location_events",locations.map(l=>({id:l.location_event_id,fields:{formatted_address:l.formatted_address,city:l.city,state:l.state,region:l.region,country:l.country,ip_city:l.ip_city,ip_region:l.ip_region,ip_country:l.ip_country}})))
 ]);
 for(const event of events){
  const id=sessionId(event);
  const found=id?sessionsById.get(id):null;
  const session=found&&found.user_id===event.user_id?found:null;
  const sessionDecoded=session?decodedSessions.get(session.session_id):null;
  const loc=session?.location_event_id?locationById.get(session.location_event_id):null;
  const allowedLocation=loc&&(loc.user_id===null||loc.user_id===session?.user_id)?loc:null;
  const locationDecoded=allowedLocation?decodedLocations.get(allowedLocation.location_event_id):null;
  out.set(event.log_id,{
   session:session??null,application:session?.client_id?clientNames.get(session.client_id)??null:null,
   ip_address:safe(sessionDecoded?.ip_address??session?.ip_address),
   device:deviceName(safe(sessionDecoded?.user_agent??session?.user_agent)),
   location:allowedLocation?locationName({...allowedLocation,...locationDecoded}):null
  });
 }
 return out;
}
