import type { CapabilityContext } from "./capabilities";
import { HttpError } from "./auth";

/**
 * Fetches exact-session app metadata from tenant-scoped XO Auth tables, and
 * exclusively uses XO Auth's existing authorized/decrypted session and location
 * endpoints for protected fields. No crypto secrets or ciphertext leave XO Auth.
 *
 * Existing XO Auth contracts are NOT event-scoped: location user_details returns
 * at most 50 recent events; active-sessions-page-data paginates 100 at a time.
 * Values that cannot be matched by immutable IDs are intentionally null.
 */
export type SignInAuditRef = { log_id:string; user_id:string|null; details:Record<string,unknown>|null };
export type SignInMetadata = {
  application:string|null; location:string|null; ip_address:string|null;
  device:string|null; mfa_verified:boolean|null; mfa_method:string|null;
  session_status:string|null; risk_level:string|null; correlated_session:boolean;
};
type Session = {
  session_id:string;user_id:string;client_id:string|null;location_event_id:string|null;
  mfa_verified:boolean|null;mfa_method:string|null;status:string|null;risk_level:string|null;
};
type DecryptedSession = {
  session_id:string;user_id:string;client_id:string|null;ip_address:string|null;
  device_label:string|null;mfa_verified:boolean|null;mfa_method:string|null;status:string|null;
};
type LocationEvent = {
  location_event_id:string;user_id:string|null;client_id:string|null;
  location_label:string|null;formatted_address:string|null;
  city:string|null;state:string|null;region:string|null;country:string|null;
};
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const safe=(v:unknown):string|null=>typeof v==="string"&&v.trim()&&!v.startsWith("xoenc:")?v.trim():null;
const uniq=(values:(string|null|undefined)[])=>[...new Set(values.filter((x):x is string=>typeof x==="string"&&!!x))];
function sessionId(row:SignInAuditRef):string|null {
  const value=row.details?.session_id;
  return typeof value==="string"&&UUID.test(value)?value:null;
}
async function rows<T>(request:PromiseLike<{data:T[]|null;error:any}>):Promise<T[]>{
  const {data,error}=await request;
  if(error)throw new HttpError(502,"SIGNIN_METADATA_QUERY_FAILED","Could not read authorized session metadata.");
  return data??[];
}
async function xoAuthPost(context:CapabilityContext,endpoint:string,input:Record<string,unknown>):Promise<any>{
  const url=context.xoAuthFunctionsBaseUrl.replace(/\/+$/,"")+"/"+endpoint;
  let response:Response;
  try {
    response=await fetch(url,{method:"POST",headers:{
      Authorization:"Bearer "+context.identity.accessToken,
      "Content-Type":"application/json",Accept:"application/json","X-Request-Id":context.traceId
    },body:JSON.stringify({
      ...input,tenant_id:context.identity.tenantId,actor_user_id:context.identity.userId
    }),signal:AbortSignal.timeout(20000)});
  }catch{throw new HttpError(502,"SIGNIN_XO_AUTH_UNAVAILABLE","XO Auth decrypted data service unavailable.");}
  if(!response.ok){
    throw new HttpError(response.status===404?404:response.status===401?401:response.status===403?403:502,
      "SIGNIN_XO_AUTH_RESOURCE_FAILED","Authorized XO Auth metadata could not be retrieved.");
  }
  const body=await response.json().catch(()=>null);
  if(!body||body.success!==true)throw new HttpError(502,"SIGNIN_XO_AUTH_RESPONSE_INVALID","Invalid XO Auth decrypted response.");
  return body;
}
/**
 * The existing active-sessions endpoint pages at 100, and decrypts inside
 * XO Auth. Never use this source to infer an unrelated/most-recent session.
 * A bounded scan can miss older sessions: unavailable data stays null.
 */
async function sessionDisplay(context:CapabilityContext,ids:Set<string>):Promise<Map<string,DecryptedSession>>{
  const found=new Map<string,DecryptedSession>();
  if(ids.size===0)return found;
  for(let page=1;page<=10&&found.size<ids.size;page++){
    const body=await xoAuthPost(context,"active-sessions-page-data",{page,page_size:100});
    if(!Array.isArray(body.sessions)||!body.pagination)
      throw new HttpError(502,"SIGNIN_XO_AUTH_RESPONSE_INVALID","Invalid session listing response.");
    for(const candidate of body.sessions as DecryptedSession[]){
      if(!candidate||!ids.has(candidate.session_id))continue;
      // Explicit session match plus user check happens again at event mapping.
      found.set(candidate.session_id,candidate);
    }
    const total=Number(body.pagination.total);
    if(!Number.isSafeInteger(total)||total<0)throw new HttpError(502,"SIGNIN_XO_AUTH_RESPONSE_INVALID","Invalid session pagination.");
    if(page*100>=total||body.sessions.length===0)break;
  }
  return found;
}
async function locationDisplay(context:CapabilityContext,userId:string,clientId:string|null):Promise<LocationEvent[]>{
  const data=await xoAuthPost(context,"location-tracking-page-data",{
    action:"user_details",selected_user_id:userId,client_id:clientId,timeline_limit:50
  });
  if(!Array.isArray(data.timeline)||data.user?.user_id!==userId)
    throw new HttpError(502,"SIGNIN_XO_AUTH_RESPONSE_INVALID","Invalid location response.");
  return data.timeline as LocationEvent[];
}
function locationLabel(e:LocationEvent):string|null{
  const formatted=safe(e.location_label)??safe(e.formatted_address);
  if(formatted)return formatted;
  const parts=[safe(e.city),safe(e.state)??safe(e.region),safe(e.country)].filter(Boolean);
  return parts.length?parts.join(", "):null;
}
export async function resolveSignInMetadata(
  context:CapabilityContext,events:SignInAuditRef[],includeSensitive:boolean
):Promise<Map<string,SignInMetadata>> {
  const result=new Map<string,SignInMetadata>();
  if(events.length===0)return result;
  const ids=uniq(events.map(sessionId));
  const sessions=ids.length?await rows<Session>(context.xoAuthDb.from("xo_sessions")
    .select("session_id,user_id,client_id,location_event_id,mfa_verified,mfa_method,status,risk_level")
    .eq("tenant_id",context.identity.tenantId).in("session_id",ids)):[];
  const bySession=new Map(sessions.map(s=>[s.session_id,s]));
  const clients=uniq(sessions.map(s=>s.client_id));
  const oauth=clients.length?await rows<{client_id:string;application_id:string|null}>(context.xoAuthDb.from("oauth_clients")
    .select("client_id,application_id").in("client_id",clients)):[];
  const applications=uniq(oauth.map(x=>x.application_id));
  const apps=applications.length?await rows<{uuid:string;app_name:string}>(context.xoAuthDb.from("xo_applications")
    .select("uuid,app_name").eq("tenant_id",context.identity.tenantId).in("uuid",applications)):[];
  const nameById=new Map(apps.map(a=>[a.uuid,safe(a.app_name)]));
  const nameByClient=new Map(oauth.map(c=>[c.client_id,c.application_id?nameById.get(c.application_id)??null:null]));

  const verified=events.map(e=>{
    const candidateId=sessionId(e),session=candidateId?bySession.get(candidateId):null;
    return {event:e,session:session&&session.user_id===e.user_id?session:null};
  });
  // Never call sensitive XO Auth endpoints for unknown or unlinked audit events.
  const validSessions=verified.map(v=>v.session).filter((v):v is Session=>v!==null);
  const decrypted=includeSensitive?await sessionDisplay(context,new Set(validSessions.map(s=>s.session_id))):new Map<string,DecryptedSession>();
  const locations=new Map<string,LocationEvent[]>();
  if(includeSensitive){
    const users=new Map<string,string|null>();
    for(const session of validSessions){
      if(!session.location_event_id)continue;
      // A query without the optional client filter avoids excluding valid location history.
      users.set(session.user_id,null);
    }
    // XO Auth limits user_details to 50 records; do not scan more than 25 users.
    if(users.size>25)throw new HttpError(413,"SIGNIN_LOCATION_QUERY_LIMIT","Reduce page size for location enrichment.");
    await Promise.all([...users].map(async ([user,client])=>{
      try{locations.set(user,await locationDisplay(context,user,client));}
      catch(e){
        // Existing endpoint returns 404 when user has no location data.
        // Never suppress denied access, crypto errors or service failure.
        if(e instanceof HttpError&&e.status===404){locations.set(user,[]);return;}
        throw e;
      }
    }));
  }
  for(const {event,session} of verified){
    const details=session?decrypted.get(session.session_id):null;
    // Do not use a decrypted record from a mismatched user.
    const authorizedDetails=details&&details.user_id===event.user_id?details:null;
    const location=session?.location_event_id
      ?(locations.get(session.user_id)??[]).find(l=>l.location_event_id===session.location_event_id
        &&(l.user_id===null||l.user_id===session.user_id)
        &&(!l.client_id||!session.client_id||l.client_id===session.client_id))
      :null;
    result.set(event.log_id,{
      application:session?.client_id?nameByClient.get(session.client_id)??null:null,
      location:location?locationLabel(location):null,
      ip_address:safe(authorizedDetails?.ip_address),
      device:safe(authorizedDetails?.device_label),
      mfa_verified:authorizedDetails?.mfa_verified??session?.mfa_verified??null,
      mfa_method:safe(authorizedDetails?.mfa_method??session?.mfa_method),
      session_status:safe(authorizedDetails?.status??session?.status),
      risk_level:safe(session?.risk_level),
      correlated_session:!!session
    });
  }
  return result;
}
