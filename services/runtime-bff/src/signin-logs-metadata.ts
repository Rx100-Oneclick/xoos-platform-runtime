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
export type SignInAuditRef = { log_id:string; user_id:string|null; client_id:string|null; details:Record<string,unknown>|null };
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
function locationId(e:SignInAuditRef):string|null {
  const value=e.details?.location_event_id;
  return typeof value==="string"&&UUID.test(value)?value:null;
}
/**
 * Audit client ID can independently identify the tenant application.
 * A session is trusted only if the audit session ID matches, or if the audit
 * location-event ID references exactly ONE session for the same tenant/user/client.
 * The location event is validated independently before asking XO Auth for plaintext.
 */
export async function resolveSignInMetadata(
  context:CapabilityContext,events:SignInAuditRef[],includeSensitive:boolean
):Promise<Map<string,SignInMetadata>> {
  const result=new Map<string,SignInMetadata>();
  if(!events.length)return result;
  const tenantId=context.identity.tenantId;
  const sessionIds=uniq(events.map(sessionId));
  const locationIds=uniq(events.map(locationId));
  const [byId,byLocation,locationRefs]=await Promise.all([
    sessionIds.length?rows<Session>(context.xoAuthDb.from("xo_sessions")
      .select("session_id,user_id,client_id,location_event_id,mfa_verified,mfa_method,status,risk_level")
      .eq("tenant_id",tenantId).in("session_id",sessionIds)):Promise.resolve([] as Session[]),
    locationIds.length?rows<Session>(context.xoAuthDb.from("xo_sessions")
      .select("session_id,user_id,client_id,location_event_id,mfa_verified,mfa_method,status,risk_level")
      .eq("tenant_id",tenantId).in("location_event_id",locationIds)):Promise.resolve([] as Session[]),
    locationIds.length?rows<{location_event_id:string;user_id:string|null;client_id:string|null}>(context.xoAuthDb.from("auth_location_events")
      .select("location_event_id,user_id,client_id").eq("tenant_id",tenantId).in("location_event_id",locationIds)):
      Promise.resolve([] as {location_event_id:string;user_id:string|null;client_id:string|null}[])
  ]);
  const sessionById=new Map(byId.map(s=>[s.session_id,s]));
  const sessionByLocation=new Map<string,Session[]>();
  for(const session of byLocation){
    if(!session.location_event_id)continue;
    const batch=sessionByLocation.get(session.location_event_id)??[];
    batch.push(session);
    sessionByLocation.set(session.location_event_id,batch);
  }
  const locationById=new Map(locationRefs.map(l=>[l.location_event_id,l]));
  const verified=events.map(event=>{
    const directId=sessionId(event),locId=locationId(event);
    const exactLocation=locId?locationById.get(locId):null;
    const location=exactLocation&&exactLocation.user_id===event.user_id
      &&(!exactLocation.client_id||exactLocation.client_id===event.client_id)?exactLocation:null;
    const direct=directId?sessionById.get(directId):null;
    const candidates=location?(sessionByLocation.get(location.location_event_id)??[]).filter(s=>
      s.user_id===event.user_id && !!event.client_id && s.client_id===event.client_id):[];
    const session=directId
      ?(direct&&direct.user_id===event.user_id&&!!event.client_id&&direct.client_id===event.client_id?direct:null)
      :(candidates.length===1?candidates[0]:null);
    return {event,session,location};
  });
  const clientIds=uniq(verified.map(v=>v.event.client_id??v.session?.client_id));
  const oauth=clientIds.length?await rows<{client_id:string;application_id:string|null}>(context.xoAuthDb.from("oauth_clients")
    .select("client_id,application_id").in("client_id",clientIds)):[];
  const applicationIds=uniq(oauth.map(x=>x.application_id));
  const apps=applicationIds.length?await rows<{uuid:string;app_name:string}>(context.xoAuthDb.from("xo_applications")
    .select("uuid,app_name").eq("tenant_id",tenantId).in("uuid",applicationIds)):[];
  const appNames=new Map(apps.map(a=>[a.uuid,safe(a.app_name)]));
  const clientNames=new Map(oauth.map(c=>[c.client_id,c.application_id?appNames.get(c.application_id)??null:null]));

  const exactSessions=verified.map(x=>x.session).filter((v):v is Session=>!!v);
  const decrypted=includeSensitive?await sessionDisplay(context,new Set(exactSessions.map(s=>s.session_id))):new Map<string,DecryptedSession>();
  const locations=new Map<string,LocationEvent[]>();
  if(includeSensitive){
    const users=uniq(verified.filter(v=>v.location).map(v=>v.event.user_id));
    if(users.length>25)throw new HttpError(413,"SIGNIN_LOCATION_QUERY_LIMIT","Reduce page size for authorized location enrichment.");
    await Promise.all(users.map(async user=>{
      try{locations.set(user,await locationDisplay(context,user,null));}
      catch(e){
        if(e instanceof HttpError&&e.status===404){locations.set(user,[]);return;}
        throw e;
      }
    }));
  }
  for(const {event,session,location} of verified){
    const display=session?decrypted.get(session.session_id):null;
    const authorizedDisplay=display&&display.user_id===event.user_id
      &&(!event.client_id||display.client_id===event.client_id)?display:null;
    const exactLocation=location?(locations.get(event.user_id??"")??[]).find(l=>
      l.location_event_id===location.location_event_id
      &&l.user_id===event.user_id
      &&(!l.client_id||l.client_id===event.client_id)):null;
    const clientId=event.client_id??session?.client_id;
    result.set(event.log_id,{
      application:clientId?clientNames.get(clientId)??null:null,
      location:exactLocation?locationLabel(exactLocation):null,
      ip_address:safe(authorizedDisplay?.ip_address),
      device:safe(authorizedDisplay?.device_label),
      mfa_verified:authorizedDisplay?.mfa_verified??session?.mfa_verified??null,
      mfa_method:safe(authorizedDisplay?.mfa_method??session?.mfa_method),
      session_status:safe(authorizedDisplay?.status??session?.status),
      risk_level:safe(session?.risk_level),
      correlated_session:!!session
    });
  }
  return result;
}
