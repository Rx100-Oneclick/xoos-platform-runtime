import type { CapabilityContext } from "./capabilities";
import { HttpError } from "./auth";

/**
 * XO Auth owns sign-in PII decryption. Runtime sends only already-authorized
 * audit log identifiers; no ciphertext, credentials or secret crypto keys.
 */
export type SignInEnrichment = {
 log_id:string;
 application:string|null;
 ip_address:string|null;
 location:string|null;
 device:string|null;
 mfa_verified:boolean|null;
 mfa_method:string|null;
 session_status:string|null;
 risk_level:string|null;
 correlated_session:boolean;
};
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const safe=(v:unknown):string|null=>typeof v==="string"&&v.trim()&&!v.startsWith("xoenc:")?v.trim():null;
export async function resolveSignInEnrichment(
 context:CapabilityContext,logIds:string[]
):Promise<Map<string,SignInEnrichment>> {
 const out=new Map<string,SignInEnrichment>();
 if(!logIds.length)return out;
 if(logIds.length>25||logIds.some(id=>!UUID.test(id)))
  throw new HttpError(400,"SIGNIN_ENRICHMENT_INPUT_INVALID","Invalid sign-in log identifiers.");
 const endpoint=context.xoAuthFunctionsBaseUrl.replace(/\/+$/,"")+"/xo-signin-log-enrichment";
 let response:Response;
 try{
  response=await fetch(endpoint,{
   method:"POST",headers:{
    Authorization:"Bearer "+context.identity.accessToken,
    "Content-Type":"application/json",Accept:"application/json",
    "X-Request-Id":context.traceId
   },
   body:JSON.stringify({log_ids:logIds}),
   signal:AbortSignal.timeout(20000)
  });
 }catch{
  throw new HttpError(502,"SIGNIN_XO_AUTH_UNAVAILABLE","XO Auth sign-in metadata service unavailable.");
 }
 if(!response.ok){
  throw new HttpError(response.status===401?401:response.status===403?403:502,
   "SIGNIN_XO_AUTH_ENRICHMENT_FAILED","Unable to retrieve authorized sign-in metadata.");
 }
 const body=await response.json().catch(()=>null);
 if(!body||body.success!==true||body.tenant_id!==context.identity.tenantId||!Array.isArray(body.records)
    ||body.records.length!==logIds.length)
  throw new HttpError(502,"SIGNIN_XO_AUTH_RESPONSE_INVALID","Invalid XO Auth sign-in metadata response.");
 const allowed=new Set(logIds);
 for(const entry of body.records){
  if(!entry||typeof entry.log_id!=="string"||!allowed.has(entry.log_id)||out.has(entry.log_id))
   throw new HttpError(502,"SIGNIN_XO_AUTH_RESPONSE_INVALID","Unexpected sign-in metadata row.");
  out.set(entry.log_id,{
   log_id:entry.log_id,
   application:safe(entry.application),
   ip_address:safe(entry.ip_address),
   location:safe(entry.location),
   device:safe(entry.device),
   mfa_verified:typeof entry.mfa_verified==="boolean"?entry.mfa_verified:null,
   mfa_method:safe(entry.mfa_method),
   session_status:safe(entry.session_status),
   risk_level:safe(entry.risk_level),
   correlated_session:entry.correlated_session===true
  });
 }
 return out;
}
