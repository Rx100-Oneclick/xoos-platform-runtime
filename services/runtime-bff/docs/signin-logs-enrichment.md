# Sign-in Logs — OAuth application and encrypted session/location resolution

## Changes
- Application name is derived from **exactly correlated** audit event `details.session_id` -> tenant-scoped `xo_sessions.client_id` -> `oauth_clients.client_id/application_id` -> tenant-scoped `xo_applications.uuid/app_name`.
- Session association is accepted only when the selected session belongs to the authenticated tenant and its user_id equals the audit event's user_id. No user/time-based guesses.
- The same shared resolver is called from both the list and detail capability handlers.
- Detail IP comes only from matched `xo_sessions.ip_address`. Never use audit IP as a replacement.
- Session IP/user agent and location address/city/state/region/country fields are decrypted using XO Auth's existing **signed internal crypto gateway protocol** with the relevant record identifier and table name, following `xo-auth-backend-services/supabase/functions/_shared/crypto-service.ts` and `location-tracking-page-data`.
- Ciphertext is never emitted to the frontend. On missing session or unmatched location, return null.
- For correct tenant confidentiality, OAuth application lookups are scoped through `xo_applications.tenant_id`; location events must match the tenant and associated user.
- Existing authentication, capability READ authorization, event counts and timeline are unchanged.

## Required backend environment
The Runtime BFF must have **server-only** `SERVICES_DECRYPT_ENDPOINT`, `XO_AUTH_SERVICES_SHARED_SECRET` and `XO_AUTH_PLATFORM_TENANT_ID` configured, with credentials approved for XO Auth encrypted security metadata. This is *not* the Microapp environment and must not be shipped to browser code.

## Deployment blockers
1. GitHub Runtime BFF is not the live Supabase `xoos-runtime` Edge Function. Apply the equivalent handler/enrichment change to the actual deployed function, preserving all existing capabilities.
2. Verify session correlation in current `auth_audit_logs.details.session_id`. Events without a matching session remain blank for application, IP and location by design. Add correlation in the authentication audit writer for future events.
3. Verify deployed crypto gateway supports `xo_sessions` and `auth_location_events` record decryption for the configured platform tenant and that the Runtime server is authorized to sign requests.
4. Conduct TypeScript typecheck, unit/integration tests, cross-tenant authorization and actual encrypted data tests before deployment.
5. Do not use missing or null risk signals as a security clearance.

## Source status
Draft source update only; no database writes, deployments or production validation.
