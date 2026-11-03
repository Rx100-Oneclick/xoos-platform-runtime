# Sign-in Logs — root cause and corrected matching

## Live XO Auth data diagnosis (2026-11-03; read-only queries)
- 674 tenant-attributed `login_success` events; **0** have `details.session_id`.
- All 674 have `client_id`; 641 resolve through `oauth_clients.application_id` to a `xo_applications` record in the same tenant.
- 417 events contain `details.location_event_id`. Of those, 176 match an existing `auth_location_events` record for the same tenant and user.
- Those 176 also have exactly one session with matching tenant, user, client and location event ID.
- These counts are database-wide, not guaranteed per tenant or per display date.

## New resolution rules
1. **Application:** resolve independently from `auth_audit_logs.client_id` → `oauth_clients.application_id` → `xo_applications.uuid/app_name`, with mandatory `xo_applications.tenant_id` check.
2. **Location:** use only verified `auth_audit_logs.details.location_event_id` and verify location row's tenant/user/client. Fetch location display via the existing authorized/decrypted XO Auth `location-tracking-page-data` endpoint; match exact location event ID.
3. **Session IP/MFA:** prefer explicit `details.session_id`; when absent, accept the session associated with the verified audit location ID only when exactly one session matches tenant/user/client. Fetch decrypted IP from existing `active-sessions-page-data` and require exact session ID + user match.
4. If an explicit audit session ID exists but does not match, **do not** fall back to another session. If IDs are absent/unmatched, return null instead of inventing sensitive values.
5. Reuse existing XO Auth decryption services. **No crypto signing key or encryption code inside Runtime.**

## Known limits
- The existing XO Auth location API returns only up to 50 recent events for one user. Older matched location IDs can be absent and must be shown as unavailable.
- Existing session API uses pagination; this implementation scans at most 1,000 rows, potentially leaving older IPs unavailable.
- XO Auth location API enforces tenant administrator membership. Some Runtime READ-authorized users can receive a 403. Review the dedicated audit role policy before release.
- Existing live Supabase `xoos-runtime` Edge Function **still has its own code** and is not updated automatically by merging Runtime BFF GitHub PR.
- TypeScript checks, live authorized decryption tests, browser QA and deployed Edge Function synchronization are required before production rollout.
