# Sign-in Logs: reuse existing XO Auth decrypted services

## Behavior
- List/detail resolve application through verified audit `details.session_id` -> tenant-scoped `xo_sessions.client_id` -> `oauth_clients.application_id` -> tenant-scoped `xo_applications.app_name`.
- The shared resolver is used by both capabilities.
- Existing `active-sessions-page-data` returns decrypted session `ip_address`, device label and authentication values; existing `location-tracking-page-data` (`action:user_details`) returns decrypted location history. Runtime does NOT decrypt fields, read crypto configuration or hold gateway secrets.
- No session association by user-only or approximate login time. Every event requires an explicit session ID, a matching user ID and tenant.
- Location must match the exact session `location_event_id` and user. Never display latest location as the selected login's location.
- Existing `xo-auth.signin-logs.timeline`, sign-in totals, tenant restriction and READ capability gate remain unchanged.

## Existing endpoint constraints / integration validation
- `active-sessions-page-data` requests page size 100 but queries the whole tenant internally for each page. The Runtime scans no more than 10 pages; older sessions outside the scan remain unavailable.
- `location-tracking-page-data` user_details fetches at most 50 recent events. Missing historical location may yield null, even when an older location_event_id exists.
- The location endpoint enforces XO Auth's existing tenant ADMIN role. Runtime READ permissions are not a substitute for that authorization; requests by other roles may return 403.
- Missing location history is returned as null; other service/crypto failures fail closed.
- Live `xoos-runtime` Supabase Edge Function is **not** automatically updated by the BFF GitHub repository. Integrate equivalent changes into the deployed Edge Function.
- Validate actual audit `details.session_id` coverage. Historical records without session identifiers will not show application/IP/location. Improve audit writer for future events if needed.
- For scalable and complete coverage, an exact-session lookup extension to an existing XO Auth endpoint would be preferable to repeated paginated/history scans, but is not included in this two-repository change.

## Tests required before merge/deployment
- Typecheck and build BFF + Native ESM Microapp, SHA-256 artifact integrity and browser layout.
- Authorized admin read, READ-only non-admin behavior, wrong tenant, wrong session/user, expired token and encryption gateway error cases.
- Confirm same application in list/detail and correct decrypted IP/location from existing XO Auth services.
- Verify unmatched sessions/locations render `—` and do not leak ciphertext.
No deployment or production integration tests performed.
