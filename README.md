# XOOS Platform Runtime

Phase 2 foundation for the XOOS Microapp architecture.

## Workspace

- `packages/contracts` — shared Runtime/BFF contracts.
- `packages/runtime` — browser package published as `@xoos/runtime`.
- `services/runtime-bff` — centralized XOOS Runtime BFF.
- `apps/runtime-playground` — reserved for the test shell / Lovable playground.

## Architecture

Customer applications authenticate with XO Auth and give `@xoos/runtime` a token provider. The browser Runtime calls the XOOS Runtime BFF. The BFF validates XO JWTs against the XO JWKS and performs server-side Registry/Feed access. Browser code never receives Supabase secret/service-role credentials.

```text
Customer App
   -> @xoos/runtime
   -> XOOS Runtime BFF
      -> XO Auth JWKS verification
      -> Registry / Feed
      -> Capability services
```

## Setup

```bash
pnpm install
pnpm build
pnpm typecheck
pnpm test
```

## Runtime development

```bash
pnpm --filter @xoos/runtime build
```

## BFF environment

Copy `services/runtime-bff/.env.example` to a local `.env` and configure only backend secrets there. Never commit private keys, Supabase secret/service-role keys, or XO JWT private keys.

## Phase 2 first pilot

Use one internally registered XO application such as `XOOS Runtime Playground`, then entitle two native ESM Microapps (for example Wallet Management and Wallet Create) and validate: login -> Runtime init -> feed -> manifest -> ESM import -> custom element mount -> capability call.


## XO Auth resource capabilities

Microapps should not receive or manage the parent XO access token directly. XO Auth resource reads flow through the existing Runtime capability bridge:

```text
Microapp
  -> @xoos/microapp-adapter useXOAuth()
  -> XOOS bridge services.request()
  -> @xoos/runtime
  -> Runtime BFF
  -> XO Auth Edge Functions
```

The Runtime BFF provides these built-in capabilities:

- `xo-auth.applications.list` -> `xo-applications`
- `xo-auth.organization-members.list` -> `xo-organization-members`

The BFF forwards the already verified current-user XO bearer token server-to-server. It never exposes that token through Runtime context or the Microapp bridge.

Configure the BFF with:

```bash
XO_AUTH_FUNCTIONS_BASE_URL=https://bolngokjtpjomleifuto.supabase.co/functions/v1
```

Microapp usage:

```tsx
import { useXOAuth } from "@xoos/microapp-adapter";

const xoAuth = useXOAuth();

const { applications } = await xoAuth.applications.list({
  limit: 50,
  offset: 0
});

const { members } = await xoAuth.organizationMembers.list();
```

`@xoos/microapp-adapter@0.2.0` adds `useXOAuth`, `XOAuthClient`, and the typed XO Auth resource DTOs.
