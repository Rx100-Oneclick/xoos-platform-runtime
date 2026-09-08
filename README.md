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
