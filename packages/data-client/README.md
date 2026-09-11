# @xoos/data-client

Shared XOOS data-plane client for Microapps.

The package deliberately does not own XO login, refresh tokens, or Supabase Auth sessions. It receives the XOOS Runtime data bridge, resolves the entitled data source, and creates a Supabase client whose `accessToken` callback always asks the Runtime for the current short-lived XOOS data token.

```ts
import { createXOOSSupabaseClient } from "@xoos/data-client";

const db = await createXOOSSupabaseClient({
  projectKey: "xoos-core",
  bridge: xoos.data,
});

const { data, error } = await db
  .from("wallets")
  .select("*");
```

Use `supabase.from()` for ordinary CRUD protected by RLS, `supabase.rpc()` for database-only transactional business logic, and `services.request()` only for operations that genuinely require server-side secrets or privileged execution.
