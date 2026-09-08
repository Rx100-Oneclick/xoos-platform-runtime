# XOOS Runtime Playground

Create the UI here or connect a dedicated Lovable project to this workspace/repository.

The playground should:

1. Sign in with XO Auth using an internally registered development application.
2. Instantiate `@xoos/runtime` with that `clientId`, the Runtime BFF base URL, and `getFreshXOAccessToken`.
3. Call `runtime.initialize()`.
4. Show Runtime context and feed.
5. Mount/unmount the first two native ESM pilot Microapps.
6. Exercise `runtime.health` before adding real business capabilities.

No Supabase secret/service-role credential belongs in this application.
