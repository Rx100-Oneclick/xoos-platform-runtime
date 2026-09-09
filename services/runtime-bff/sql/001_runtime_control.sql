-- Phase 2 Runtime control-plane tables.
-- Review and apply through a controlled Supabase migration, not from browser code.

create table if not exists xoos_control.xoos_microapp_deployments (
  uuid uuid primary key default gen_random_uuid(),
  microapp_id uuid not null references xoos_control.xoos_microapps(uuid) on delete cascade,
  environment text not null check (environment in ('development','staging','production')),
  version text not null,
  manifest_url text not null,
  entry_url text,
  integrity text,
  status text not null default 'active' check (status in ('active','inactive','retired')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (microapp_id, environment, version)
);

create table if not exists xoos_control.xoos_client_microapp_entitlements (
  uuid uuid primary key default gen_random_uuid(),
  client_id text not null references public.oauth_clients(client_id) on delete cascade,
  microapp_id uuid not null references xoos_control.xoos_microapps(uuid) on delete cascade,
  environment text not null check (environment in ('development','staging','production')),
  is_enabled boolean not null default true,
  version_policy text not null default 'latest_compatible' check (version_policy in ('latest_compatible','pinned')),
  pinned_version text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (client_id, microapp_id, environment),
  check (version_policy <> 'pinned' or pinned_version is not null)
);

alter table xoos_control.xoos_microapp_deployments enable row level security;
alter table xoos_control.xoos_client_microapp_entitlements enable row level security;

-- These are control-plane tables. Runtime browser clients must not query them directly.
-- Access them through the Runtime BFF using a backend-only Supabase secret/service credential.
revoke all on xoos_control.xoos_microapp_deployments from anon, authenticated;
revoke all on xoos_control.xoos_client_microapp_entitlements from anon, authenticated;
