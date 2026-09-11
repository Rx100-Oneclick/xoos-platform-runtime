-- XOOS data-plane registry used by the Runtime BFF.
-- Browser Microapps never query these control-plane tables directly.

create table if not exists xoos_control.xoos_data_sources (
  uuid uuid primary key default gen_random_uuid(),
  project_key text not null,
  provider text not null default 'supabase' check (provider in ('supabase')),
  environment text not null check (environment in ('development','staging','production')),
  supabase_url text not null,
  publishable_key text not null,
  status text not null default 'active' check (status in ('active','inactive','retired')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (project_key, environment)
);

create table if not exists xoos_control.xoos_client_data_source_entitlements (
  uuid uuid primary key default gen_random_uuid(),
  client_id text not null references public.oauth_clients(client_id) on delete cascade,
  data_source_id uuid not null references xoos_control.xoos_data_sources(uuid) on delete cascade,
  environment text not null check (environment in ('development','staging','production')),
  is_enabled boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (client_id, data_source_id, environment)
);

alter table xoos_control.xoos_data_sources enable row level security;
alter table xoos_control.xoos_client_data_source_entitlements enable row level security;

revoke all on xoos_control.xoos_data_sources from anon, authenticated;
revoke all on xoos_control.xoos_client_data_source_entitlements from anon, authenticated;

grant usage on schema xoos_control to service_role;
grant select on xoos_control.xoos_data_sources to service_role;
grant select on xoos_control.xoos_client_data_source_entitlements to service_role;

comment on table xoos_control.xoos_data_sources is
  'Public connection metadata for data projects. Never store service-role keys, database passwords, or signing private keys here.';

comment on table xoos_control.xoos_client_data_source_entitlements is
  'Maps XO OAuth clients to data sources they are allowed to request short-lived XOOS data tokens for.';
