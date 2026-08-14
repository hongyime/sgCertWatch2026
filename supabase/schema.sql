create table if not exists public.findings (
  id text primary key,
  observed_at timestamptz not null,
  certificate_not_before text,
  registrable text not null,
  domains text[] not null default '{}',
  score integer not null,
  severity text not null check (severity in ('low', 'medium', 'high', 'critical')),
  signals jsonb not null default '[]'::jsonb,
  matched_brands text[] not null default '{}',
  matched_schemes text[] not null default '{}',
  issuer text,
  suppressed boolean not null default false,
  source jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists findings_observed_at_idx on public.findings (observed_at desc);
create index if not exists findings_severity_idx on public.findings (severity);
create index if not exists findings_registrable_idx on public.findings (registrable);
create index if not exists findings_matched_brands_idx on public.findings using gin (matched_brands);
create index if not exists findings_matched_schemes_idx on public.findings using gin (matched_schemes);

alter table public.findings enable row level security;

revoke all on table public.findings from anon, authenticated;
grant select, insert, update on table public.findings to service_role;
