begin;

create table if not exists public.intel_evidence (
  id text primary key,
  domain text not null check (
    length(domain) <= 253 and domain = lower(domain)
    and domain ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?([.][a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
  ),
  source text not null check (source in ('openphish', 'urlscan', 'urlhaus', 'threatfox')),
  source_ref text not null check (
    (source = 'openphish' and source_ref ~ '^https://(www[.])?openphish[.]com(/|$)')
    or (source = 'urlscan' and source_ref ~ '^https://urlscan[.]io(/|$)')
    or (source = 'urlhaus' and source_ref ~ '^https://urlhaus[.]abuse[.]ch(/|$)')
    or (source = 'threatfox' and source_ref ~ '^https://threatfox[.]abuse[.]ch(/|$)')
  ),
  verdict text not null check (verdict in ('phishing', 'malware', 'observed')),
  observed_at timestamptz not null,
  expires_at timestamptz not null,
  details jsonb not null default '{}'::jsonb
);

create index if not exists intel_evidence_domain_expires_idx on public.intel_evidence (domain, expires_at);
create index if not exists intel_evidence_expires_idx on public.intel_evidence (expires_at);
create index if not exists findings_intel_candidates_idx
  on public.findings (score desc, observed_at desc, id) where suppressed = false and score >= 60;
create index if not exists findings_intel_domains_idx
  on public.findings using gin (domains) where suppressed = false;
create index if not exists findings_intel_empty_domains_idx
  on public.findings (registrable) where suppressed = false and cardinality(domains) = 0;
create index if not exists findings_intel_registrable_score_idx
  on public.findings (registrable, score desc, observed_at desc, id)
  where suppressed = false and score >= 60;

alter table public.intel_evidence enable row level security;
revoke all on table public.intel_evidence from public, anon, authenticated;
grant select on table public.intel_evidence to anon;
grant select, insert, update, delete on table public.intel_evidence to service_role;

drop policy if exists intel_evidence_public_read on public.intel_evidence;
create policy intel_evidence_public_read on public.intel_evidence
  for select to anon
  using (
    expires_at > now()
    and exists (
      select 1 from public.findings f
      where f.suppressed = false
        and (
          f.domains @> array[intel_evidence.domain]
          or (cardinality(f.domains) = 0
            and f.registrable = intel_evidence.domain)
        )
    )
  );

-- Service polling chooses one CT finding per registrable before applying the limit.
create or replace function public.intel_candidate_findings(candidate_limit integer default 500)
returns setof public.findings
language sql stable security invoker set search_path = ''
as $$
  select f.*
  from (
    select candidate.id, candidate.score, candidate.observed_at,
      row_number() over (
        partition by candidate.score >= 70
        order by candidate.score desc, candidate.observed_at desc, candidate.id
      ) as bucket_rank
    from (
      select distinct on (finding.registrable)
        finding.id, finding.registrable, finding.score, finding.observed_at
      from public.findings finding
      where finding.suppressed = false and finding.score >= 60
      order by finding.registrable, finding.score desc, finding.observed_at desc, finding.id
    ) candidate
    order by bucket_rank, candidate.score desc, candidate.observed_at desc, candidate.id
    limit least(greatest(candidate_limit, 1), 1000)
  ) candidate
  join public.findings f on f.id = candidate.id
  order by candidate.bucket_rank, candidate.score desc, candidate.observed_at desc, candidate.id;
$$;
revoke all on function public.intel_candidate_findings(integer) from public, anon, authenticated;
grant execute on function public.intel_candidate_findings(integer) to service_role;

-- Hosts have already passed the shared evidence verdict filter in the read API.
create or replace function public.intel_findings_for_hosts(hosts text[], result_limit integer default 100)
returns setof public.findings
language sql stable security invoker set search_path = ''
as $$
  select f.*
  from public.findings f
  where f.suppressed = false and f.score >= 60
    and (f.domains && hosts
      or (cardinality(f.domains) = 0 and f.registrable = any(hosts)))
  order by f.score desc, f.observed_at desc, f.id
  limit least(greatest(result_limit, 1), 100);
$$;
revoke all on function public.intel_findings_for_hosts(text[], integer) from public, anon, authenticated;
grant execute on function public.intel_findings_for_hosts(text[], integer) to anon, service_role;

drop policy if exists ingest_state_public_read on public.ingest_state;
create policy ingest_state_public_read on public.ingest_state
  for select to anon
  using (key in ('ct_poll_status', 'ct_source_state', 'intel_poll_status'));

commit;
