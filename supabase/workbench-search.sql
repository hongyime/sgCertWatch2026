-- supabase/workbench-search.sql
--
-- Parameterised RPC for the bounded historical findings search (Task 8).
-- Security: SECURITY INVOKER + anon-visible unsuppressed rows only.
-- Never boosts from shared registrable / IP / sibling: only the
-- exact-host fresh intel_evidence row (host membership in findings.domains).
-- Statement timeout: SET LOCAL statement_timeout = '3s'.
--
-- Deploy: apply only after Task 7 capacity check passes.

-- ---------------------------------------------------------------------------
-- Indexes
--
-- Prior schema had no findings.priority_score column; the earlier draft
-- indexed a nonexistent column. We index findings.score instead (the
-- authoritative CT score), plus a prefix-supporting registrable index.
-- ---------------------------------------------------------------------------
create index if not exists findings_registrable_prefix_idx
  on public.findings (registrable text_pattern_ops)
  where suppressed = false;

create index if not exists findings_score_observed_id_idx
  on public.findings (score desc, observed_at desc, id asc)
  where suppressed = false;

-- Support host-membership lookups against domains[] for the intel-boost join.
create index if not exists findings_domains_gin_idx
  on public.findings using gin (domains)
  where suppressed = false;

-- Match the anon-visible slice of intel_evidence used by the boost.
create index if not exists intel_evidence_domain_expires_idx
  on public.intel_evidence (domain, expires_at desc);

-- ---------------------------------------------------------------------------
-- Freshness predicate: identical to lib/intel/evidence.js attachIntelEvidence.
--   openphish  + verdict='phishing'
--   urlhaus    + verdict='malware'  + details.url_status='online'
--   threatfox  + verdict='malware'  + (details.confidence)::int >= 75
--   otherwise  verdict in ('phishing','malware') + details.verdict_confirmed=true
-- The row must not be expired and must be observed no more than 5 min in future.
-- ---------------------------------------------------------------------------
create or replace function public.workbench_intel_is_strong(
  p_source text, p_verdict text, p_details jsonb
)
returns boolean
language sql immutable
as $$
  select case p_source
    when 'openphish' then p_verdict = 'phishing'
    when 'urlhaus'   then p_verdict = 'malware'
                          and coalesce(p_details->>'url_status','') = 'online'
    when 'threatfox' then p_verdict = 'malware'
                          and coalesce((p_details->>'confidence')::numeric, 0) >= 75
    else                p_verdict in ('phishing','malware')
                          and coalesce((p_details->>'verdict_confirmed')::boolean, false)
  end;
$$;

revoke all on function public.workbench_intel_is_strong(text,text,jsonb)
  from public, anon, authenticated;
grant execute on function public.workbench_intel_is_strong(text,text,jsonb)
  to anon, service_role;

-- ---------------------------------------------------------------------------
-- RPC: workbench_search_findings
--
-- Returns jsonb { findings, evaluated_at }.  Callers already validate every
-- input in lib/findings-query.js; the RPC re-validates enums as defence in
-- depth and always applies WHERE filters before the LIMIT + 1 probe.
-- ---------------------------------------------------------------------------
create or replace function public.workbench_search_findings(
  p_q            text    default '',
  p_severity     text    default '',
  p_brand_id     text    default '',
  p_from_at      text    default '',
  p_to_at        text    default '',
  p_verdict      text    default '',
  p_source       text    default '',
  p_priority_min integer default null,
  p_priority_max integer default null,
  p_sort         text    default 'observed',
  p_limit        integer default 50,
  p_after_id     text    default null,
  p_after_obs    text    default null,
  p_after_pri    integer default null,
  p_evaluated_at text    default null
)
returns jsonb
language plpgsql
stable
security invoker
set search_path = pg_catalog, public
as $$
declare
  v_rows       jsonb;
  v_limit      integer;
  v_eval_at    timestamptz;
  v_from       timestamptz;
  v_to         timestamptz;
begin
  perform set_config('statement_timeout', '3s', true);

  -- Enum validation (defence in depth)
  if p_severity <> '' and p_severity not in ('critical','high','medium','low') then
    raise exception 'invalid_severity' using errcode = 'P0001';
  end if;
  if p_verdict <> '' and p_verdict not in ('phishing','malware','observed') then
    raise exception 'invalid_verdict' using errcode = 'P0001';
  end if;
  if p_source <> '' and p_source not in ('openphish','urlscan','urlhaus','threatfox') then
    raise exception 'invalid_source' using errcode = 'P0001';
  end if;
  if p_sort not in ('observed','priority') then
    raise exception 'invalid_sort' using errcode = 'P0001';
  end if;
  if length(coalesce(p_q, '')) > 253 then
    raise exception 'query_too_long' using errcode = 'P0001';
  end if;

  v_limit   := least(greatest(coalesce(p_limit, 50), 1), 100) + 1;
  v_eval_at := coalesce(nullif(p_evaluated_at, '')::timestamptz, now());
  v_from    := nullif(p_from_at, '')::timestamptz;
  v_to      := nullif(p_to_at, '')::timestamptz;

  with base as (
    select
      f.*,
      -- Compute exact-host intel boost using an evaluated_at-consistent
      -- snapshot of intel_evidence.  Only unsuppressed findings and only
      -- rows whose domain is in f.domains[] contribute (no registrable
      -- / sibling / IP inheritance).
      case
        when f.score >= 60 and exists (
          select 1
            from public.intel_evidence ie
           where ie.domain = any(f.domains)
             and ie.expires_at > v_eval_at
             and ie.observed_at <= v_eval_at + interval '5 minutes'
             and public.workbench_intel_is_strong(ie.source, ie.verdict, ie.details)
        ) then 10 else 0
      end as intel_priority_boost
    from public.findings f
    where f.suppressed = false
      -- Anon-visible slice explicitly (defence in depth on top of RLS).
      -- text_pattern_ops prefix (case-insensitive registrable prefix).
      and (p_q = '' or f.registrable ilike (replace(replace(replace(p_q,E'\\',E'\\\\'),'%',E'\\%'),'_',E'\\_') || '%') escape E'\\')
      and (p_severity = '' or f.severity = p_severity)
      and (p_brand_id = ''
           or f.matched_brands @> array[p_brand_id])
      and (v_from is null or f.observed_at >= v_from)
      and (v_to   is null or f.observed_at <= v_to)
  ),
  scoped as (
    select b.*, (b.score + b.intel_priority_boost) as priority_score
    from base b
    where
      -- Verdict + source filter share the same fresh exact-host evidence row.
      (p_verdict = '' and p_source = '')
      or exists (
        select 1
          from public.intel_evidence ie
         where ie.domain = any(b.domains)
           and ie.expires_at > v_eval_at
           and ie.observed_at <= v_eval_at + interval '5 minutes'
           and (p_source  = '' or ie.source  = p_source)
           and (p_verdict = '' or ie.verdict = p_verdict)
      )
  ),
  bounded as (
    select s.*
    from scoped s
    where
      -- Priority range (nullable both sides)
      (p_priority_min is null or s.priority_score >= p_priority_min)
      and (p_priority_max is null or s.priority_score <= p_priority_max)
      -- Cursor continuation
      and (
        p_after_id is null
        or (
          case p_sort
            when 'priority' then
              (s.priority_score < p_after_pri)
              or (s.priority_score = p_after_pri and s.observed_at < p_after_obs::timestamptz)
              or (s.priority_score = p_after_pri and s.observed_at = p_after_obs::timestamptz and s.id > p_after_id)
            else -- 'observed'
              s.observed_at < p_after_obs::timestamptz
              or (s.observed_at = p_after_obs::timestamptz and s.id > p_after_id)
          end
        )
      )
  )
  select coalesce(jsonb_agg(row_to_json(t.*) order by t.o1, t.o2, t.o3), '[]'::jsonb)
    into v_rows
  from (
    select b.*,
           case when p_sort = 'priority' then -b.priority_score else 0 end as o1,
           extract(epoch from b.observed_at) * -1                          as o2,
           b.id                                                            as o3
      from bounded b
     order by o1, o2, o3
     limit v_limit
  ) t;

  return jsonb_build_object(
    'findings',     coalesce(v_rows, '[]'::jsonb),
    'evaluated_at', v_eval_at
  );
end;
$$;

revoke all on function public.workbench_search_findings(
  text,text,text,text,text,text,text,integer,integer,text,integer,text,text,integer,text
) from public, authenticated;
grant execute on function public.workbench_search_findings(
  text,text,text,text,text,text,text,integer,integer,text,integer,text,text,integer,text
) to anon, service_role;
