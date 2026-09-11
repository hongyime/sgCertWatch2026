-- Run as one standalone statement outside a transaction if source lookups regress.
create index concurrently if not exists finding_sources_finding_id_idx
  on public.finding_sources using btree (finding_id);
