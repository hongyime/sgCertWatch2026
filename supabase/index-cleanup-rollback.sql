-- Run as a standalone statement, outside a transaction, if identity lookups
-- are introduced or an observed query regression requires this index again.
create index concurrently if not exists findings_cert_identity_idx
  on public.findings using btree (cert_issuer_dn_sha256, cert_serial);
