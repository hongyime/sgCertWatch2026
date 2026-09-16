// Physical metadata comparison only. Run after test_evidence_postgres.mjs in
// its isolated fixture database. Never import or export application records.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import pg from "pg";

const connectionString = process.env.EVIDENCE_TEST_DATABASE_URL;
if (!connectionString) throw new Error("Expected a disposable fixture database");
const target = new URL(connectionString);
if (!["127.0.0.1", "localhost", "[::1]"].includes(target.hostname)
    || !/^\/prawn_evidence_fixture_[a-z0-9]+$/.test(target.pathname)) {
  throw new Error("Refusing database outside the disposable loopback fixture scope");
}
let addresses = ["127.0.0.1", "::1"];
if (process.env.GITHUB_ACTIONS === "true") {
  const id = process.env.EVIDENCE_TEST_CONTAINER_ID;
  assert(/^[a-f0-9]{64}$/.test(id));
  const [container] = JSON.parse(execFileSync("docker", ["inspect", id], { encoding: "utf8" }));
  assert.equal(container.Id, id); assert.equal(container.Config.Image, "postgres:17.11");
  assert(container.Config.Env.includes("POSTGRES_DB=" + target.pathname.slice(1)));
  addresses = Object.values(container.NetworkSettings.Networks).map(n => n.IPAddress).filter(Boolean);
  assert(addresses.length);
}
const count = Number(process.env.EVIDENCE_METADATA_ROWS || 2000);
assert(Number.isSafeInteger(count) && count >= 2000 && count <= 1000000);
const resume = process.env.EVIDENCE_METADATA_RESUME === "1";
const client = new pg.Client({ connectionString, connectionTimeoutMillis: 5000, statement_timeout: 60000 });
await client.connect();
try {
  const identity = (await client.query("select current_database() as db,inet_server_addr()::text as address,current_setting('server_version') as version")).rows[0];
  assert.equal(identity.db, target.pathname.slice(1)); assert(addresses.includes(identity.address.split("/")[0]));
  const existing = (await client.query("select to_regnamespace('evidence_capacity_fixture') as existing")).rows[0].existing;
  assert.equal(Boolean(existing), resume, "Fresh or resume mode must match the fixture schema");
  assert.equal((await client.query("select atttypid::regtype::text as type from pg_attribute where attrelid='public.evidence_object_manifests'::regclass and attname='finding_pointer'")).rows[0].type, "bytea");
  if (!resume) await client.query(`create schema evidence_capacity_fixture;
    create table evidence_capacity_fixture.findings(id text primary key);
    create table evidence_capacity_fixture.legacy(
      finding_id text primary key references evidence_capacity_fixture.findings(id),
      revision bigint not null check(revision between 1 and 9007199254740991),
      finding_pointer jsonb not null check(public.evidence_pointer_valid(finding_pointer)),
      sources_pointer jsonb check(sources_pointer is null or public.evidence_pointer_valid(sources_pointer)));
    create table evidence_capacity_fixture.compact(like public.evidence_object_manifests including all);
    alter table evidence_capacity_fixture.compact add foreign key(finding_id) references evidence_capacity_fixture.findings(id);
  `);
  const done = (await client.query(`select
    (select count(*)::integer from evidence_capacity_fixture.findings) as parents,
    (select count(*)::integer from evidence_capacity_fixture.legacy) as legacy,
    (select count(*)::integer from evidence_capacity_fixture.compact) as compact`)).rows[0];
  assert(done.compact <= done.legacy && done.legacy <= done.parents && done.parents <= count);
  for (const n of Object.values(done)) assert(n === count || n % 10000 === 0);
  console.log("EVIDENCE_METADATA_PROGRESS " + JSON.stringify({ target: count, resume, ...done }));
  for (let start = Math.min(...Object.values(done)) + 1; start <= count; start += 10000) {
    const end = Math.min(start + 9999, count);
    if (start > done.parents) await client.query("insert into evidence_capacity_fixture.findings select md5(g::text) from generate_series($1::integer,$2::integer) g", [start, end]);
    if (start > done.legacy) await client.query(`insert into evidence_capacity_fixture.legacy
      select md5(g::text),1,
        jsonb_build_object('object',md5(g::text)||md5(g::text||':finding'),'offset',(g%4096)*512,'length',256+g%768),
        jsonb_build_object('object',md5(g::text)||md5(g::text||':sources'),'offset',(g%2048)*1024,'length',512+g%1024)
      from generate_series($1::integer,$2::integer) g`, [start, end]);
    if (start > done.compact) await client.query(`insert into evidence_capacity_fixture.compact
      select finding_id,revision,public.pack_evidence_pointer(finding_pointer),public.pack_evidence_pointer(sources_pointer)
      from evidence_capacity_fixture.legacy where finding_id in
        (select md5(g::text) from generate_series($1::integer,$2::integer) g)`, [start, end]);
  }
  await client.query("vacuum (analyze) evidence_capacity_fixture.legacy");
  await client.query("vacuum (analyze) evidence_capacity_fixture.compact");
  const equality = (await client.query(`select count(*)::integer as compared,
    count(*) filter(where l.revision is distinct from c.revision
      or l.finding_pointer is distinct from public.unpack_evidence_pointer(c.finding_pointer)
      or l.sources_pointer is distinct from public.unpack_evidence_pointer(c.sources_pointer))::integer as mismatches
    from evidence_capacity_fixture.legacy l full join evidence_capacity_fixture.compact c using(finding_id)`)).rows[0];
  assert.equal(equality.compared, count); assert.equal(equality.mismatches, 0);
  const sizes = (await client.query(`select c.relname,
    pg_table_size(c.oid)::bigint::text as table_bytes,
    pg_indexes_size(c.oid)::bigint::text as index_bytes,
    pg_total_relation_size(c.oid)::bigint::text as total_bytes
    from pg_class c where c.oid in ('evidence_capacity_fixture.legacy'::regclass,'evidence_capacity_fixture.compact'::regclass)
    order by c.relname`)).rows.map(row => ({ ...row, table_bytes: Number(row.table_bytes), index_bytes: Number(row.index_bytes), total_bytes: Number(row.total_bytes) }));
  const compact = sizes.find(r => r.relname === "compact"), legacy = sizes.find(r => r.relname === "legacy");
  assert(compact.total_bytes < legacy.total_bytes);
  const result = { rows: count, compared: equality.compared, mismatches: 0, resumed: resume, identity, sizes,
    saved_bytes: legacy.total_bytes - compact.total_bytes,
    saved_percent: 100 * (legacy.total_bytes - compact.total_bytes) / legacy.total_bytes,
    assumptions: "Synthetic 32-byte finding IDs, both pointers present, full 32-byte hashes, varied valid frame offsets/lengths, one revision. Physical table and primary-key bytes included. Parent findings, evidence objects, object metadata, query indexes, bloat, versions, orphans and migration peak are excluded; this is not whole-project capacity proof." };
  console.log("EVIDENCE_METADATA_MEASUREMENT " + JSON.stringify(result));
} finally { await client.end(); }
