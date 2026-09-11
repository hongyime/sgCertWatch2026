"""Verify source-index removal using synthetic rows in a disposable local database."""
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
import argparse
import json
import os
import shutil
import statistics
import subprocess
import time
import uuid

parser = argparse.ArgumentParser()
parser.add_argument('--docker-container')
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
database = 'source_index_test_' + uuid.uuid4().hex
checks = []

if args.docker_container:
    docker = shutil.which('docker') or 'C:/Program Files/Docker/Docker/resources/bin/docker.exe'
    info = json.loads(subprocess.check_output([docker, 'inspect', args.docker_container], text=True, timeout=30))[0]
    assert info['Config']['Labels'].get('prawn.maintenance') == 'true'
    assert info['HostConfig']['NetworkMode'] == 'none'
    assert '/var/lib/postgresql/data' in info['HostConfig']['Tmpfs']
    assert info['State']['Running']

    def command(name):
        return [docker, 'exec', '-i', args.docker_container, 'psql', '-X', '-qAt',
                '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', name]
else:
    endpoint = urlsplit(os.environ.get('INDEX_TEST_DATABASE_URL', ''))
    assert endpoint.scheme in ('postgres', 'postgresql')
    assert endpoint.hostname in ('localhost', '127.0.0.1', '::1')
    assert endpoint.path == '/notification_outbox_test', 'Use only the disposable CI service'

    def command(name):
        return ['psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '--dbname',
                urlunsplit(endpoint._replace(path='/' + name))]


def execute(sql, *, name=database, expected_error=None):
    result = subprocess.run(command(name), input=sql, capture_output=True, text=True, timeout=35)
    if expected_error:
        assert result.returncode != 0 and expected_error in result.stderr, 'Expected guarded failure'
    else:
        assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def check(label, predicate):
    assert execute('SELECT (' + predicate + ')::text;') == 'true', label
    checks.append(label)


def indexes(plan):
    found = [plan['Index Name']] if 'Index Name' in plan else []
    for child in plan.get('Plans', []):
        found.extend(indexes(child))
    return found


execute('CREATE DATABASE ' + database, name='postgres' if args.docker_container else 'notification_outbox_test')
execute("""DO $$ BEGIN
 IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='anon') THEN CREATE ROLE anon; END IF;
 IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='authenticated') THEN CREATE ROLE authenticated; END IF;
 IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='service_role') THEN CREATE ROLE service_role BYPASSRLS; END IF;
END $$;""")
execute((root / 'supabase/schema.sql').read_text(encoding='utf-8'))
migration = (root / 'supabase/source-index-cleanup.sql').read_text(encoding='utf-8')
rollback = (root / 'supabase/source-index-cleanup-rollback.sql').read_text(encoding='utf-8')
check('fresh schema omits overlapping index', "to_regclass('public.finding_sources_finding_id_idx') IS NULL")
execute(rollback)
execute("""
INSERT INTO public.findings(id,observed_at,registrable,score,severity)
 SELECT md5(n::text),'2026-09-11'::timestamptz+n*interval '1 second',
  'fixture-'||n||'.invalid',n%100,'medium' FROM generate_series(1,5000) n;
INSERT INTO public.finding_sources(finding_id,source,source_ref,observed_at,details)
 SELECT id,'fixture-'||s,md5(id||s)||md5(s||id),observed_at+s*interval '1 second',
  jsonb_build_object('null',NULL,'nested',jsonb_build_array('é',true,123456789012345678901234567890),
    'evidence',repeat(md5(id||s),12))
 FROM public.findings CROSS JOIN generate_series(1,3) s;
ANALYZE public.findings; ANALYZE public.finding_sources;
CREATE UNLOGGED TABLE expected_sources AS TABLE public.finding_sources;
CREATE UNLOGGED TABLE expected_findings AS TABLE public.findings;
CREATE UNLOGGED TABLE expected_objects AS
 SELECT oid,relname,relfilenode,relrowsecurity,relacl::text FROM pg_class
 WHERE oid IN ('public.findings'::regclass,'public.finding_sources'::regclass);
CREATE UNLOGGED TABLE expected_constraints AS SELECT conname,pg_get_constraintdef(oid) AS definition
 FROM pg_constraint WHERE conrelid IN ('public.findings'::regclass,'public.finding_sources'::regclass);
CREATE UNLOGGED TABLE expected_indexes AS SELECT indexname,indexdef FROM pg_indexes
 WHERE schemaname='public' AND tablename IN ('findings','finding_sources')
 AND indexname<>'finding_sources_finding_id_idx';
CREATE UNLOGGED TABLE expected_policies AS SELECT * FROM pg_policies
 WHERE schemaname='public' AND tablename IN ('findings','finding_sources');
""")
queries = {
    'source_detail': "SELECT * FROM public.finding_sources WHERE finding_id=md5('25') ORDER BY observed_at DESC LIMIT 100",
    'source_batch': "SELECT s.* FROM generate_series(1,200) n CROSS JOIN LATERAL (SELECT * FROM public.finding_sources WHERE finding_id=md5(n::text) ORDER BY observed_at DESC LIMIT 100) s",
    'source_filter': "SELECT * FROM public.finding_sources WHERE source='fixture-1' ORDER BY observed_at DESC LIMIT 100",
    'source_latest': "SELECT * FROM public.finding_sources ORDER BY observed_at DESC LIMIT 100",
}


def measure():
    results = {}
    for label, query in queries.items():
        runs = [json.loads(execute('EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ' + query))[0] for _ in range(3)]
        results[label] = {'indexes': indexes(runs[-1]['Plan']),
                          'median_execution_ms': statistics.median(r['Execution Time'] for r in runs),
                          'shared_blocks': runs[-1]['Plan'].get('Shared Hit Blocks', 0) + runs[-1]['Plan'].get('Shared Read Blocks', 0)}
    return results


before = measure()
removed_bytes = int(execute("SELECT pg_relation_size('public.finding_sources_finding_id_idx')"))
execute(migration)
check('overlapping index removed', "to_regclass('public.finding_sources_finding_id_idx') IS NULL")
for table, expected in [('findings', 'expected_findings'), ('finding_sources', 'expected_sources')]:
    check('all ' + table + ' fields preserved', f'NOT EXISTS ((TABLE public.{table} EXCEPT ALL TABLE {expected}) UNION ALL (TABLE {expected} EXCEPT ALL TABLE public.{table}))')
for label, expected, query in [
    ('table files, grants and RLS flags unchanged', 'expected_objects', "SELECT oid,relname,relfilenode,relrowsecurity,relacl::text FROM pg_class WHERE oid IN ('public.findings'::regclass,'public.finding_sources'::regclass)"),
    ('constraints unchanged', 'expected_constraints', "SELECT conname,pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid IN ('public.findings'::regclass,'public.finding_sources'::regclass)"),
    ('other indexes unchanged', 'expected_indexes', "SELECT indexname,indexdef FROM pg_indexes WHERE schemaname='public' AND tablename IN ('findings','finding_sources')"),
    ('RLS policies unchanged', 'expected_policies', "SELECT * FROM pg_policies WHERE schemaname='public' AND tablename IN ('findings','finding_sources')"),
]:
    check(label, f'NOT EXISTS ((TABLE {expected} EXCEPT {query}) UNION ALL ({query} EXCEPT TABLE {expected}))')
after = measure()
for label in ['source_detail', 'source_batch']:
    assert 'finding_sources_pkey' in after[label]['indexes'], label
    checks.append(label + ' uses retained primary key')
for role in ['anon', 'authenticated']:
    execute(f'SET ROLE {role}; SELECT * FROM public.finding_sources LIMIT 1', expected_error='permission denied')
    checks.append(role + ' remains unable to read private sightings')
execute("""SET ROLE service_role;
 INSERT INTO public.finding_sources(finding_id,source,source_ref,observed_at,details)
 SELECT finding_id,source,source_ref,observed_at,'{"updated":true}'::jsonb
 FROM public.finding_sources WHERE finding_id=md5('25') AND source='fixture-1'
 ON CONFLICT(finding_id,source,source_ref) DO UPDATE SET details=excluded.details;""")
check('service upsert keeps unique identity', "(SELECT count(*)=1 AND bool_and(details='{" + '"updated":true' + "}'::jsonb) FROM public.finding_sources WHERE finding_id=md5('25') AND source='fixture-1')")
execute("INSERT INTO public.finding_sources VALUES('missing','fixture','missing',now(),'{}',now())", expected_error='foreign key constraint')
checks.append('foreign key still rejects missing finding')
execute("BEGIN; DELETE FROM public.findings WHERE id=md5('25'); DO $$ BEGIN IF EXISTS (SELECT FROM public.finding_sources WHERE finding_id=md5('25')) THEN RAISE EXCEPTION 'Cascade failed'; END IF; END $$; ROLLBACK;")
checks.append('foreign key cascade works inside rolled-back synthetic transaction')
execute(migration)
checks.append('migration is idempotent')
execute(rollback)
check('concurrent rollback restores valid index', "EXISTS(SELECT FROM pg_index WHERE indexrelid=to_regclass('public.finding_sources_finding_id_idx') AND indisvalid AND indisready AND NOT indisunique)")
execute('DROP INDEX public.finding_sources_finding_id_idx; CREATE INDEX finding_sources_finding_id_idx ON public.finding_sources(source);')
execute(migration, expected_error='differs from the reviewed definition')
checks.append('changed lookup definition fails closed')
execute('DROP INDEX public.finding_sources_finding_id_idx;')
execute(rollback)
execute('ALTER TABLE public.finding_sources DROP CONSTRAINT finding_sources_pkey;')
execute(migration, expected_error='cannot replace this lookup index')
check('missing primary key leaves lookup intact', "to_regclass('public.finding_sources_finding_id_idx') IS NOT NULL")
execute('ALTER TABLE public.finding_sources ADD CONSTRAINT finding_sources_pkey PRIMARY KEY(source,finding_id,source_ref);')
execute(migration, expected_error='cannot replace this lookup index')
checks.append('primary key with wrong leading column fails closed')
execute('ALTER TABLE public.finding_sources DROP CONSTRAINT finding_sources_pkey; ALTER TABLE public.finding_sources ADD CONSTRAINT finding_sources_pkey PRIMARY KEY(finding_id,source,source_ref);')
holder = subprocess.Popen(command(database), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
try:
    holder.stdin.write('BEGIN; SELECT 1 FROM public.finding_sources LIMIT 1; SELECT pg_sleep(8); ROLLBACK;\n')
    holder.stdin.close()
    deadline = time.monotonic() + 5
    while execute("SELECT EXISTS(SELECT FROM pg_locks WHERE relation='public.finding_sources'::regclass AND mode='AccessShareLock' AND granted AND pid<>pg_backend_pid())::text") != 'true':
        assert time.monotonic() < deadline
        time.sleep(0.05)
    started = time.monotonic()
    execute(migration, expected_error='lock timeout')
    assert time.monotonic() - started < 5
    check('busy table aborts promptly and retains index', "to_regclass('public.finding_sources_finding_id_idx') IS NOT NULL")
finally:
    if holder.poll() is None:
        holder.wait(timeout=15)
execute(migration)
checks.append('migration succeeds after lock release')
print(json.dumps({'database': database, 'synthetic_findings': 5000, 'synthetic_sightings': 15000,
                  'checks': checks, 'passed': len(checks), 'production_connections': 0,
                  'removed_index_bytes': removed_bytes, 'before': before, 'after': after,
                  'limitations': 'Synthetic, warm-cache query measurements; not production latency or full-size cache pressure.'}))
