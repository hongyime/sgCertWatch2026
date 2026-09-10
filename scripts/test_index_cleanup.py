"""Exercise the real migration in a disposable PostgreSQL database, with synthetic rows."""
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
import argparse
import json
import os
import shutil
import subprocess
import time
import uuid

parser = argparse.ArgumentParser()
parser.add_argument('--docker-container')
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
database = 'cert_index_test_' + uuid.uuid4().hex
checks = []

if args.docker_container:
    docker = shutil.which('docker') or 'C:/Program Files/Docker/Docker/resources/bin/docker.exe'
    inspected = subprocess.run([docker, 'inspect', args.docker_container],
                               capture_output=True, text=True, timeout=30, check=True)
    info = json.loads(inspected.stdout)[0]
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
    assert endpoint.path == '/notification_outbox_test', 'Use the disposable CI database service'

    def command(name):
        address = urlunsplit(endpoint._replace(path='/' + name))
        return ['psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '--dbname', address]


def execute(sql, *, name=database, expected_error=None):
    result = subprocess.run(command(name), input=sql, capture_output=True, text=True, timeout=30)
    if expected_error:
        assert result.returncode != 0 and expected_error in result.stderr, 'Expected guarded SQL failure'
        return result.stdout.strip()
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def check(label, predicate):
    assert execute('SELECT (' + predicate + ')::text;') == 'true', label
    checks.append(label)


execute('CREATE DATABASE ' + database, name='postgres' if args.docker_container else 'notification_outbox_test')
execute("""DO $$ BEGIN
 IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='anon') THEN CREATE ROLE anon; END IF;
 IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='authenticated') THEN CREATE ROLE authenticated; END IF;
 IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='service_role') THEN CREATE ROLE service_role BYPASSRLS; END IF;
END $$;""")
execute((root / 'supabase/schema.sql').read_text(encoding='utf-8'))
migration = (root / 'supabase/index-cleanup.sql').read_text(encoding='utf-8')
rollback = (root / 'supabase/index-cleanup-rollback.sql').read_text(encoding='utf-8')
check('fresh schema omits unused index', "to_regclass('public.findings_cert_identity_idx') IS NULL")
execute(rollback)
execute("""
INSERT INTO public.findings
 (id, observed_at, registrable, domains, score, severity, cert_serial, cert_issuer_dn_sha256, suppressed, source)
 SELECT md5(n::text), '2026-09-10'::timestamptz + n * interval '1 second',
  'example-'||n||'.invalid', ARRAY['example-'||n||'.invalid'], n%100, 'medium',
  CASE WHEN n%7=0 THEN NULL ELSE md5(('serial-'||n)::text) END,
  md5(('issuer-'||n%20)::text), n%11=0, jsonb_build_object('fixture',true,'ordinal',n)
 FROM generate_series(1,2500) n;
INSERT INTO public.finding_sources (finding_id,source,source_ref,observed_at,details)
 SELECT id,'fixture', 'sighting-'||n, observed_at,
  jsonb_build_object('ordinal',n,'null_value',NULL,'nested',jsonb_build_array('a','b'))
 FROM public.findings CROSS JOIN generate_series(1,2) n;
ANALYZE public.findings;
ANALYZE public.finding_sources;
CREATE TABLE expected_findings AS TABLE public.findings;
CREATE TABLE expected_sources AS TABLE public.finding_sources;
CREATE TABLE expected_objects AS
 SELECT oid, relname, relfilenode, relrowsecurity FROM pg_class
 WHERE oid IN ('public.findings'::regclass,'public.finding_sources'::regclass);
CREATE TABLE expected_indexes AS SELECT indexname,indexdef FROM pg_indexes
 WHERE schemaname='public' AND tablename IN ('findings','finding_sources')
  AND indexname<>'findings_cert_identity_idx';
CREATE TABLE expected_policies AS SELECT * FROM pg_policies
 WHERE schemaname='public' AND tablename IN ('findings','finding_sources');
""")
queries = {
 'latest': 'SELECT * FROM public.findings WHERE suppressed=false ORDER BY observed_at DESC LIMIT 50',
 'watch': 'SELECT * FROM public.findings WHERE suppressed=false AND score>=60 ORDER BY score DESC,observed_at DESC,id LIMIT 100',
 'detail': "SELECT * FROM public.findings WHERE id=md5('25')",
 'sources': "SELECT * FROM public.finding_sources WHERE finding_id=md5('25') ORDER BY observed_at DESC LIMIT 100",
 'candidates': 'SELECT * FROM public.intel_candidate_findings(500)',
 'hosts': "SELECT * FROM public.intel_findings_for_hosts(ARRAY['example-25.invalid'],100)",
}
before = {label: json.loads(execute('EXPLAIN (FORMAT JSON) '+query)) for label, query in queries.items()}
execute(migration)
check('reviewed index removed', "to_regclass('public.findings_cert_identity_idx') IS NULL")
for label, table in [('every finding field preserved', 'findings'), ('every sighting field preserved', 'finding_sources')]:
    expected = 'expected_findings' if table == 'findings' else 'expected_sources'
    check(label, f"NOT EXISTS ((TABLE public.{table} EXCEPT ALL TABLE {expected}) UNION ALL (TABLE {expected} EXCEPT ALL TABLE public.{table}))")
check('tables and RLS flags unchanged', "NOT EXISTS (SELECT 1 FROM expected_objects e FULL JOIN pg_class c ON c.oid=e.oid WHERE e.oid IS NOT NULL AND (c.oid IS NULL OR (e.relname,e.relfilenode,e.relrowsecurity) IS DISTINCT FROM (c.relname,c.relfilenode,c.relrowsecurity)))")
check('all other indexes unchanged', "NOT EXISTS ((TABLE expected_indexes EXCEPT SELECT indexname,indexdef FROM pg_indexes WHERE schemaname='public' AND tablename IN ('findings','finding_sources')) UNION ALL (SELECT indexname,indexdef FROM pg_indexes WHERE schemaname='public' AND tablename IN ('findings','finding_sources') EXCEPT TABLE expected_indexes))")
check('RLS policies unchanged', "NOT EXISTS ((TABLE expected_policies EXCEPT SELECT * FROM pg_policies WHERE schemaname='public' AND tablename IN ('findings','finding_sources')) UNION ALL (SELECT * FROM pg_policies WHERE schemaname='public' AND tablename IN ('findings','finding_sources') EXCEPT TABLE expected_policies))")
after = {label: json.loads(execute('EXPLAIN (FORMAT JSON) '+query)) for label, query in queries.items()}
assert before == after, 'Existing query plans changed'
checks.append('six existing query plans unchanged')
execute(migration)
checks.append('migration is idempotent')
execute("""INSERT INTO public.findings(id,observed_at,registrable,score,severity)
 VALUES(md5('25'),now(),'example-25.invalid',80,'high')
 ON CONFLICT(id) DO UPDATE SET score=excluded.score;
 DO $$ BEGIN
  BEGIN
   INSERT INTO public.finding_sources(finding_id,source,source_ref,observed_at)
   VALUES ('missing-fixture','fixture','missing',now());
   RAISE EXCEPTION 'Foreign key was not enforced';
  EXCEPTION WHEN foreign_key_violation THEN NULL;
  END;
 END $$;""")
check('primary-key upsert and foreign key remain active', "(SELECT count(*)=1 AND min(score)=80 FROM public.findings WHERE id=md5('25'))")
execute(rollback)
check('concurrent rollback recreates valid original index', "EXISTS (SELECT 1 FROM pg_index WHERE indexrelid=to_regclass('public.findings_cert_identity_idx') AND indisvalid AND NOT indisunique)")
execute('DROP INDEX public.findings_cert_identity_idx; CREATE INDEX findings_cert_identity_idx ON public.findings (cert_serial);')
execute(migration, expected_error='differs from the reviewed definition')
check('changed index definition fails closed', "pg_get_indexdef('public.findings_cert_identity_idx'::regclass) LIKE '%(cert_serial)'")
execute('DROP INDEX public.findings_cert_identity_idx;')
execute(rollback)
holder = subprocess.Popen(command(database), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
try:
    holder.stdin.write("BEGIN; SELECT 1 FROM public.findings LIMIT 1; SELECT pg_sleep(12); ROLLBACK;\n")
    holder.stdin.close()
    deadline = time.monotonic() + 8
    while execute("SELECT EXISTS (SELECT 1 FROM pg_locks WHERE relation='public.findings'::regclass AND mode='AccessShareLock' AND granted AND pid<>pg_backend_pid())::text") != 'true':
        assert time.monotonic() < deadline, 'Fixture lock not acquired'
        time.sleep(0.05)
    started = time.monotonic()
    execute(migration, expected_error='lock timeout')
    assert time.monotonic() - started < 8, 'Migration did not respect lock deadline'
    check('busy table leaves index intact', "to_regclass('public.findings_cert_identity_idx') IS NOT NULL")
finally:
    # A disconnected local psql session rolls back its own fixture transaction.
    if holder.poll() is None:
        holder.wait(timeout=20)
execute(migration)
checks.append('migration succeeds after fixture lock is released')
print(json.dumps({'database': database, 'synthetic_findings': 2500, 'synthetic_sightings': 5000,
                  'checks': checks, 'passed': len(checks), 'production_connections': 0}))
