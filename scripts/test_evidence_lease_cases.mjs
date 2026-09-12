// Invoked only by the guarded, synthetic PostgreSQL contract fixture.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";

export async function verifyLeaseContracts({ t, pool, asRole, stores, seed, finding, source }) {
  const lost = error => error.code === "PT409";
  const pointer = { object: "a".repeat(64), offset: 0, length: 100 };
  const next = { suppressed: false, finding: pointer, sources: null };
  const publishSql = "select public.publish_evidence_manifest($1,$2,$3,$4,$5,$6,$7) as saved";
  const params = (id, revision, lease) => [id, revision, false, pointer, null, lease.name, lease.owner];
  async function acquire(name) {
    const lease = { name, owner: randomUUID() };
    assert.equal((await asRole("service_role", "select public.acquire_run_lock($1,$2,900) as owned", [name, lease.owner])).rows[0].owned, true);
    return lease;
  }
  const expire = lease => pool.query("update public.run_locks set locked_until=clock_timestamp()-interval '1 second' where name=$1", [lease.name]);
  async function blocked(pid) {
    const deadline = Date.now() + 1500;
    do {
      const { rows } = await pool.query("select wait_event_type from pg_stat_activity where pid=$1", [pid]);
      if (rows[0]?.wait_event_type === "Lock") return;
      await new Promise(resolve => setTimeout(resolve, 10));
    } while (Date.now() < deadline);
    assert.fail("Expected the publication/lease transfer to wait on a database row lock");
  }
  const waitExpiry = lease => pool.query("select pg_sleep(greatest(0,extract(epoch from locked_until-clock_timestamp()))::double precision+0.03) from public.run_locks where name=$1", [lease.name]);

  await t.test("missing, unknown, wrong and expired leases reject direct single and batch RPCs", async () => {
    const id = "lease-invalid"; await seed(id); const lease = await acquire(id);
    const invalid = [null, { name: "absent", owner: lease.owner }, { name: lease.name, owner: randomUUID() }];
    for (const value of invalid) {
      const store = stores(value ?? { name: null, owner: null });
      await assert.rejects(store.privateManifests.compareAndSwap(id, 0, next), lost);
      await assert.rejects(store.privateManifests.compareAndSwapMany([{ id, expectedRevision: 0, next }]), lost);
    }
    await expire(lease);
    await assert.rejects(stores(lease).privateManifests.compareAndSwap(id, 0, next), lost);
    assert.equal(await stores(lease).privateManifests.get(id), null);
  });

  await t.test("lease transfer during verified upload cannot replace either committed pointer", async () => {
    const id = "lease-upload"; await seed(id); const lease = await acquire(id); const store = stores(lease);
    const before = await store.repository.publish(id, { finding: finding(id), sources: [source(id, "kept")] }, 0);
    const put = store.objects.putIfAbsent; let successor;
    store.objects.putIfAbsent = async (...args) => {
      await put(...args);
      if (!successor) { await expire(lease); successor = await acquire(id); }
    };
    await assert.rejects(store.repository.publish(id, { finding: finding(id), sources: [source(id, "stale")] }, 1), lost);
    assert.deepEqual(await store.privateManifests.get(id), before);
    assert.equal(await stores(successor).privateManifests.compareAndSwap(id, 1, before), true);
    await assert.rejects(store.privateManifests.compareAndSwap(id, 2, before), lost);
    assert.equal((await store.privateManifests.get(id)).revision, 2);
  });

  await t.test("a no-op source retry rechecks ownership after reading the snapshot", async () => {
    const id = "lease-noop"; await seed(id); const lease = await acquire(id); const store = stores(lease);
    const original = source(id, "kept");
    const before = await store.repository.publish(id, { finding: finding(id), sources: [original] }, 0);
    const read = store.objects.read; let changed = false;
    store.objects.read = async key => {
      const value = await read(key);
      if (!changed) { changed = true; await expire(lease); await acquire(id); }
      return value;
    };
    store.events.length = 0;
    await assert.rejects(store.repository.upsertSources(id, [original]), lost);
    assert.equal(store.events.filter(event => event === "object_put").length, 0);
    assert.deepEqual(await store.privateManifests.get(id), before);
  });

  for (const lockTarget of ["finding", "manifest", "batch"]) {
    await t.test(`expiry while waiting on ${lockTarget} rolls back all publication changes`, async () => {
      const first = `lease-wait-${lockTarget}-a`, last = `lease-wait-${lockTarget}-z`;
      await seed(first); await seed(last); const lease = await acquire(first); const store = stores(lease);
      await store.privateManifests.compareAndSwap(first, 0, next);
      await store.privateManifests.compareAndSwap(last, 0, next);
      const before = await Promise.all([store.privateManifests.get(first), store.privateManifests.get(last)]);
      const blocker = await pool.connect(), writer = await pool.connect(); let pending;
      try {
        await blocker.query("begin");
        await blocker.query(lockTarget === "manifest"
          ? "select 1 from public.evidence_object_manifests where finding_id=$1 for update"
          : "select 1 from public.findings where id=$1 for update", [last]);
        await pool.query("update public.run_locks set locked_until=clock_timestamp()+interval '700 milliseconds' where name=$1", [lease.name]);
        await writer.query("begin"); await writer.query("set local role service_role");
        pending = (lockTarget === "batch"
          ? writer.query("select * from public.publish_evidence_manifests($1,$2,$3)", [JSON.stringify([first, last].map(id => ({
            id, expected_revision: 1, suppressed: false, finding_pointer: pointer, sources_pointer: pointer
          }))), lease.name, lease.owner])
          : writer.query(publishSql, params(last, 1, lease))).then(value => ({ value }), error => ({ error }));
        await blocked(writer.processID); await waitExpiry(lease); await blocker.query("commit");
        const result = await pending; assert.equal(result.error?.code, "PT409");
        await writer.query("rollback");
        assert.deepEqual(await Promise.all([store.privateManifests.get(first), store.privateManifests.get(last)]), before);
      } finally {
        await blocker.query("rollback"); await pending; await writer.query("rollback");
        blocker.release(); writer.release();
      }
    });
  }

  await t.test("takeover waits for publication commit and the old owner cannot write afterward", async () => {
    const id = "lease-commit"; await seed(id); const lease = await acquire(id);
    const publisher = await pool.connect(), successor = await pool.connect(); let pending;
    try {
      await pool.query("update public.run_locks set locked_until=clock_timestamp()+interval '700 milliseconds' where name=$1", [lease.name]);
      await publisher.query("begin"); await publisher.query("set local role service_role");
      assert.equal((await publisher.query(publishSql, params(id, 0, lease))).rows[0].saved, true);
      await waitExpiry(lease);
      await successor.query("begin"); await successor.query("set local role service_role");
      const owner = randomUUID();
      pending = successor.query("select public.acquire_run_lock($1,$2,900) as owned", [id, owner]).then(value => ({ value }), error => ({ error }));
      await blocked(successor.processID);
      assert.equal(await stores(lease).privateManifests.get(id), null, "Uncommitted publication must stay invisible");
      await publisher.query("commit");
      const result = await pending; assert.equal(result.value?.rows[0].owned, true); await successor.query("commit");
      assert.equal((await stores(lease).privateManifests.get(id)).revision, 1);
      await assert.rejects(stores(lease).privateManifests.compareAndSwap(id, 1, next), lost);
      assert.equal(await stores({ name: id, owner }).privateManifests.compareAndSwap(id, 1, next), true);
    } finally {
      await publisher.query("rollback"); await pending; await successor.query("rollback");
      publisher.release(); successor.release();
    }
  });

  await t.test("lease lock contention fails within the database lock timeout", async () => {
    const lease = await acquire("lease-timeout"); const blocker = await pool.connect();
    try {
      await blocker.query("begin"); await blocker.query("select 1 from public.run_locks where name=$1 for update", [lease.name]);
      const start = Date.now();
      await assert.rejects(stores(lease).privateManifests.assertLease(), error => error.code === "55P03");
      assert(Date.now() - start < 7000, "Database lock timeout must precede the eight-second request deadline");
    } finally { await blocker.query("rollback"); blocker.release(); }
  });

  await t.test("service workers have no direct manifest DML or unfenced RPC overload", async () => {
    for (const sql of ["insert into public.evidence_object_manifests values ('bypass',1,null,null)",
      "update public.evidence_object_manifests set revision=revision+1", "delete from public.evidence_object_manifests"])
      await assert.rejects(asRole("service_role", sql), error => error.code === "42501");
    const overloads = (await pool.query("select to_regprocedure('public.publish_evidence_manifest(text,bigint,boolean,jsonb,jsonb)') as single,to_regprocedure('public.publish_evidence_manifests(jsonb)') as batch")).rows[0];
    assert.deepEqual(overloads, { single: null, batch: null });
  });

  await t.test("temporary relations and caller search paths cannot replace the real lease", async () => {
    const id = "lease-shadow"; await seed(id); const owner = randomUUID(); const client = await pool.connect();
    try {
      await client.query("begin"); await client.query("set local role service_role");
      await client.query("create temporary table run_locks(name text,owner_id uuid,locked_until timestamptz)");
      await client.query("insert into run_locks values ($1,$2,clock_timestamp()+interval '1 day')", [id, owner]);
      await client.query("set local search_path=pg_temp,public");
      await assert.rejects(client.query(publishSql, params(id, 0, { name: id, owner })), lost);
      await client.query("rollback");
      assert.equal(await stores().privateManifests.get(id), null);
      const functions = (await pool.query("select proname,prosecdef,proconfig from pg_proc where oid in ('public.assert_evidence_lease(text,uuid)'::regprocedure,'public.publish_evidence_manifest(text,bigint,boolean,jsonb,jsonb,text,uuid)'::regprocedure,'public.publish_evidence_manifests(jsonb,text,uuid)'::regprocedure)")).rows;
      assert.equal(functions.length, 3);
      for (const fn of functions) { assert.equal(fn.prosecdef, true); assert(fn.proconfig.includes('search_path=""')); assert(fn.proconfig.includes('lock_timeout=2s')); }
    } finally { await client.query("rollback"); client.release(); }
  });
}
