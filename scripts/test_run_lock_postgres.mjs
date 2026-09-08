import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import pg from "pg";

const url = new URL(process.env.OUTBOX_TEST_DATABASE_URL || "https://missing.invalid");
if (!["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) || url.pathname !== "/notification_outbox_test") {
  throw new Error("Lease SQL tests require the disposable localhost notification_outbox_test database");
}
const pool = new pg.Pool({ connectionString: url.href, max: 20 });
async function rpc(name, parameters, connection = null) {
  assert.ok(["acquire_run_lock", "renew_run_lock", "release_run_lock", "set_run_state"].includes(name));
  const client = connection || await pool.connect();
  try {
    await client.query("begin; set local role service_role; set local statement_timeout = '15s'");
    const result = await client.query(`select public.${name}(${parameters.map((_, i) => `$${i + 1}`).join(",")}) as result`, parameters);
    await client.query("commit");
    return result.rows[0].result;
  } catch (error) { await client.query("rollback"); throw error; }
  finally { if (!connection) client.release(); }
}

async function blockedLeaseCall(name, { expire = true } = {}) {
  const holder = await pool.connect();
  const waiter = await pool.connect();
  const owner = randomUUID();
  const caller = name === "acquire_run_lock" ? randomUUID() : owner;
  let holding = false;
  let pending;
  try {
    const initial = await pool.query(`update public.run_locks
      set owner_id=$1, locked_until=clock_timestamp()+make_interval(secs => $2)
      where name='ct_poll_run' returning locked_until`, [owner, expire ? 5 : 30]);
    assert.equal(initial.rowCount, 1);
    const originalDeadline = initial.rows[0].locked_until;
    await holder.query("begin");
    holding = true;
    // A row lock without an UPDATE exposes stale pre-lock predicates and timestamps.
    await holder.query("select name from public.run_locks where name='ct_poll_run' for update");
    const before = await waiter.query("select locked_until > clock_timestamp() as active from public.run_locks where name='ct_poll_run'");
    assert.equal(before.rows[0].active, true, "The RPC must enter while the lease is still valid");
    const parameters = name === "set_run_state"
      ? ["ct_poll_run", caller, "ct_source_state", { cursor: "expired-writer" }]
      : ["ct_poll_run", caller, 30];
    let settled = false;
    pending = rpc(name, parameters, waiter).finally(() => { settled = true; });
    void pending.catch(() => {});
    const deadline = Date.now() + 5000;
    for (;;) {
      const blockers = await pool.query(`select $1::integer = any(pg_blocking_pids(pid)) as blocked,
        query_start < $3::timestamptz as entered_before_expiry from pg_stat_activity where pid=$2`,
      [holder.processID, waiter.processID, originalDeadline]);
      if (blockers.rows[0]?.blocked) {
        assert.equal(blockers.rows[0].entered_before_expiry, true, "The blocked RPC must have started before expiry");
        break;
      }
      assert.equal(settled, false, `${name} completed without waiting for the holder`);
      assert.ok(Date.now() < deadline, `${name} never reached the row lock`);
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    if (expire) {
      await pool.query(`select pg_sleep((greatest(0,
        extract(epoch from ($1::timestamptz-clock_timestamp())))+0.1)::double precision)`, [originalDeadline]);
      const expired = await pool.query("select $1::timestamptz <= clock_timestamp() as expired", [originalDeadline]);
      assert.equal(expired.rows[0].expired, true);
    } else {
      await pool.query("select pg_sleep(0.25)");
    }
    assert.equal(settled, false, `${name} must remain blocked until COMMIT`);
    const releaseTime = await holder.query("select clock_timestamp() as releasing_at");
    await holder.query("commit");
    holding = false;
    const accepted = await pending;
    const after = await pool.query(`select owner_id, locked_until,
      locked_until >= $1::timestamptz + interval '30 seconds' as fresh,
      locked_until > clock_timestamp() as active from public.run_locks where name='ct_poll_run'`,
    [releaseTime.rows[0].releasing_at]);
    return { accepted, owner, caller, originalDeadline, lease: after.rows[0] };
  } finally {
    if (holding) await holder.query("rollback");
    if (pending) await pending.catch(() => {});
    holder.release();
    waiter.release();
  }
}

try {
  await pool.query(await readFile(new URL("../supabase/run-locks.sql", import.meta.url), "utf8"));
  await pool.query("grant select, insert, update on public.ingest_state to service_role");
  await pool.query(`begin; ${await readFile(new URL("./test_run_lock.sql", import.meta.url), "utf8")} rollback;`);
  const owners = Array.from({ length: 20 }, () => randomUUID());
  const results = await Promise.all(owners.map(owner => rpc("acquire_run_lock", ["ct_poll_run", owner, 900])));
  assert.equal(results.filter(Boolean).length, 1);
  const oldOwner = owners[results.indexOf(true)];
  assert.equal(await rpc("set_run_state", ["ct_poll_run", oldOwner, "ct_source_state", { cursor: 1 }]), true);
  await pool.query("update public.run_locks set locked_until=clock_timestamp()-interval '1 second' where name='ct_poll_run'");
  const newOwner = randomUUID();
  assert.equal(await rpc("acquire_run_lock", ["ct_poll_run", newOwner, 900]), true);
  assert.equal(await rpc("set_run_state", ["ct_poll_run", newOwner, "ct_source_state", { cursor: 2 }]), true);
  assert.equal(await rpc("set_run_state", ["ct_poll_run", oldOwner, "ct_source_state", { cursor: 1 }]), false);
  assert.equal(await rpc("release_run_lock", ["ct_poll_run", oldOwner]), false);
  const stored = await pool.query("select value from public.ingest_state where key='ct_source_state'");
  assert.equal(stored.rows[0].value.cursor, 2);
  console.log("PostgreSQL lease tests passed: 20 contenders, owner fencing, successor cursor preservation and private permissions");

  const checkpoint = await blockedLeaseCall("set_run_state");
  assert.equal(checkpoint.accepted, false, "A checkpoint blocked past expiry must be rejected");
  assert.equal(checkpoint.lease.owner_id, checkpoint.owner);
  const preserved = await pool.query("select value from public.ingest_state where key='ct_source_state'");
  assert.deepEqual(preserved.rows[0].value, stored.rows[0].value, "Expired checkpoint cannot change committed state");
  console.log("Blocked checkpoint past expiry rejected; committed cursor retained");

  const expiredRenewal = await blockedLeaseCall("renew_run_lock");
  assert.equal(expiredRenewal.accepted, false, "A blocked renewal cannot revive an expired lease");
  assert.equal(expiredRenewal.lease.owner_id, expiredRenewal.owner);
  assert.equal(expiredRenewal.lease.active, false);
  assert.deepEqual(expiredRenewal.lease.locked_until, expiredRenewal.originalDeadline);
  console.log("Blocked renewal past expiry rejected without changing the expired lease");

  const acquisition = await blockedLeaseCall("acquire_run_lock");
  assert.equal(acquisition.accepted, true, "A new owner may acquire after the prior lease expires");
  assert.equal(acquisition.lease.owner_id, acquisition.caller);
  assert.equal(acquisition.lease.fresh, true, "Acquisition must grant a full lease starting after the lock wait");
  assert.equal(acquisition.lease.active, true);
  console.log("Blocked acquisition grants the new owner a fresh full lease after the wait");

  const liveRenewal = await blockedLeaseCall("renew_run_lock", { expire: false });
  assert.equal(liveRenewal.accepted, true);
  assert.equal(liveRenewal.lease.owner_id, liveRenewal.owner);
  assert.equal(liveRenewal.lease.fresh, true, "Successful renewal must compute its deadline after the lock wait");
  assert.equal(liveRenewal.lease.active, true);
  assert.equal(await rpc("release_run_lock", ["ct_poll_run", liveRenewal.owner]), true);
  console.log("Blocked live renewal grants a fresh full lease after the wait");
} finally { await pool.end(); }
