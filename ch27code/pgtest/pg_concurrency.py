# pg_concurrency.py
"""Listing 27.6 — Python: concurrency tests for the server's SQL against
PostgreSQL 16. Runs the exact statements from sql/queries.sql (the same file the
Go PGStore embeds) from many connections at once, and contrasts them with the
obvious-but-wrong versions."""
import os, re, sys, threading, collections, psycopg

DSN = os.environ.get("MURMUR_PG",
    "host=127.0.0.1 port=55432 user=murmur dbname=murmur")
Q = dict(re.findall(r"-- name: (\w+)\n(?:--[^\n]*\n)*(.*?;)",
    open(sys.argv[1]).read(), re.S))
# $n → %(pn)s: psycopg placeholders, same statements
def ex(conn, name, *args):
    return conn.execute(re.sub(r"\$(\d+)", r"%(p\1)s", Q[name]),
        {f"p{i+1}": a for i, a in enumerate(args)})

def run_parallel(n_threads, fn):
    out, lock = [], threading.Lock()
    barrier = threading.Barrier(n_threads)
    def worker(i):
        with psycopg.connect(DSN, autocommit=True) as c:
            barrier.wait()                       # start everyone at once
            r = fn(c, i)
            with lock: out.append(r)
    ts = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
    [t.start() for t in ts]; [t.join() for t in ts]
    return out

def reset(c):
    c.execute(
        "TRUNCATE one_time_prekeys, envelopes, queue_quota, mls_groups, "
        "mls_handshake_log")

with psycopg.connect(DSN, autocommit=True) as c:
    # ── 1. one-time prekeys: 40 keys, 60 concurrent bundle fetches ──
    def load():
        reset(c)
        with c.cursor() as cur:
            cur.executemany(
                "INSERT INTO one_time_prekeys VALUES ('dev-bob', 'ec', %s, "
                "%s, NULL)",
                [(i, os.urandom(32)) for i in range(1, 41)])
    load()
    def correct(conn, i):
        row = ex(conn, "claim_one_time", "dev-bob", "ec").fetchone()
        return row[0] if row else None
    got = run_parallel(60, correct)
    ids = [g for g in got if g is not None]
    dup = [k for k, v in collections.Counter(ids).items() if v > 1]
    print(
        f"  claim_one_time (DELETE … FOR UPDATE SKIP LOCKED): {len(ids)} "
        f"keys handed out, "
        f"{got.count(None)} fetches got none, duplicates: {len(dup)}, left "
        f"in table: "
        f"{c.execute('select count(*) from one_time_prekeys').fetchone()[0]}")

    load()
    # ⚠️ INSECURE: read, then delete, unchecked
    def naive(conn, i):
        row = conn.execute(
            "SELECT key_id FROM one_time_prekeys WHERE device_id='dev-bob' "
            "AND kind='ec' "
            "ORDER BY key_id LIMIT 1").fetchone()
        # any real work between the two statements
        conn.execute("SELECT pg_sleep(0.002)")
        if row:
            conn.execute(
                "DELETE FROM one_time_prekeys WHERE device_id='dev-bob' AND "
                "key_id=%s", row)
        return row[0] if row else None
    got = run_parallel(60, naive)
    ids = [g for g in got if g is not None]
    dup = {k: v for k, v in collections.Counter(ids).items() if v > 1}
    print(
        f"  naive SELECT-then-DELETE:                         {len(ids)} "
        f"fetches got a key, but only "
        f"{len(set(ids))} distinct key(s) were handed out: "
        f"{sum(dup.values())} fetches shared a key")

    # ── 2. relay admission control: cap 50 envelopes, 80 concurrent senders ──
    reset(c)
    def send(conn, i):
        with conn.transaction():
            ok = ex(conn, "reserve_quota", "dev-bob", 1000, 50,
                10 << 20).fetchone()
            if not ok: return "full"
            ex(conn, "enqueue", os.urandom(16), "dev-bob", os.urandom(1000), 30)
            return "queued"
    res = collections.Counter(run_parallel(80, send))
    n, b = c.execute(
        "select n, bytes from queue_quota where device_id='dev-bob'").fetchone()
    stored = c.execute("select count(*) from envelopes").fetchone()[0]
    print(
        f"  reserve_quota + enqueue, cap 50: queued={res['queued']} "
        f"rejected={res['full']} "
        f"stored={stored} quota row=({n}, {b} B)")

    # ── 3. ack deletes only the caller's envelopes and releases quota exactly
    # once ──
    guids = [r[0] for r in ex(c, "fetch", "dev-bob", 10).fetchall()]
    other = ex(c, "ack", "dev-mallory", guids).fetchone()
    acks = run_parallel(5, lambda conn, i: ex(conn, "ack", "dev-bob",
        guids).fetchone()[0])
    n, b = c.execute(
        "select n, bytes from queue_quota where device_id='dev-bob'").fetchone()
    print(f"  ack by another device: {other[0] if other else 0} deleted; "
          f"5 concurrent identical acks by dev-bob: deleted {sorted(acks)} → "
          f"quota now ({n}, {b} B)")

    # ── 3b. a send to two devices, one of them full, is all-or-none
    # (PGStore.EnqueueBatch) ──
    before = c.execute("select count(*) from envelopes where "
        "device_id='dev-bob-tablet'").fetchone()[0]
    try:
        with c.transaction():
            # dev-bob holds 40: full at cap 40
            for dev, cap in (("dev-bob-tablet", 50), ("dev-bob", 40)):
                if not ex(c, "reserve_quota", dev, 1000, cap,
                    10 << 20).fetchone():
                    raise LookupError(dev)
                ex(c, "enqueue", os.urandom(16), dev, os.urandom(1000), 30)
    except LookupError as full:
        after = c.execute("select count(*) from envelopes where "
            "device_id='dev-bob-tablet'").fetchone()[0]
        q = c.execute("select count(*) from queue_quota where "
            "device_id='dev-bob-tablet'").fetchone()[0]
        print(
            f"  batch to tablet + full {full}: rolled back — tablet "
            f"envelopes {before} → {after}, tablet quota rows: {q}")

    # ── 4. MLS commit ordering: 25 members commit for epoch 7 at once ──
    reset(c)
    c.execute("INSERT INTO mls_groups VALUES ('\\x6772','7')")
    def commit(conn, i):
        with conn.transaction():
            row = ex(conn, "advance_epoch", b"gr", 7).fetchone()
            if not row: return None
            ex(conn, "log_commit", b"gr", 7, f"commit-from-{i}".encode())
            return i
    winners = [w for w in run_parallel(25, commit) if w is not None]
    ep = c.execute("select epoch from mls_groups").fetchone()[0]
    log = c.execute("select count(*) from mls_handshake_log").fetchone()[0]
    print(
        f"  advance_epoch CAS: {len(winners)} winner of 25, epoch now {ep}, "
        f"log entries for epoch 7: {log}")
