-- queries.sql — the correctness-critical statements, shared by the Go PGStore
-- (go:embed) and the Python concurrency tests. Each "-- name:" block is one
-- statement.

-- name: claim_one_time
-- Atomically take ONE one-time prekey of a kind and delete it. SKIP LOCKED
-- makes concurrent claimers take different rows instead of waiting for (or
-- worse, reading) the same one.
DELETE FROM one_time_prekeys
WHERE (device_id, kind, key_id) = (
    SELECT device_id, kind, key_id FROM one_time_prekeys
    WHERE device_id = $1 AND kind = $2
    ORDER BY key_id
    LIMIT 1
    FOR UPDATE SKIP LOCKED)
RETURNING key_id, public_key, signature;

-- name: newest_signed
SELECT key_id, public_key, signature FROM signed_prekeys
WHERE device_id = $1 AND kind = $2 ORDER BY created_at DESC,
    key_id DESC LIMIT 1;

-- name: reserve_quota
-- Admission control for a device's queue: count and bytes, checked and updated
-- in one step.
INSERT INTO queue_quota AS q (device_id, n, bytes) VALUES ($1, 1, $2)
ON CONFLICT (device_id) DO UPDATE SET n = q.n + 1, bytes = q.bytes + $2
WHERE q.n < $3 AND q.bytes + $2 <= $4
RETURNING n;

-- name: enqueue
INSERT INTO envelopes (guid, device_id, body, received_at, expires_at)
VALUES ($1, $2, $3, date_trunc('minute', now()),
    now() + make_interval(days => $4));

-- name: fetch
SELECT guid, body FROM envelopes
WHERE device_id = $1 AND expires_at > now() ORDER BY seq LIMIT $2;

-- name: ack
-- Delete ONLY the caller's own envelopes, and release their quota, in one
-- statement.
WITH gone AS (
    DELETE FROM envelopes WHERE device_id = $1 AND guid = ANY(
    $2) RETURNING octet_length(body) AS len)
UPDATE queue_quota SET n = n - (SELECT count(*) FROM gone),
                       bytes = bytes - (SELECT coalesce(sum(len), 0) FROM gone)
WHERE device_id = $1
RETURNING (SELECT count(*) FROM gone);

-- name: advance_epoch
-- Compare-and-swap on the epoch: exactly one commit per epoch can succeed.
UPDATE mls_groups SET epoch = epoch + 1 WHERE group_id = $1 AND epoch = $2
    RETURNING epoch;

-- name: log_commit
INSERT INTO mls_handshake_log (group_id, epoch, message) VALUES ($1, $2, $3);
