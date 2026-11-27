// pgstore.go
// Listing 27.5 — Go: key directory storage with transactional one-time prekey
// consumption, queue admission and acknowledgement, and the epoch
// compare-and-swap — on Postgres through database/sql. The statements are
// embedded from sql/queries.sql, the same file the concurrency tests (Listing
// 27.6) run against PostgreSQL 16. Production registers the pgx driver; the
// driver is the only thing this file does not contain.
package main

import (
    "context"
    "database/sql"
    _ "embed"
    "errors"
    "regexp"
    "time"
)

//go:embed sql/queries.sql
var queriesSQL string

var queries = func() map[string]string {
    m := map[string]string{}
    re := regexp.MustCompile(`(?s)-- name: (\w+)\n(?:--[^\n]*\n)*(.*?;)`)
    for _, x := range re.FindAllStringSubmatch(queriesSQL, -1) {
        m[x[1]] = x[2]
    }
    return m
}()

type PGStore struct {
    DB                 *sql.DB
    MaxQueue, MaxBytes int
}

// ClaimBundle reads the identity key and newest signed prekeys, then claims one
// EC and one PQ one-time prekey, all in ONE transaction. If anything fails, the
// claimed rows come back.
func (p *PGStore) ClaimBundle(ctx context.Context, device string) (*Bundle,
    error) {
    tx, err := p.DB.BeginTx(ctx,
        &sql.TxOptions{Isolation: sql.LevelReadCommitted})
    if err != nil {
        return nil, err
    }
    defer tx.Rollback() // no-op after Commit
    b := &Bundle{}
    if err := tx.QueryRowContext(ctx,
        `SELECT identity_key FROM identity_keys WHERE device_id = $1`, device).
        Scan(&b.IdentityKey); err != nil {
        return nil, notFound(err)
    }
    if err := tx.QueryRowContext(ctx, queries["newest_signed"], device, "ec").
        Scan(&b.SignedPrekey.ID, &b.SignedPrekey.Pub,
            &b.SignedPrekey.Sig); err != nil {
        return nil, notFound(err)
    }
    var k PreKey
    switch err := tx.QueryRowContext(ctx, queries["claim_one_time"], device,
        "ec").Scan(&k.ID, &k.Pub, &k.Sig); {
    case err == nil:
        b.OneTime = &k
    case !errors.Is(err, sql.ErrNoRows):
        return nil, err
    // no rows: exhausted, the initiator runs 3-DH X3DH and the recipient's
    // replay cache applies
    }
    switch err := tx.QueryRowContext(ctx, queries["claim_one_time"], device,
        "pq").Scan(&b.PQ.ID, &b.PQ.Pub, &b.PQ.Sig); {
    case errors.Is(err, sql.ErrNoRows):
        b.PQLastResort = true
        if err := tx.QueryRowContext(ctx, queries["newest_signed"], device,
            "pq").
            Scan(&b.PQ.ID, &b.PQ.Pub, &b.PQ.Sig); err != nil {
            return nil, notFound(err)
        }
    case err != nil:
        return nil, err
    }
    return b, tx.Commit()
}

func (p *PGStore) Enqueue(ctx context.Context, device string, guid, body []byte,
    ttl time.Duration) error {
    it := Item{Device: device, GUID: guid, Body: body}
    return p.EnqueueBatch(ctx, []Item{it}, ttl)
}

// EnqueueBatch: one transaction for the whole send. If any device's quota is
// full, the rollback undoes the reservations and inserts already made for the
// other devices.
func (p *PGStore) EnqueueBatch(ctx context.Context, items []Item,
    ttl time.Duration) error {
    tx, err := p.DB.BeginTx(ctx, nil)
    if err != nil {
        return err
    }
    defer tx.Rollback()
    for _, it := range items {
        var n int
        if err := tx.QueryRowContext(ctx, queries["reserve_quota"], it.Device,
            len(it.Body), p.MaxQueue, p.MaxBytes).
            Scan(&n); errors.Is(err, sql.ErrNoRows) {
            // retryable for the sender; the recipient has been offline too long
            return ErrQueueFull
        } else if err != nil {
            return err
        }
        if _, err := tx.ExecContext(ctx, queries["enqueue"], it.GUID, it.Device,
            it.Body, int(ttl.Hours()/24)); err != nil {
            return err
        }
    }
    return tx.Commit()
}

func (p *PGStore) Fetch(ctx context.Context, device string,
    limit int) ([]Stored, error) {
    rows, err := p.DB.QueryContext(ctx, queries["fetch"], device, limit)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    var out []Stored
    for rows.Next() {
        var s Stored
        if err := rows.Scan(&s.GUID, &s.Body); err != nil {
            return nil, err
        }
        out = append(out, s)
    }
    return out, rows.Err()
}

// Ack: device_id is in the WHERE clause, so a device can only delete its own
// envelopes no matter which GUIDs it sends. pgx encodes [][]byte as bytea[] for
// ANY($2).
func (p *PGStore) Ack(ctx context.Context, device string, guids [][]byte) (int,
    error) {
    var n int
    err := p.DB.QueryRowContext(ctx, queries["ack"], device, guids).Scan(&n)
    if errors.Is(err, sql.ErrNoRows) {
        return 0, nil
    }
    return n, err
}

func (p *PGStore) AdvanceEpoch(ctx context.Context, group []byte, epoch uint64,
    commit []byte) error {
    tx, err := p.DB.BeginTx(ctx, nil)
    if err != nil {
        return err
    }
    defer tx.Rollback()
    if _, err := tx.ExecContext(ctx,
        `INSERT INTO mls_groups (group_id) VALUES ($1) ON CONFLICT DO NOTHING`,
        group); err != nil {
        return err
    }
    var next uint64
    if err := tx.QueryRowContext(ctx, queries["advance_epoch"], group,
        epoch).Scan(&next); errors.Is(err, sql.ErrNoRows) {
        return ErrStaleEpoch
    } else if err != nil {
        return err
    }
    if _, err := tx.ExecContext(ctx, queries["log_commit"], group, epoch,
        commit); err != nil {
        return err
    }
    // the fan-out enqueue (Listing 27.7) joins this transaction in production
    return tx.Commit()
}

func (p *PGStore) Epoch(ctx context.Context, group []byte) (uint64, error) {
    var e uint64
    err := p.DB.QueryRowContext(ctx,
        `SELECT epoch FROM mls_groups WHERE group_id = $1`, group).Scan(&e)
    if errors.Is(err, sql.ErrNoRows) {
        return 0, nil
    }
    return e, err
}

func notFound(err error) error {
    if errors.Is(err, sql.ErrNoRows) {
        return ErrNotFound
    }
    return err
}

var _ GroupStore = (*PGStore)(nil)
var _ QueueStore = (*PGStore)(nil)
