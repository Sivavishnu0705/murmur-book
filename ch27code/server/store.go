// store.go — the storage interfaces the Chapter 27 handlers use, and MemStore, the in-memory
// store the lab runs on. Chapter 27 lists this file under "Described only": it gives the same
// guarantees as the SQL in sql/queries.sql (atomic one-time prekey claims, all-or-none queue
// admission with quotas, acknowledgement scoped to the device, one commit per epoch) by doing
// each operation under one mutex. PGStore (Listing 27.5) is the Postgres implementation.
package main

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

var (
	ErrNotFound   = errors.New("not found")
	ErrQueueFull  = errors.New("queue full")
	ErrStaleEpoch = errors.New("stale epoch")
)

// PreKey is one uploaded public key. EC one-time prekeys carry no signature; every other
// kind is signed by the device's identity key (XEdDSA over type byte ‖ public key, Ch 18).
type PreKey struct {
	ID  int64  `json:"id"`
	Pub []byte `json:"pub"`
	Sig []byte `json:"sig,omitempty"`
}

// Bundle is what GET /v1/keys/bundle/{device} returns (Ch 18 §18.7, PQXDH).
type Bundle struct {
	IdentityKey  []byte  `json:"identity_key"`
	SignedPrekey PreKey  `json:"signed_prekey"`
	OneTime      *PreKey `json:"one_time_prekey,omitempty"` // absent when exhausted
	PQ           PreKey  `json:"pq_prekey"`                 // a PQ one-time key, or the last resort
	PQLastResort bool    `json:"pq_last_resort"`
}

// Item is one envelope to enqueue; Stored is one queued envelope as a device fetches it.
type Item struct {
	Device     string
	GUID, Body []byte
}

type Stored struct {
	GUID []byte `json:"guid"`
	Body []byte `json:"body"`
}

// KeyStore holds identity keys and prekeys. kind is "ec" (X25519) or "pq" (ML-KEM-1024).
type KeyStore interface {
	PutIdentity(ctx context.Context, account, device string, ik []byte) error
	PutSigned(ctx context.Context, device, kind string, k PreKey) error
	AddOneTime(ctx context.Context, device, kind string, ks []PreKey) error
	CountOneTime(ctx context.Context, device, kind string) (int, error)
	ClaimBundle(ctx context.Context, device string) (*Bundle, error)
}

// QueueStore holds per-device envelope queues.
type QueueStore interface {
	Enqueue(ctx context.Context, device string, guid, body []byte, ttl time.Duration) error
	EnqueueBatch(ctx context.Context, items []Item, ttl time.Duration) error
	Fetch(ctx context.Context, device string, limit int) ([]Stored, error)
	Ack(ctx context.Context, device string, guids [][]byte) (int, error)
}

// GroupStore holds the MLS epoch of each group and the log of accepted commits.
type GroupStore interface {
	AdvanceEpoch(ctx context.Context, group []byte, epoch uint64, commit []byte) error
	Epoch(ctx context.Context, group []byte) (uint64, error)
}

type queued struct {
	Stored
	expires time.Time
}

type quota struct{ n, bytes int }

// MemStore implements KeyStore, QueueStore and GroupStore in memory.
type MemStore struct {
	MaxQueue, MaxBytes int
	Clock              func() time.Time

	mu        sync.Mutex
	identity  map[string][]byte              // device → identity key
	signed    map[string]map[string]PreKey   // device → kind → newest signed prekey
	oneTime   map[string]map[string][]PreKey // device → kind → keys, ordered by ID
	queues    map[string][]queued
	quotas    map[string]quota
	epochs    map[string]uint64
	commitLog [][]byte
}

func NewMemStore(maxQueue, maxBytes int, clock func() time.Time) *MemStore {
	return &MemStore{MaxQueue: maxQueue, MaxBytes: maxBytes, Clock: clock,
		identity: map[string][]byte{}, signed: map[string]map[string]PreKey{},
		oneTime: map[string]map[string][]PreKey{}, queues: map[string][]queued{},
		quotas: map[string]quota{}, epochs: map[string]uint64{}}
}

// ── KeyStore ──

func (m *MemStore) PutIdentity(_ context.Context, _, device string, ik []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.identity[device] = append([]byte(nil), ik...)
	return nil
}

func (m *MemStore) PutSigned(_ context.Context, device, kind string, k PreKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.signed[device] == nil {
		m.signed[device] = map[string]PreKey{}
	}
	m.signed[device][kind] = k
	return nil
}

// AddOneTime ignores IDs already stored, so a retried upload is idempotent.
func (m *MemStore) AddOneTime(_ context.Context, device, kind string, ks []PreKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.oneTime[device] == nil {
		m.oneTime[device] = map[string][]PreKey{}
	}
	have := map[int64]bool{}
	for _, k := range m.oneTime[device][kind] {
		have[k.ID] = true
	}
	for _, k := range ks {
		if !have[k.ID] {
			m.oneTime[device][kind] = append(m.oneTime[device][kind], k)
			have[k.ID] = true
		}
	}
	l := m.oneTime[device][kind]
	sort.Slice(l, func(i, j int) bool { return l[i].ID < l[j].ID })
	return nil
}

func (m *MemStore) CountOneTime(_ context.Context, device, kind string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.oneTime[device][kind]), nil
}

// ClaimBundle takes one EC and one PQ one-time prekey (lowest ID first) and deletes them in
// the same critical section that reads them, as claim_one_time does in one SQL statement.
func (m *MemStore) ClaimBundle(_ context.Context, device string) (*Bundle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ik, ok := m.identity[device]
	spk, ok2 := m.signed[device]["ec"]
	if !ok || !ok2 {
		return nil, ErrNotFound
	}
	b := &Bundle{IdentityKey: ik, SignedPrekey: spk}
	if l := m.oneTime[device]["ec"]; len(l) > 0 {
		k := l[0]
		b.OneTime, m.oneTime[device]["ec"] = &k, l[1:]
	}
	if l := m.oneTime[device]["pq"]; len(l) > 0 {
		b.PQ, m.oneTime[device]["pq"] = l[0], l[1:]
	} else if lr, ok := m.signed[device]["pq"]; ok {
		b.PQ, b.PQLastResort = lr, true
	} else {
		return nil, ErrNotFound
	}
	return b, nil
}

// ForgetDevice is part of the revocation cascade: keys and queue go with the device.
func (m *MemStore) ForgetDevice(device string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.identity, device)
	delete(m.signed, device)
	delete(m.oneTime, device)
	delete(m.queues, device)
	delete(m.quotas, device)
}

// ── QueueStore ──

func (m *MemStore) Enqueue(ctx context.Context, device string, guid, body []byte, ttl time.Duration) error {
	return m.EnqueueBatch(ctx, []Item{{Device: device, GUID: guid, Body: body}}, ttl)
}

// EnqueueBatch admits every envelope or none: quotas are checked for the whole batch before
// anything is written (reserve_quota inside one transaction, in the SQL version).
func (m *MemStore) EnqueueBatch(_ context.Context, items []Item, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	add := map[string]quota{}
	for _, it := range items {
		q, a := m.quotas[it.Device], add[it.Device]
		a.n, a.bytes = a.n+1, a.bytes+len(it.Body)
		if q.n+a.n > m.MaxQueue || q.bytes+a.bytes > m.MaxBytes {
			return ErrQueueFull
		}
		add[it.Device] = a
	}
	exp := m.Clock().Add(ttl)
	for _, it := range items {
		m.queues[it.Device] = append(m.queues[it.Device], queued{Stored{
			GUID: append([]byte(nil), it.GUID...), Body: append([]byte(nil), it.Body...)}, exp})
	}
	for d, a := range add {
		q := m.quotas[d]
		m.quotas[d] = quota{q.n + a.n, q.bytes + a.bytes}
	}
	return nil
}

func (m *MemStore) Fetch(_ context.Context, device string, limit int) ([]Stored, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.Clock()
	var out []Stored
	for _, q := range m.queues[device] {
		if len(out) == limit {
			break
		}
		if now.Before(q.expires) {
			out = append(out, q.Stored)
		}
	}
	return out, nil
}

// Ack deletes only the caller's own envelopes and releases their quota.
func (m *MemStore) Ack(_ context.Context, device string, guids [][]byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	keep, n, freed := m.queues[device][:0], 0, 0
	for _, q := range m.queues[device] {
		acked := false
		for _, g := range guids {
			if bytes.Equal(g, q.GUID) {
				acked = true
				break
			}
		}
		if acked {
			n, freed = n+1, freed+len(q.Body)
		} else {
			keep = append(keep, q)
		}
	}
	m.queues[device] = keep
	if n > 0 {
		q := m.quotas[device]
		m.quotas[device] = quota{q.n - n, q.bytes - freed}
	}
	return n, nil
}

// ── GroupStore ──

// AdvanceEpoch is a compare-and-swap: it succeeds only if epoch is the group's current
// epoch, so exactly one commit per epoch is accepted.
func (m *MemStore) AdvanceEpoch(_ context.Context, group []byte, epoch uint64, commit []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.epochs[string(group)] != epoch {
		return ErrStaleEpoch
	}
	m.epochs[string(group)] = epoch + 1
	m.commitLog = append(m.commitLog, append([]byte(nil), commit...))
	return nil
}

func (m *MemStore) Epoch(_ context.Context, group []byte) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.epochs[string(group)], nil
}

// Dump concatenates every byte the store holds (keys, queued envelopes, the commit log).
// The lab searches it for plaintext that should never reach the server.
func (m *MemStore) Dump() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	var b bytes.Buffer
	for _, ik := range m.identity {
		b.Write(ik)
	}
	for _, kinds := range m.signed {
		for _, k := range kinds {
			b.Write(k.Pub)
			b.Write(k.Sig)
		}
	}
	for _, kinds := range m.oneTime {
		for _, l := range kinds {
			for _, k := range l {
				b.Write(k.Pub)
				b.Write(k.Sig)
			}
		}
	}
	for _, q := range m.queues {
		for _, e := range q {
			b.Write(e.Body)
		}
	}
	for _, c := range m.commitLog {
		b.Write(c)
	}
	return b.Bytes()
}

var (
	_ KeyStore   = (*MemStore)(nil)
	_ QueueStore = (*MemStore)(nil)
	_ GroupStore = (*MemStore)(nil)
)
