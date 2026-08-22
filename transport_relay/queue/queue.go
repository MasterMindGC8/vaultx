// Package queue implements the relay's zero-knowledge packet buffer.
//
// Per CLAUDE.md: the relay must never persist plaintext, sender/recipient
// identity, or IP-linked metadata to disk. Everything in this package lives
// only in process memory. A packet leaves memory in exactly two ways: the
// recipient ACKs it (Ack), or it outlives its TTL (SweepExpired). A process
// restart drops every undelivered packet — that is the intended behavior,
// not a bug, for a store that must never become a durable surveillance log.
package queue

import (
	"sync"
	"time"
)

// Packet is opaque, already-encrypted payload addressed to a recipient's
// opaque device ID (a hex identifier, not a real-world identity). The relay
// never inspects, decrypts, or logs Payload.
type Packet struct {
	ID        string
	Sender    string
	Recipient string
	Payload   []byte
	QueuedAt  time.Time
}

// DefaultTTL bounds how long an undelivered packet is held before it is
// swept, so an offline recipient can't be used to make the relay accumulate
// an unbounded, indefinitely-retained mailbox.
const DefaultTTL = 14 * 24 * time.Hour

// RAMQueue holds undelivered packets per recipient, entirely in memory.
type RAMQueue struct {
	mu   sync.Mutex
	byID map[string]map[string]*Packet // recipient device ID -> packet ID -> packet
	ttl  time.Duration
}

func New(ttl time.Duration) *RAMQueue {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &RAMQueue{byID: make(map[string]map[string]*Packet), ttl: ttl}
}

// Enqueue buffers a packet for later delivery.
func (q *RAMQueue) Enqueue(p *Packet) {
	q.mu.Lock()
	defer q.mu.Unlock()
	bucket, ok := q.byID[p.Recipient]
	if !ok {
		bucket = make(map[string]*Packet)
		q.byID[p.Recipient] = bucket
	}
	bucket[p.ID] = p
}

// Drain removes and returns every packet currently queued for recipient, in
// no particular order. Callers are expected to re-enqueue anything the
// recipient does not immediately ACK (e.g. on a dropped connection).
func (q *RAMQueue) Drain(recipient string) []*Packet {
	q.mu.Lock()
	defer q.mu.Unlock()
	bucket, ok := q.byID[recipient]
	if !ok || len(bucket) == 0 {
		return nil
	}
	out := make([]*Packet, 0, len(bucket))
	for _, p := range bucket {
		out = append(out, p)
	}
	delete(q.byID, recipient)
	return out
}

// Requeue puts packets back (e.g. the recipient disconnected before ACKing
// them).
func (q *RAMQueue) Requeue(packets []*Packet) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, p := range packets {
		bucket, ok := q.byID[p.Recipient]
		if !ok {
			bucket = make(map[string]*Packet)
			q.byID[p.Recipient] = bucket
		}
		bucket[p.ID] = p
	}
}

// Ack permanently deletes one packet once its recipient has confirmed
// delivery, so it is never handed out twice and never lingers past that
// point.
func (q *RAMQueue) Ack(recipient, packetID string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if bucket, ok := q.byID[recipient]; ok {
		delete(bucket, packetID)
		if len(bucket) == 0 {
			delete(q.byID, recipient)
		}
	}
}

// SweepExpired deletes packets older than the queue's TTL and returns how
// many were removed. This is the only path besides Ack by which packets
// ever leave memory before delivery; callers should run it on a timer.
func (q *RAMQueue) SweepExpired() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	removed := 0
	now := time.Now()
	for recipient, bucket := range q.byID {
		for id, p := range bucket {
			if now.Sub(p.QueuedAt) > q.ttl {
				delete(bucket, id)
				removed++
			}
		}
		if len(bucket) == 0 {
			delete(q.byID, recipient)
		}
	}
	return removed
}

// Len reports the total number of packets currently buffered, across all
// recipients. Intended for metrics/health checks only.
func (q *RAMQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	n := 0
	for _, bucket := range q.byID {
		n += len(bucket)
	}
	return n
}
