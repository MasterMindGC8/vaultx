package queue

import (
	"testing"
	"time"
)

func TestEnqueueAndDrain(t *testing.T) {
	q := New(time.Hour)
	q.Enqueue(&Packet{ID: "p1", Sender: "alice", Recipient: "bob", Payload: []byte("ct1"), QueuedAt: time.Now()})
	q.Enqueue(&Packet{ID: "p2", Sender: "alice", Recipient: "bob", Payload: []byte("ct2"), QueuedAt: time.Now()})
	q.Enqueue(&Packet{ID: "p3", Sender: "carol", Recipient: "dave", Payload: []byte("ct3"), QueuedAt: time.Now()})

	bobPackets := q.Drain("bob")
	if len(bobPackets) != 2 {
		t.Fatalf("expected 2 packets for bob, got %d", len(bobPackets))
	}

	// Draining again returns nothing: packets are removed on drain.
	if again := q.Drain("bob"); len(again) != 0 {
		t.Fatalf("expected drain to be empty on second call, got %d", len(again))
	}

	davePackets := q.Drain("dave")
	if len(davePackets) != 1 || davePackets[0].ID != "p3" {
		t.Fatalf("expected exactly p3 for dave, got %+v", davePackets)
	}
}

func TestAckRemovesExactlyOnePacket(t *testing.T) {
	q := New(time.Hour)
	q.Enqueue(&Packet{ID: "keep", Sender: "a", Recipient: "b", QueuedAt: time.Now()})
	q.Enqueue(&Packet{ID: "remove", Sender: "a", Recipient: "b", QueuedAt: time.Now()})

	q.Ack("b", "remove")

	remaining := q.Drain("b")
	if len(remaining) != 1 || remaining[0].ID != "keep" {
		t.Fatalf("expected only 'keep' to remain, got %+v", remaining)
	}
}

func TestSweepExpiredRemovesOnlyOldPackets(t *testing.T) {
	q := New(50 * time.Millisecond)
	q.Enqueue(&Packet{ID: "old", Sender: "a", Recipient: "b", QueuedAt: time.Now().Add(-time.Hour)})
	q.Enqueue(&Packet{ID: "fresh", Sender: "a", Recipient: "b", QueuedAt: time.Now()})

	removed := q.SweepExpired()
	if removed != 1 {
		t.Fatalf("expected 1 packet swept, got %d", removed)
	}

	remaining := q.Drain("b")
	if len(remaining) != 1 || remaining[0].ID != "fresh" {
		t.Fatalf("expected only 'fresh' to survive the sweep, got %+v", remaining)
	}
}

func TestLenReflectsBufferedPackets(t *testing.T) {
	q := New(time.Hour)
	if q.Len() != 0 {
		t.Fatalf("expected empty queue to have length 0, got %d", q.Len())
	}
	q.Enqueue(&Packet{ID: "1", Recipient: "a", QueuedAt: time.Now()})
	q.Enqueue(&Packet{ID: "2", Recipient: "b", QueuedAt: time.Now()})
	if q.Len() != 2 {
		t.Fatalf("expected length 2, got %d", q.Len())
	}
	q.Ack("a", "1")
	if q.Len() != 1 {
		t.Fatalf("expected length 1 after ack, got %d", q.Len())
	}
}

func TestPreKeyStorePutAndGet(t *testing.T) {
	s := NewPreKeyStore()
	if _, ok := s.Get("device-1"); ok {
		t.Fatal("expected no bundle before Put")
	}
	s.Put("device-1", []byte("opaque-bundle-bytes"))
	bundle, ok := s.Get("device-1")
	if !ok {
		t.Fatal("expected bundle after Put")
	}
	if string(bundle.Bundle) != "opaque-bundle-bytes" {
		t.Fatalf("unexpected bundle contents: %q", bundle.Bundle)
	}
}
