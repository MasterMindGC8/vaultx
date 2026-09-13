package router

import (
	"fmt"
	"testing"
	"time"

	"vaultx/transport_relay/queue"
)

// Local-only regression probes. They exercise the existing production code;
// no deployed relay, real identity, or user file is involved.
func TestAuditSlowRecipientDoesNotStrandPacket(t *testing.T) {
	srv, h := newTestServer(t)
	c := dialStream(t, srv, "audit-recipient")
	defer c.Close()
	// More than the old 32-packet channel, including enough ciphertext to
	// make the socket apply backpressure while its reader is paused.
	for i := 0; i < 80; i++ {
		h.deliverOrQueue(&queue.Packet{ID: fmt.Sprint(i), Recipient: "audit-recipient", Payload: make([]byte, 65536), QueuedAt: time.Now()})
	}
	time.Sleep(50 * time.Millisecond)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	for i := 0; i < 80; i++ {
		var e wireEnvelope
		if err := c.ReadJSON(&e); err != nil {
			t.Fatalf("packet %d missing: %v", i, err)
		}
		if e.PacketID != fmt.Sprint(i) {
			t.Fatalf("out of order at packet %d", i)
		}
	}
}

func TestAuditDisconnectRaceDoesNotPanic(t *testing.T) {
	srv, h := newTestServer(t)
	for i := 0; i < 30; i++ {
		c := dialStream(t, srv, "audit-recipient")
		done := make(chan struct{})
		go func() { _ = c.Close(); close(done) }()
		h.deliverOrQueue(&queue.Packet{ID: fmt.Sprint(i), Recipient: "audit-recipient", QueuedAt: time.Now()})
		<-done
	}
	if h.Queue.Len() != 30 {
		t.Fatal("unacknowledged packets were lost on disconnect")
	}
}

func TestAuditReconnectReplaysOnlyUnacknowledgedPackets(t *testing.T) {
	srv, h := newTestServer(t)
	h.deliverOrQueue(&queue.Packet{ID: "first", Recipient: "audit-recipient", QueuedAt: time.Now()})
	h.deliverOrQueue(&queue.Packet{ID: "second", Recipient: "audit-recipient", QueuedAt: time.Now()})
	c := dialStream(t, srv, "audit-recipient")
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	var e wireEnvelope
	if err := c.ReadJSON(&e); err != nil {
		t.Fatal(err)
	}
	if err := c.WriteJSON(wireEnvelope{Type: "ack", PacketID: "first"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for h.Queue.Len() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if h.Queue.Len() != 1 {
		t.Fatal("ACK was not applied")
	}
	_ = c.Close()
	reconnected := dialStream(t, srv, "audit-recipient")
	defer reconnected.Close()
	_ = reconnected.SetReadDeadline(time.Now().Add(time.Second))
	if err := reconnected.ReadJSON(&e); err != nil {
		t.Fatal(err)
	}
	if e.PacketID != "second" {
		t.Fatal("replayed acknowledged packet or lost pending packet")
	}
}

func TestAuditQueuedDeliveryRetainedUntilAcknowledged(t *testing.T) {
	srv, h := newTestServer(t)
	h.Queue.Enqueue(&queue.Packet{ID: "unacked", Sender: "audit-sender", Recipient: "audit-recipient", QueuedAt: time.Now()})
	c := dialStream(t, srv, "audit-recipient")
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	var e wireEnvelope
	if err := c.ReadJSON(&e); err != nil {
		t.Fatal(err)
	}
	// Reading a socket is not the application-level delivery ACK.
	if h.Queue.Len() != 1 {
		t.Fatalf("queued packet discarded before recipient ACK; retained=%d", h.Queue.Len())
	}
}
