package router

import (
	"testing"
	"time"
)

func TestAcceptedMeansQueuedNotReceived(t *testing.T) {
	srv, hub := newTestServer(t)
	sender := dialStream(t, srv, "synthetic-sender")
	defer sender.Close()
	if err := sender.WriteJSON(wireEnvelope{Type: "send", PacketID: "synthetic-packet", Recipient: "offline-peer", Payload: []byte{1, 2, 3}}); err != nil {
		t.Fatal(err)
	}
	_ = sender.SetReadDeadline(time.Now().Add(time.Second))
	var e wireEnvelope
	if err := sender.ReadJSON(&e); err != nil {
		t.Fatal(err)
	}
	if e.Type != "accepted" || e.PacketID != "synthetic-packet" {
		t.Fatal("missing acceptance confirmation")
	}
	if hub.Queue.Len() != 1 {
		t.Fatal("acceptance must retain the undelivered packet")
	}
	receiver := dialStream(t, srv, "offline-peer")
	defer receiver.Close()
	_ = receiver.SetReadDeadline(time.Now().Add(time.Second))
	if err := receiver.ReadJSON(&e); err != nil {
		t.Fatal(err)
	}
	if e.Type != "deliver" || e.PacketID != "synthetic-packet" {
		t.Fatal("queued message not delivered on reconnect")
	}
}
