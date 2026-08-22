package router

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"vaultx/transport_relay/queue"
)

func newTestServer(t *testing.T) (*httptest.Server, *Hub) {
	t.Helper()
	hub := NewHub(queue.New(time.Hour), queue.NewPreKeyStore())
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/prekeys/{id}", hub.HandlePrekeyUpload)
	mux.HandleFunc("GET /v1/prekeys/{id}", hub.HandlePrekeyFetch)
	mux.HandleFunc("GET /v1/stream", hub.HandleStream)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, hub
}

func dialStream(t *testing.T, srv *httptest.Server, deviceID string) *websocket.Conn {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/stream"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	if err := conn.WriteJSON(map[string]string{"type": "hello", "sender": deviceID}); err != nil {
		t.Fatalf("hello failed: %v", err)
	}
	return conn
}

type wireEnvelope struct {
	Type      string `json:"type"`
	PacketID  string `json:"packet_id,omitempty"`
	Sender    string `json:"sender,omitempty"`
	Recipient string `json:"recipient,omitempty"`
	Payload   []byte `json:"payload,omitempty"`
	Message   string `json:"message,omitempty"`
}

func TestPrekeyUploadAndFetch(t *testing.T) {
	srv, _ := newTestServer(t)

	bundle := []byte("opaque-pqxdh-bundle-bytes")
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/prekeys/device-alice", bytes.NewReader(bundle))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("upload request failed: %v", err)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", resp.StatusCode)
	}

	fetchResp, err := http.Get(srv.URL + "/v1/prekeys/device-alice")
	if err != nil {
		t.Fatalf("fetch request failed: %v", err)
	}
	defer fetchResp.Body.Close()
	got, _ := io.ReadAll(fetchResp.Body)
	if !bytes.Equal(got, bundle) {
		t.Fatalf("expected fetched bundle to match upload, got %q", got)
	}
}

func TestPrekeyFetchMissingDeviceReturns404(t *testing.T) {
	srv, _ := newTestServer(t)
	resp, err := http.Get(srv.URL + "/v1/prekeys/nobody")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestLiveDeliveryBetweenConnectedPeers(t *testing.T) {
	srv, _ := newTestServer(t)

	alice := dialStream(t, srv, "alice")
	defer alice.Close()
	bob := dialStream(t, srv, "bob")
	defer bob.Close()

	if err := alice.WriteJSON(map[string]any{
		"type":      "send",
		"packet_id": "msg-1",
		"recipient": "bob",
		"payload":   []byte("ciphertext-blob"),
	}); err != nil {
		t.Fatalf("send failed: %v", err)
	}

	bob.SetReadDeadline(time.Now().Add(2 * time.Second))
	var env wireEnvelope
	if err := bob.ReadJSON(&env); err != nil {
		t.Fatalf("bob did not receive delivery: %v", err)
	}
	if env.Type != "deliver" || env.Sender != "alice" || string(env.Payload) != "ciphertext-blob" {
		t.Fatalf("unexpected envelope: %+v", env)
	}
}

func TestOfflineRecipientGetsQueuedPacketOnConnect(t *testing.T) {
	srv, hub := newTestServer(t)

	alice := dialStream(t, srv, "alice")
	defer alice.Close()

	if err := alice.WriteJSON(map[string]any{
		"type":      "send",
		"packet_id": "msg-offline",
		"recipient": "bob",
		"payload":   []byte("for-later"),
	}); err != nil {
		t.Fatalf("send failed: %v", err)
	}

	// Give the server a moment to process the send before bob connects.
	deadline := time.Now().Add(2 * time.Second)
	for hub.Queue.Len() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if hub.Queue.Len() != 1 {
		t.Fatalf("expected packet to be queued for offline bob, queue len=%d", hub.Queue.Len())
	}

	bob := dialStream(t, srv, "bob")
	defer bob.Close()

	bob.SetReadDeadline(time.Now().Add(2 * time.Second))
	var env wireEnvelope
	if err := bob.ReadJSON(&env); err != nil {
		t.Fatalf("bob did not receive queued delivery on connect: %v", err)
	}
	if env.Type != "deliver" || string(env.Payload) != "for-later" {
		t.Fatalf("unexpected envelope: %+v", env)
	}

	// ACK it and confirm it's gone from the queue for good.
	if err := bob.WriteJSON(map[string]string{"type": "ack", "packet_id": env.PacketID}); err != nil {
		t.Fatalf("ack failed: %v", err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for hub.Queue.Len() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if hub.Queue.Len() != 0 {
		t.Fatalf("expected queue empty after ack, len=%d", hub.Queue.Len())
	}
}
