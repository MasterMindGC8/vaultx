// Package router implements the relay's HTTP/WebSocket surface: publishing
// and fetching prekey bundles, and streaming packets between connected
// devices.
//
// The relay is a courier, not a party to the conversation. It never parses
// message payloads, never authenticates devices against real-world
// identity, and — per CLAUDE.md — never writes plaintext, sender/recipient
// identity, or IP-linked metadata to disk. End-to-end authentication and
// confidentiality are entirely crypto_core's responsibility (PQXDH + the
// Double Ratchet / MLS); the relay just needs to know which opaque device
// ID to hand a blob to next.
package router

import (
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"vaultx/transport_relay/queue"
)

// maxPacketPayloadBytes bounds both prekey bundle uploads and individual
// relayed packets, so a misbehaving or malicious client can't force
// unbounded memory growth in the RAM-only queue. Large files are sent as
// many chunks under this cap (see client_app's file-transfer envelope),
// not as one oversized packet — this limits per-message memory, not total
// file size.
const maxPacketPayloadBytes = 2 * 1024 * 1024

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	// Vault X's stream endpoint is only ever called by the native client, not
	// from a browser page on another origin, so the usual browser
	// CSRF-style Origin check doesn't apply here. Revisit if a web client
	// is ever added to the monorepo.
	CheckOrigin: func(r *http.Request) bool { return true },
}

// Hub owns the relay's live WebSocket connections and the ephemeral packet
// queue and prekey store they share. It holds no disk-backed state itself.
type Hub struct {
	Queue   *queue.RAMQueue
	PreKeys *queue.PreKeyStore

	mu      sync.Mutex
	clients map[string]*client // opaque device ID -> live connection
}

func NewHub(q *queue.RAMQueue, pk *queue.PreKeyStore) *Hub {
	return &Hub{Queue: q, PreKeys: pk, clients: make(map[string]*client)}
}

type client struct {
	deviceID string
	conn     *websocket.Conn
	send     chan envelope
}

// envelope is the WebSocket wire format. `Payload` is opaque
// already-encrypted bytes produced by crypto_core; Go's encoding/json
// base64-encodes/decodes []byte fields automatically.
type envelope struct {
	Type      string `json:"type"`
	PacketID  string `json:"packet_id,omitempty"`
	Sender    string `json:"sender,omitempty"`
	Recipient string `json:"recipient,omitempty"`
	Payload   []byte `json:"payload,omitempty"`
	Message   string `json:"message,omitempty"`
}

// HandlePrekeyUpload implements `POST /v1/prekeys/{id}`: the request body
// is stored verbatim as the opaque prekey bundle published for device `id`.
func (h *Hub) HandlePrekeyUpload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "missing device id", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxPacketPayloadBytes+1))
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	if len(body) == 0 {
		http.Error(w, "empty bundle", http.StatusBadRequest)
		return
	}
	if len(body) > maxPacketPayloadBytes {
		http.Error(w, "bundle too large", http.StatusRequestEntityTooLarge)
		return
	}
	h.PreKeys.Put(id, body)
	w.WriteHeader(http.StatusNoContent)
}

// HandlePrekeyFetch implements `GET /v1/prekeys/{id}`: returns the opaque
// prekey bundle currently published for device `id`, or 404 if none exists.
func (h *Hub) HandlePrekeyFetch(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	bundle, ok := h.PreKeys.Get(id)
	if !ok {
		http.Error(w, "no prekey bundle published for this device", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(bundle.Bundle)
}

// HandleStream implements `WS /v1/stream`. The first message a client must
// send is `{"type":"hello","sender":"<device id>"}`; after that it may send
// `{"type":"send", ...}` to relay a packet or `{"type":"ack", ...}` to
// confirm delivery of one it received, and will receive
// `{"type":"deliver", ...}` messages for packets addressed to it (both
// those queued while it was offline, sent immediately on connect, and any
// arriving live).
func (h *Hub) HandleStream(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return // upgrader already wrote the HTTP error response
	}
	conn.SetReadLimit(maxPacketPayloadBytes + 4096)

	var hello envelope
	if err := conn.ReadJSON(&hello); err != nil || hello.Type != "hello" || hello.Sender == "" {
		_ = conn.WriteJSON(envelope{Type: "error", Message: "expected hello with sender device id"})
		_ = conn.Close()
		return
	}
	deviceID := hello.Sender

	c := &client{deviceID: deviceID, conn: conn, send: make(chan envelope, 32)}
	h.register(c)
	defer h.unregister(c)

	writerDone := make(chan struct{})
	go h.writePump(c, writerDone)

	// Flush anything that queued up while this device was offline.
	for _, p := range h.Queue.Drain(deviceID) {
		c.send <- envelope{Type: "deliver", PacketID: p.ID, Sender: p.Sender, Payload: p.Payload}
	}

	h.readPump(c)
	close(c.send)
	<-writerDone
}

func (h *Hub) register(c *client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clients[c.deviceID] = c
}

func (h *Hub) unregister(c *client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.clients[c.deviceID] == c {
		delete(h.clients, c.deviceID)
	}
}

func (h *Hub) writePump(c *client, done chan struct{}) {
	defer close(done)
	for env := range c.send {
		_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := c.conn.WriteJSON(env); err != nil {
			return
		}
	}
}

func (h *Hub) readPump(c *client) {
	for {
		var env envelope
		if err := c.conn.ReadJSON(&env); err != nil {
			return
		}
		switch env.Type {
		case "send":
			if env.Recipient == "" || env.PacketID == "" {
				continue
			}
			h.deliverOrQueue(&queue.Packet{
				ID:        env.PacketID,
				Sender:    c.deviceID,
				Recipient: env.Recipient,
				Payload:   env.Payload,
				QueuedAt:  time.Now(),
			})
		case "ack":
			if env.PacketID != "" {
				h.Queue.Ack(c.deviceID, env.PacketID)
			}
		default:
			// Unknown envelope types are ignored rather than tearing down
			// the connection, so future message kinds can be added without
			// breaking older clients talking to a newer relay (or vice
			// versa).
		}
	}
}

// deliverOrQueue hands a packet straight to its recipient if they're
// currently connected and keeping up; otherwise it falls back to the
// ephemeral RAM queue for delivery on next connect.
func (h *Hub) deliverOrQueue(p *queue.Packet) {
	h.mu.Lock()
	recipient, online := h.clients[p.Recipient]
	h.mu.Unlock()

	if online {
		select {
		case recipient.send <- envelope{Type: "deliver", PacketID: p.ID, Sender: p.Sender, Payload: p.Payload}:
			return
		default:
			// Recipient's outbound buffer is full (slow consumer) — queue
			// instead of blocking this goroutine or dropping the packet.
		}
	}
	h.Queue.Enqueue(p)
}
