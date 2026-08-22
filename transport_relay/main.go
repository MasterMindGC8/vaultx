// Command transport_relay runs Vault X's zero-knowledge relay: it routes
// opaque, already end-to-end-encrypted packets between devices and serves
// PQXDH prekey bundles, without ever persisting plaintext, sender/recipient
// identity, or IP-linked metadata to disk. See CLAUDE.md for the binding
// constraints and router/queue for the implementation.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"vaultx/transport_relay/queue"
	"vaultx/transport_relay/router"
)

const sweepInterval = 5 * time.Minute

func main() {
	addr := os.Getenv("VAULTX_RELAY_ADDR")
	if addr == "" {
		addr = ":8443"
	}

	q := queue.New(queue.DefaultTTL)
	preKeys := queue.NewPreKeyStore()
	hub := router.NewHub(q, preKeys)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/prekeys/{id}", hub.HandlePrekeyUpload)
	mux.HandleFunc("GET /v1/prekeys/{id}", hub.HandlePrekeyFetch)
	mux.HandleFunc("GET /v1/stream", hub.HandleStream)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Periodically drop any packet that outlived its TTL undelivered. This
	// is the only background path (besides an explicit client ACK) by
	// which buffered packets are ever removed.
	go func() {
		ticker := time.NewTicker(sweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				removed := q.SweepExpired()
				if removed > 0 {
					log.Printf("relay: swept %d expired packet(s)", removed)
				}
			}
		}
	}()

	go func() {
		log.Printf("relay: listening on %s", addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("relay: server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("relay: shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("relay: graceful shutdown error: %v", err)
	}
}
