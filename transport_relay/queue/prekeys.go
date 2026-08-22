package queue

import "sync"

// PreKeyBundle is the opaque, already-serialized public key material a
// device publishes so others can start a PQXDH handshake with it
// asynchronously (see crypto_core::pqxdh::PreKeyBundle, which is what
// Bundle actually contains once encoded). The relay treats it as an opaque
// blob: it never parses, validates, or logs the key material itself, only
// the device ID it's filed under.
type PreKeyBundle struct {
	DeviceID string
	Bundle   []byte
}

// PreKeyStore holds one published bundle per device, in memory. Unlike
// message packets, prekey bundles are public key material, not secret
// payload — the zero-knowledge constraint here is narrower: the relay must
// not link a device's prekey lookups to its IP or to other devices'
// activity, not that the bundle itself is confidential.
type PreKeyStore struct {
	mu      sync.Mutex
	bundles map[string]*PreKeyBundle
}

func NewPreKeyStore() *PreKeyStore {
	return &PreKeyStore{bundles: make(map[string]*PreKeyBundle)}
}

// Put publishes (or replaces) the bundle for deviceID.
func (s *PreKeyStore) Put(deviceID string, bundle []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bundles[deviceID] = &PreKeyBundle{DeviceID: deviceID, Bundle: bundle}
}

// Get fetches the bundle currently published for deviceID.
func (s *PreKeyStore) Get(deviceID string) (*PreKeyBundle, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.bundles[deviceID]
	return b, ok
}
