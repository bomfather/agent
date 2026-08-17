package secureshutdown

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type ShutdownChallenge struct {
	Nonce     string    // The nonce string to sign
	CreatedAt time.Time // When challenge was issued
	used      uint32    // 0=unused, 1=used
}

// ChallengeStore manages all active shutdown challenges
type ChallengeStore struct {
	challenges      sync.Map      // map[string]*ShutdownChallenge (nonce -> challenge)
	cleanupTicker   *time.Ticker  // Periodic cleanup timer
	stopCleanup     chan struct{} // Signal to stop cleanup goroutine
	stopCleanupOnce sync.Once
	triggerShutdown func()         // Requests agent shutdown after authentication
	publicKey       *rsa.PublicKey // Public key for signature verification
	logger          *slog.Logger   // Logger
}

// NewChallengeStore creates a new challenge store and starts cleanup
func NewChallengeStore(logger *slog.Logger, triggerShutdown func(), publicKey *rsa.PublicKey) *ChallengeStore {
	if triggerShutdown == nil {
		triggerShutdown = func() {}
	}
	store := &ChallengeStore{
		logger:          logger,
		triggerShutdown: triggerShutdown,
		publicKey:       publicKey,
	}
	store.startCleanup()
	return store
}

// startCleanup begins the background cleanup goroutine
func (s *ChallengeStore) startCleanup() {
	s.cleanupTicker = time.NewTicker(30 * time.Second)
	s.stopCleanup = make(chan struct{})

	go func() {
		defer s.cleanupTicker.Stop()
		for {
			select {
			case <-s.cleanupTicker.C:
				s.cleanupExpired()
			case <-s.stopCleanup:
				return
			}
		}
	}()
}

// StopCleanup stops the cleanup goroutine
func (s *ChallengeStore) StopCleanup() {
	if s.stopCleanup != nil {
		s.stopCleanupOnce.Do(func() {
			close(s.stopCleanup)
		})
	}
}

// cleanupExpired removes expired and used challenges
func (s *ChallengeStore) cleanupExpired() {
	expirationTime := time.Now().Add(-5 * time.Minute)
	var keysToDelete []string

	// First pass: collect keys to delete
	s.challenges.Range(func(key, value interface{}) bool {
		challenge := value.(*ShutdownChallenge)
		if challenge.CreatedAt.Before(expirationTime) || atomic.LoadUint32(&challenge.used) == 1 {
			keysToDelete = append(keysToDelete, key.(string))
		}
		return true
	})

	// Second pass: delete collected keys
	for _, key := range keysToDelete {
		s.challenges.Delete(key)
	}
}

// GetChallenge retrieves a challenge by nonce
func (s *ChallengeStore) GetChallenge(nonce string) (*ShutdownChallenge, bool) {
	value, exists := s.challenges.Load(nonce)
	if !exists {
		return nil, false
	}
	return value.(*ShutdownChallenge), true
}

// VerifySignature verifies a signature against the nonce using the public key
func (s *ChallengeStore) VerifySignature(nonce, signature string) error {
	if s.publicKey == nil {
		return fmt.Errorf("no public key configured")
	}

	// Decode base64 signature
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("invalid signature format: %w", err)
	}

	// Hash the nonce
	hash := sha256.Sum256([]byte(nonce))

	// Verify signature
	err = rsa.VerifyPKCS1v15(s.publicKey, crypto.SHA256, hash[:], sigBytes)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

func newNonce(size int) (string, error) {
	b := make([]byte, size) // e.g., 16 = 128 bits
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *ChallengeStore) createChallenge() (string, error) {
	nonce, err := newNonce(16)
	if err != nil {
		return "", err
	}
	challenge := &ShutdownChallenge{
		Nonce:     nonce,
		CreatedAt: time.Now(),
		used:      0,
	}
	s.challenges.Store(nonce, challenge)
	return nonce, nil
}

func (s *ChallengeStore) request(w http.ResponseWriter, r *http.Request) {
	challenge, err := s.createChallenge()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create challenge"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "request received, sign the challenge and hit the stop api with the sig and the nonce",
		"nonce":   challenge,
	})
}

func (s *ChallengeStore) stop(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Nonce     string `json:"nonce"`
		Signature string `json:"signature"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Nonce == "" || req.Signature == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request format"})
		return
	}

	// Get the challenge
	challenge, exists := s.GetChallenge(req.Nonce)
	if !exists {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or expired nonce"})
		return
	}

	if atomic.LoadUint32(&challenge.used) != 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "nonce already used"})
		return
	}

	// Check if expired
	if time.Since(challenge.CreatedAt) > 5*time.Minute {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "nonce expired"})
		return
	}

	// Verify signature
	if err := s.VerifySignature(req.Nonce, req.Signature); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "signature verification failed"})
		return
	}

	// Atomically mark as used only if still unused
	if !atomic.CompareAndSwapUint32(&challenge.used, 0, 1) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "nonce already used concurrently"})
		return
	}

	// Stop cleanup before shutting down
	s.StopCleanup()
	s.logger.Info("Shutting down agent after secure shutdown")
	s.triggerShutdown()
	writeJSON(w, http.StatusOK, map[string]string{"message": "shutdown initiated"})
}

func ParsePublicKey(publicKey string) (*rsa.PublicKey, error) {

	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		pubPEM, err := os.ReadFile(publicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key and failed to read from file: %w", err)
		}

		block, _ = pem.Decode(pubPEM)
		if block == nil {
			return nil, fmt.Errorf("shutdown public key is not valid PEM")
		}
	}

	switch block.Type {
	case "PUBLIC KEY":
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
		}

		rsaPub, ok := parsed.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("shutdown public key must be RSA")
		}
		return rsaPub, nil
	case "RSA PUBLIC KEY":
		rsaPub, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#1 public key: %w", err)
		}
		return rsaPub, nil
	case "CERTIFICATE":
		parsed, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}

		rsaPub, ok := parsed.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("shutdown public key must be RSA")
		}
		return rsaPub, nil
	default:
		return nil, fmt.Errorf("unsupported public key type: %s", block.Type)
	}
}
