package secureshutdown

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewChallengeStore(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	publicKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	store := NewChallengeStore(logger, func() {}, &publicKey.PublicKey)

	assert.NotNil(t, store)
	assert.NotNil(t, store.cleanupTicker)
	assert.NotNil(t, store.stopCleanup)
	assert.NotNil(t, store.triggerShutdown)
	assert.Equal(t, &publicKey.PublicKey, store.publicKey)
	assert.Equal(t, logger, store.logger)
}

func TestCreateChallenge(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	publicKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	store := NewChallengeStore(logger, func() {}, &publicKey.PublicKey)

	nonce, err := store.createChallenge()
	require.NoError(t, err)
	assert.NotEmpty(t, nonce)

	challenge, exists := store.GetChallenge(nonce)
	assert.True(t, exists)
	assert.Equal(t, nonce, challenge.Nonce)
	assert.Equal(t, uint32(0), challenge.used)
	assert.WithinDuration(t, time.Now(), challenge.CreatedAt, time.Second)
}

func TestGetChallengeAndMarkUsed(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	publicKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	store := NewChallengeStore(logger, func() {}, &publicKey.PublicKey)

	nonce, err := store.createChallenge()
	require.NoError(t, err)

	// Get challenge
	challenge, exists := store.GetChallenge(nonce)
	assert.True(t, exists)
	assert.Equal(t, uint32(0), challenge.used)

	// Mark used using atomic compare and swap
	swapped := atomic.CompareAndSwapUint32(&challenge.used, 0, 1)
	assert.True(t, swapped)

	// Verify marked used
	updatedChallenge, exists := store.GetChallenge(nonce)
	assert.True(t, exists)
	assert.Equal(t, uint32(1), atomic.LoadUint32(&updatedChallenge.used))
}

func TestVerifySignature(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	publicKey := &privateKey.PublicKey

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	store := NewChallengeStore(logger, func() {}, publicKey)

	t.Run("Valid Signature", func(t *testing.T) {
		nonce := "test-nonce"
		hash := sha256.Sum256([]byte(nonce))
		signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
		require.NoError(t, err)
		sigStr := base64.StdEncoding.EncodeToString(signature)

		err = store.VerifySignature(nonce, sigStr)
		assert.NoError(t, err)
	})

	t.Run("Invalid Signature", func(t *testing.T) {
		nonce := "test-nonce"
		invalidSig := "invalid-signature"
		err := store.VerifySignature(nonce, invalidSig)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid signature format")
	})

	t.Run("Wrong Signature", func(t *testing.T) {
		nonce := "test-nonce"
		wrongNonce := "wrong-nonce"
		hash := sha256.Sum256([]byte(wrongNonce))
		signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
		require.NoError(t, err)
		sigStr := base64.StdEncoding.EncodeToString(signature)

		err = store.VerifySignature(nonce, sigStr)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "signature verification failed")
	})

	t.Run("No Public Key", func(t *testing.T) {
		noKeyStore := NewChallengeStore(logger, func() {}, nil)
		err := noKeyStore.VerifySignature("test", "sig")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no public key configured")
	})
}

func TestCleanupExpired(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	publicKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	store := NewChallengeStore(logger, func() {}, &publicKey.PublicKey)

	// Create recent challenge
	recentNonce, _ := store.createChallenge()

	// Create old challenge
	oldChallenge := &ShutdownChallenge{
		Nonce:     "old-nonce",
		CreatedAt: time.Now().Add(-10 * time.Minute),
		used:      0,
	}
	store.challenges.Store("old-nonce", oldChallenge)

	// Create used challenge
	usedChallenge := &ShutdownChallenge{
		Nonce:     "used-nonce",
		CreatedAt: time.Now(),
		used:      1,
	}
	store.challenges.Store("used-nonce", usedChallenge)

	// Run cleanup
	store.cleanupExpired()

	// Check recent still exists
	_, exists := store.GetChallenge(recentNonce)
	assert.True(t, exists)

	// Check old removed
	_, exists = store.GetChallenge("old-nonce")
	assert.False(t, exists)

	// Check used removed
	_, exists = store.GetChallenge("used-nonce")
	assert.False(t, exists)
}

func TestStopCleanup(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	publicKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	store := NewChallengeStore(logger, func() {}, &publicKey.PublicKey)

	// Stop cleanup
	store.StopCleanup()

	// Verify channel closed
	select {
	case <-store.stopCleanup:
		// Expected
	default:
		t.Error("stopCleanup channel not closed")
	}
}

func TestHTTPRequestHandler(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	publicKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	store := NewChallengeStore(logger, func() {}, &publicKey.PublicKey)
	h := newAPIHandler(store, nil)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/request", nil)
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Contains(t, resp, "nonce")
	nonce := resp["nonce"].(string)
	assert.NotEmpty(t, nonce)

	// Verify challenge created
	_, exists := store.GetChallenge(nonce)
	assert.True(t, exists)
}

func TestHTTPStopHandler(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	shutdownCalled := make(chan struct{}, 1)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	publicKey := &privateKey.PublicKey
	store := NewChallengeStore(logger, func() {
		shutdownCalled <- struct{}{}
	}, publicKey)
	h := newAPIHandler(store, nil)

	// Create challenge first
	nonce, err := store.createChallenge()
	require.NoError(t, err)

	// Generate valid signature
	hash := sha256.Sum256([]byte(nonce))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	require.NoError(t, err)
	sigStr := base64.StdEncoding.EncodeToString(signature)

	t.Run("Valid Request", func(t *testing.T) {
		body := map[string]string{"nonce": nonce, "signature": sigStr}
		jsonBody, _ := json.Marshal(body)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/stop", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		h.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]interface{}
		json.NewDecoder(w.Body).Decode(&resp)
		assert.Contains(t, resp, "message")
		assert.Equal(t, "shutdown initiated", resp["message"])

		// Verify marked used
		challenge, exists := store.GetChallenge(nonce)
		assert.True(t, exists)
		assert.Equal(t, uint32(1), atomic.LoadUint32(&challenge.used))

		// Verify shutdown callback invoked
		select {
		case <-shutdownCalled:
			// Expected
		default:
			t.Error("Shutdown callback not invoked")
		}
	})

	t.Run("Invalid JSON", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/stop", bytes.NewReader([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")
		h.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var resp map[string]interface{}
		json.NewDecoder(w.Body).Decode(&resp)
		assert.Contains(t, resp, "error")
		assert.Equal(t, "invalid request format", resp["error"])
	})

	t.Run("Invalid Nonce", func(t *testing.T) {
		invalidBody := map[string]string{"nonce": "invalid", "signature": sigStr}
		jsonBody, _ := json.Marshal(invalidBody)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/stop", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		h.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var resp map[string]interface{}
		json.NewDecoder(w.Body).Decode(&resp)
		assert.Contains(t, resp, "error")
		assert.Equal(t, "invalid or expired nonce", resp["error"])
	})

	t.Run("Used Nonce", func(t *testing.T) {
		// Mark as used using atomic operation
		challenge, _ := store.GetChallenge(nonce)
		atomic.StoreUint32(&challenge.used, 1)

		// Recreate body for this subtest
		body := map[string]string{"nonce": nonce, "signature": sigStr}
		jsonBody, _ := json.Marshal(body)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/stop", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		h.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var resp map[string]interface{}
		json.NewDecoder(w.Body).Decode(&resp)
		assert.Contains(t, resp, "error")
		assert.Equal(t, "nonce already used", resp["error"])
	})

	t.Run("Expired Nonce", func(t *testing.T) {
		// Reset used, set old timestamp
		challenge, _ := store.GetChallenge(nonce)
		challenge.CreatedAt = time.Now().Add(-10 * time.Minute)
		atomic.StoreUint32(&challenge.used, 0)
		store.challenges.Store(nonce, challenge)

		// Recreate body for this subtest
		body := map[string]string{"nonce": nonce, "signature": sigStr}
		jsonBody, _ := json.Marshal(body)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/stop", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		h.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var resp map[string]interface{}
		json.NewDecoder(w.Body).Decode(&resp)
		assert.Contains(t, resp, "error")
		assert.Equal(t, "nonce expired", resp["error"])
	})

	t.Run("Invalid Signature", func(t *testing.T) {
		// Reset challenge to fresh
		freshNonce, _ := store.createChallenge()
		hash := sha256.Sum256([]byte("wrong-nonce"))
		wrongSig, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
		wrongSigStr := base64.StdEncoding.EncodeToString(wrongSig)

		invalidSigBody := map[string]string{"nonce": freshNonce, "signature": wrongSigStr}
		invalidSigJson, _ := json.Marshal(invalidSigBody)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/stop", bytes.NewReader(invalidSigJson))
		req.Header.Set("Content-Type", "application/json")
		h.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		var resp map[string]interface{}
		json.NewDecoder(w.Body).Decode(&resp)
		assert.Contains(t, resp, "error")
		assert.Contains(t, resp["error"], "signature verification failed")
	})

	t.Run("Nil Shutdown Callback", func(t *testing.T) {
		nilCallbackStore := NewChallengeStore(logger, nil, publicKey)

		testNonce, _ := nilCallbackStore.createChallenge()
		testHash := sha256.Sum256([]byte(testNonce))
		testSig, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, testHash[:])
		testSigStr := base64.StdEncoding.EncodeToString(testSig)

		testBody := map[string]string{"nonce": testNonce, "signature": testSigStr}
		testJSON, _ := json.Marshal(testBody)

		h := newAPIHandler(nilCallbackStore, nil)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/stop", bytes.NewReader(testJSON))
		req.Header.Set("Content-Type", "application/json")
		h.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}
