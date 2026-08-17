package secureshutdown

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/bomfather/bomfather/agent/metrics"
)

const (
	serverReadHeaderTimeout = 5 * time.Second
	serverReadTimeout       = 10 * time.Second
	serverWriteTimeout      = 10 * time.Second
	serverIdleTimeout       = 60 * time.Second
)

// StartAPIServer creates and starts the secure shutdown HTTP server on the specified port
func StartAPIServer(ctx context.Context, port string, logger *slog.Logger, triggerShutdown func(), publicKey *rsa.PublicKey, agentMetrics *metrics.Metrics) error {
	if logger == nil {
		logger = slog.Default()
	}

	s := NewChallengeStore(logger, triggerShutdown, publicKey)
	defer s.StopCleanup()

	addr := ":" + port
	logger.Info("Starting secure shutdown server", "port", port)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("API server failed: %w", err)
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           newAPIHandler(s, agentMetrics),
		ReadHeaderTimeout: serverReadHeaderTimeout,
		ReadTimeout:       serverReadTimeout,
		WriteTimeout:      serverWriteTimeout,
		IdleTimeout:       serverIdleTimeout,
	}

	if agentMetrics != nil {
		agentMetrics.SetComponentState(metrics.ComponentSecureShutdown, metrics.StateRunning)
		defer agentMetrics.SetComponentState(metrics.ComponentSecureShutdown, metrics.StateDisabled)
	}

	go func() {
		<-ctx.Done()
		s.StopCleanup()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil && err != http.ErrServerClosed {
			logger.Error("secure shutdown API server shutdown failed", "error", err)
		}
	}()

	if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
		logger.Error("API server error", "error", err)
		return fmt.Errorf("API server failed: %w", err)
	}
	return nil
}

func newAPIHandler(s *ChallengeStore, agentMetrics *metrics.Metrics) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /request", withMetrics(agentMetrics, "/request", s.request))
	mux.HandleFunc("POST /stop", withMetrics(agentMetrics, "/stop", s.stop))
	return recoverHandler(mux)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

func withMetrics(agentMetrics *metrics.Metrics, handler string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next(rec, r)
		if agentMetrics == nil || agentMetrics.SecureShutdownHTTPRequests == nil {
			return
		}
		agentMetrics.SecureShutdownHTTPRequests.WithLabelValues(
			strconv.Itoa(rec.status),
			r.Method,
			handler,
		).Inc()
	}
}

func recoverHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
			}
		}()
		next.ServeHTTP(w, r)
	})
}
