package secureshutdown

import (
	"context"
	"crypto/rsa"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/bomfather/bomfather/agent/metrics"
	"github.com/gin-gonic/gin"
)

const (
	serverReadHeaderTimeout = 5 * time.Second
	serverReadTimeout       = 10 * time.Second
	serverWriteTimeout      = 10 * time.Second
	serverIdleTimeout       = 60 * time.Second
)

// StartAPIServer creates and starts a new Gin API server on the specified port
func StartAPIServer(ctx context.Context, port string, logger *slog.Logger, triggerShutdown func(), publicKey *rsa.PublicKey, agentMetrics *metrics.Metrics) error {
	if logger == nil {
		logger = slog.Default()
	}

	s := NewChallengeStore(logger, triggerShutdown, publicKey)
	defer s.StopCleanup()

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	if agentMetrics != nil {
		r.Use(httpMetricsMiddleware(agentMetrics))
	}

	r.POST("/request", s.request)
	r.POST("/stop", s.stop)

	addr := ":" + port
	logger.Info("Starting secure shutdown server", "port", port)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("API server failed: %w", err)
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           r,
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

func httpMetricsMiddleware(agentMetrics *metrics.Metrics) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		if agentMetrics == nil || agentMetrics.SecureShutdownHTTPRequests == nil {
			return
		}
		handler := c.FullPath()
		if handler == "" {
			handler = "unknown"
		}
		agentMetrics.SecureShutdownHTTPRequests.WithLabelValues(
			strconv.Itoa(c.Writer.Status()),
			c.Request.Method,
			handler,
		).Inc()
	}
}
