package secureshutdown

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/bomfather/bomfather/agent/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPMetricsMiddleware(t *testing.T) {
	registry, agentMetrics := metrics.NewRegistry()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /request", withMetrics(agentMetrics, "/request", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("POST /stop", withMetrics(agentMetrics, "/stop", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "signature verification failed"})
	}))

	req := httptest.NewRequest(http.MethodPost, "/request", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	stopReq := httptest.NewRequest(http.MethodPost, "/stop", nil)
	stopW := httptest.NewRecorder()
	mux.ServeHTTP(stopW, stopReq)
	require.Equal(t, http.StatusUnauthorized, stopW.Code)

	assert.Equal(t, float64(1), gatherCounter(t, registry, "bomfather_agent_secure_shutdown_http_requests_total", "200", "POST", "/request"))
	assert.Equal(t, float64(1), gatherCounter(t, registry, "bomfather_agent_secure_shutdown_http_requests_total", "401", "POST", "/stop"))
}

func TestHTTPMetricsMiddlewareNilMetrics(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /request", withMetrics(nil, "/request", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/request", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestStartAPIServerComponentState(t *testing.T) {
	registry, agentMetrics := metrics.NewRegistry()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- StartAPIServer(ctx, strconv.Itoa(port), slog.New(slog.NewTextHandler(os.Stdout, nil)), cancel, &privateKey.PublicKey, agentMetrics)
	}()

	require.Eventually(t, func() bool {
		value, ok := gatherGauge(registry, "bomfather_agent_component_state", metrics.ComponentSecureShutdown)
		return ok && value == float64(metrics.StateRunning)
	}, 2*time.Second, 20*time.Millisecond)

	cancel()
	require.NoError(t, <-errCh)

	value, ok := gatherGauge(registry, "bomfather_agent_component_state", metrics.ComponentSecureShutdown)
	require.True(t, ok)
	assert.Equal(t, float64(metrics.StateDisabled), value)
}

func gatherCounter(t *testing.T, registry *prometheus.Registry, name, code, method, handler string) float64 {
	t.Helper()
	families, err := registry.Gather()
	require.NoError(t, err)

	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.Metric {
			labels := map[string]string{}
			for _, label := range metric.Label {
				labels[label.GetName()] = label.GetValue()
			}
			if labels["code"] == code && labels["method"] == method && labels["handler"] == handler {
				return metric.GetCounter().GetValue()
			}
		}
	}
	t.Fatalf("counter %s{%s,%s,%s} not found", name, code, method, handler)
	return 0
}

func gatherGauge(registry *prometheus.Registry, name, component string) (float64, bool) {
	families, err := registry.Gather()
	if err != nil {
		return 0, false
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.Metric {
			for _, label := range metric.Label {
				if label.GetName() == "component" && label.GetValue() == component {
					return metric.GetGauge().GetValue(), true
				}
			}
		}
	}
	return 0, false
}
