package metrics

import "github.com/prometheus/client_golang/prometheus"

const (
	StateDisabled = iota
	StateStarting
	StateRunning
	StateDegraded
)

const (
	ComponentGRPC           = "grpc"
	ComponentAPIKey         = "api_key"
	ComponentSecureShutdown = "secure_shutdown"
	Openat                  = "openat"
	Execve                  = "execve"
	Violation               = "violation"
)

type Metrics struct {
	StartTime                  prometheus.Gauge
	BuildInfo                  *prometheus.GaugeVec
	ComponentState             *prometheus.GaugeVec
	SecureShutdownHTTPRequests *prometheus.CounterVec
	GRPCStreamConnected        prometheus.Gauge
	GRPCQueueLength            *prometheus.GaugeVec
}

func NewRegistry() (*prometheus.Registry, *Metrics) {
	registry := prometheus.NewRegistry()
	metrics := &Metrics{
		StartTime: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "bomfather_agent_start_time",
			Help: "The time the metrics server started",
		}),
		BuildInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "bomfather_agent_build_info",
			Help: "Agent build information; value is always 1.",
		}, []string{"version", "commit"}),
		ComponentState: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "bomfather_agent_component_state",
			Help: "Current state of an agent component: disabled=0, starting=1, running=2, degraded=3",
		}, []string{"component"}),
		SecureShutdownHTTPRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "bomfather_agent_secure_shutdown_http_requests_total",
			Help: "Secure shutdown HTTP requests partitioned by status code, method, and handler.",
		}, []string{"code", "method", "handler"}),
		GRPCStreamConnected: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "bomfather_agent_grpc_stream_connected",
			Help: "Whether the gRPC event stream is connected (1) or not (0).",
		}),
		GRPCQueueLength: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "bomfather_agent_grpc_queue_messages",
			Help: "Number of buffered messages waiting to be sent on the gRPC event stream.",
		}, []string{"queue"}),
	}
	registry.MustRegister(
		metrics.StartTime,
		metrics.BuildInfo,
		metrics.ComponentState,
		metrics.SecureShutdownHTTPRequests,
		metrics.GRPCStreamConnected,
		metrics.GRPCQueueLength,
	)
	return registry, metrics
}

func (m *Metrics) SetBuildInfo(version, commit string) {
	m.BuildInfo.WithLabelValues(version, commit).Set(1)
}

func (m *Metrics) SetComponentState(component string, state int) {
	m.ComponentState.WithLabelValues(component).Set(float64(state))
}
