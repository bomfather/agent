package metrics

import (
	"net"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewServerUsesConfiguredPort(t *testing.T) {
	registry, _ := NewRegistry()
	server := NewServer(registry, WithPort("9191"))

	assert.Equal(t, net.JoinHostPort(metricsBindHost, "9191"), server.Server.Addr)
}

func TestSetBuildInfo(t *testing.T) {
	registry, m := NewRegistry()
	m.SetBuildInfo("v0.1.0-4-g67c56c7", "67c56c7")

	families, err := registry.Gather()
	require.NoError(t, err)

	var found bool
	for _, family := range families {
		if family.GetName() != "bomfather_agent_build_info" {
			continue
		}
		require.Len(t, family.Metric, 1)
		labels := map[string]string{}
		for _, label := range family.Metric[0].Label {
			labels[label.GetName()] = label.GetValue()
		}
		assert.Equal(t, "v0.1.0-4-g67c56c7", labels["version"])
		assert.Equal(t, "67c56c7", labels["commit"])
		assert.Equal(t, float64(1), family.Metric[0].GetGauge().GetValue())
		found = true
	}
	assert.True(t, found)
}

func TestGRPCConnectionAndQueueMetrics(t *testing.T) {
	registry, m := NewRegistry()

	m.GRPCStreamConnected.Set(0)
	m.GRPCQueueLength.WithLabelValues(Openat).Set(3)
	m.GRPCQueueLength.WithLabelValues(Execve).Set(1)
	m.GRPCQueueLength.WithLabelValues(Violation).Set(0)

	assert.Equal(t, float64(0), gatherGauge(t, registry, "bomfather_agent_grpc_stream_connected"))
	assert.Equal(t, float64(3), gatherLabeledGauge(t, registry, "bomfather_agent_grpc_queue_messages", "queue", Openat))
	assert.Equal(t, float64(1), gatherLabeledGauge(t, registry, "bomfather_agent_grpc_queue_messages", "queue", Execve))
	assert.Equal(t, float64(0), gatherLabeledGauge(t, registry, "bomfather_agent_grpc_queue_messages", "queue", Violation))

	m.GRPCStreamConnected.Set(1)
	assert.Equal(t, float64(1), gatherGauge(t, registry, "bomfather_agent_grpc_stream_connected"))
}

func gatherGauge(t *testing.T, registry *prometheus.Registry, name string) float64 {
	t.Helper()
	families, err := registry.Gather()
	require.NoError(t, err)
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		require.NotEmpty(t, family.Metric)
		return family.Metric[0].GetGauge().GetValue()
	}
	t.Fatalf("gauge %s not found", name)
	return 0
}

func gatherLabeledGauge(t *testing.T, registry *prometheus.Registry, name, label, value string) float64 {
	t.Helper()
	families, err := registry.Gather()
	require.NoError(t, err)
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.Metric {
			for _, l := range metric.Label {
				if l.GetName() == label && l.GetValue() == value {
					return metric.GetGauge().GetValue()
				}
			}
		}
	}
	t.Fatalf("gauge %s{%s=%s} not found", name, label, value)
	return 0
}
