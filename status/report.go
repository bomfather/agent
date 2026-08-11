package status

import (
	"fmt"
	"sort"
	"strings"

	dto "github.com/prometheus/client_model/go"
)

type Report struct {
	Metrics []MetricFamily `json:"metrics"`
	summary reportSummary  `json:"-"`
}

type MetricFamily struct {
	Name   string  `json:"name"`
	Type   string  `json:"type"`
	Help   string  `json:"help"`
	Values []Value `json:"values"`
}

type Value struct {
	Labels map[string]string `json:"labels"`
	Value  float64           `json:"value"`
}

type reportSummary struct {
	grpcState           string
	streamState         string
	apiKeyState         string
	secureShutdownState string
}

func NewReport(families map[string]*dto.MetricFamily) Report {
	names := make([]string, 0, len(families))
	for name := range families {
		names = append(names, name)
	}
	sort.Strings(names)

	report := Report{
		Metrics: make([]MetricFamily, 0, len(names)),
		summary: reportSummary{
			grpcState:           "unknown",
			streamState:         "unknown",
			apiKeyState:         "unknown",
			secureShutdownState: "unknown",
		},
	}

	for _, name := range names {
		family := families[name]
		metricFamily := MetricFamily{
			Name:   name,
			Type:   strings.ToLower(family.GetType().String()),
			Help:   family.GetHelp(),
			Values: make([]Value, 0, len(family.Metric)),
		}

		for _, metric := range family.Metric {
			value := Value{Labels: make(map[string]string, len(metric.Label))}
			for _, label := range metric.Label {
				value.Labels[label.GetName()] = label.GetValue()
			}

			switch family.GetType() {
			case dto.MetricType_COUNTER:
				value.Value = metric.GetCounter().GetValue()
			case dto.MetricType_GAUGE:
				value.Value = metric.GetGauge().GetValue()
			case dto.MetricType_UNTYPED:
				value.Value = metric.GetUntyped().GetValue()
			default:
				continue
			}
			metricFamily.Values = append(metricFamily.Values, value)
			report.applySummaryComparison(name, value)
		}

		report.Metrics = append(report.Metrics, metricFamily)
	}
	return report
}

func (r Report) Summary() string {
	streamState := r.summary.streamState
	if r.summary.grpcState == "disabled" {
		streamState = "disabled"
	}

	agentState := "running"
	if r.summary.apiKeyState == "degraded" || r.summary.grpcState == "degraded" || r.summary.secureShutdownState == "degraded" || streamState == "disconnected" {
		agentState = "degraded"
	}

	return fmt.Sprintf(
		"agent: %s\napi_key: %s\ngrpc: %s\nstream: %s\nsecure_shutdown: %s\n\nFor a more in depth report, run with --json\n",
		agentState,
		r.summary.apiKeyState,
		r.summary.grpcState,
		streamState,
		r.summary.secureShutdownState,
	)
}

func (r *Report) applySummaryComparison(metricName string, value Value) {
	switch metricName {
	case "bomfather_agent_component_state":
		v := map[float64]string{
			0: "disabled",
			1: "starting",
			2: "running",
			3: "degraded",
		}[value.Value]
		if v == "" {
			v = "unknown"
		}

		switch value.Labels["component"] {
		case "grpc":
			r.summary.grpcState = v
		case "api_key":
			r.summary.apiKeyState = v
		case "secure_shutdown":
			r.summary.secureShutdownState = v
		}
	case "bomfather_agent_grpc_stream_connected":
		if value.Value == 1 {
			r.summary.streamState = "connected"
			return
		}
		r.summary.streamState = "disconnected"
	}
}
