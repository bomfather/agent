package metrics

import (
	"net"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	defaultMetricsPort = "9095"
	metricsBindHost    = "127.0.0.1"
)

type Server struct {
	Server *http.Server
	port   string
}

type ServerOption func(*Server)

func NewServer(registry *prometheus.Registry, opts ...ServerOption) Server {
	s := Server{
		port: defaultMetricsPort,
	}
	for _, opt := range opts {
		opt(&s)
	}
	s.Server = &http.Server{
		Addr:    net.JoinHostPort(metricsBindHost, s.port),
		Handler: promhttp.HandlerFor(registry, promhttp.HandlerOpts{}),
	}
	return s
}

func WithPort(port string) ServerOption {
	return func(s *Server) {
		s.port = port
	}
}
