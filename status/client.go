package status

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

const DefaultMetricsHost = "127.0.0.1"

type Client struct {
	endpoint   string
	httpClient *http.Client
}

func NewClient(host, port string) *Client {
	endpoint := url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(host, port),
		Path:   "/metrics",
	}
	return &Client{
		endpoint:   endpoint.String(),
		httpClient: http.DefaultClient,
	}
}

func (c *Client) Fetch(ctx context.Context) (map[string]*dto.MetricFamily, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create metrics request: %w", err)
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("request metrics: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request metrics: unexpected HTTP status %s", response.Status)
	}

	parser := expfmt.NewTextParser(model.LegacyValidation)
	families, err := parser.TextToMetricFamilies(response.Body)
	if err != nil {
		return nil, fmt.Errorf("parse metrics response: %w", err)
	}
	return families, nil
}
