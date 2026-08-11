package grpcclient

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	grpc_health_v1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
)

type fakeHealthChecker struct {
	mu         sync.Mutex
	errs       []error
	calls      int
	lastReq    *grpc_health_v1.HealthCheckRequest
	lastMD     metadata.MD
	callSignal chan struct{}
}

func newFakeHealthChecker(errs ...error) *fakeHealthChecker {
	return &fakeHealthChecker{
		errs:       errs,
		callSignal: make(chan struct{}, 16),
	}
}

func (f *fakeHealthChecker) Check(ctx context.Context, in *grpc_health_v1.HealthCheckRequest, opts ...grpc.CallOption) (*grpc_health_v1.HealthCheckResponse, error) {
	f.mu.Lock()
	f.calls++
	callIdx := f.calls
	f.lastReq = in
	f.lastMD, _ = metadata.FromOutgoingContext(ctx)
	f.mu.Unlock()

	select {
	case f.callSignal <- struct{}{}:
	default:
	}

	if callIdx-1 < len(f.errs) && f.errs[callIdx-1] != nil {
		return nil, f.errs[callIdx-1]
	}
	return &grpc_health_v1.HealthCheckResponse{}, nil
}

func (f *fakeHealthChecker) CallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeHealthChecker) LastRequest() *grpc_health_v1.HealthCheckRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastReq
}

func (f *fakeHealthChecker) LastMetadata() metadata.MD {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastMD
}

func waitForCallSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for health check call")
	}
}

func healthcheckLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestRunHealthcheckOnceAddsMetadataAndService(t *testing.T) {
	t.Parallel()

	client := &DefaultClient{
		apiKey:        "api-key",
		hostname:      "host-1",
		correlationID: "corr-1",
	}
	checker := newFakeHealthChecker()

	err := client.runHealthcheckOnce(context.Background(), checker, time.Second)
	if err != nil {
		t.Fatalf("runHealthcheckOnce returned error: %v", err)
	}

	if checker.CallCount() != 1 {
		t.Fatalf("expected 1 check call, got %d", checker.CallCount())
	}
	req := checker.LastRequest()
	if req == nil {
		t.Fatal("expected request to be captured")
	}
	if req.Service != serviceName {
		t.Fatalf("unexpected service name: got %q want %q", req.Service, serviceName)
	}

	md := checker.LastMetadata()
	if got := md.Get(MetadataKeyAPIKey); len(got) != 1 || got[0] != "api-key" {
		t.Fatalf("unexpected %s metadata: %v", MetadataKeyAPIKey, got)
	}
	if got := md.Get(MetadataKeyHostname); len(got) != 1 || got[0] != "host-1" {
		t.Fatalf("unexpected %s metadata: %v", MetadataKeyHostname, got)
	}
	if got := md.Get(MetadataKeyCorrelationID); len(got) != 1 || got[0] != "corr-1" {
		t.Fatalf("unexpected %s metadata: %v", MetadataKeyCorrelationID, got)
	}
}

func TestStartHealthcheckLoopContinuesAfterError(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := &DefaultClient{apiKey: "api-key"}
	checker := newFakeHealthChecker(errors.New("first failed"), nil)
	ticks := make(chan time.Time, 4)
	done := make(chan struct{})

	go func() {
		for {
			select {
			case <-ctx.Done():
				close(done)
				return
			case <-ticks:
				if err := client.runHealthcheckOnce(ctx, checker, time.Second); err != nil {
					healthcheckLogger().Warn("healthcheck failed", "error", err)
				}
			}
		}
	}()

	ticks <- time.Now()
	waitForCallSignal(t, checker.callSignal)

	ticks <- time.Now()
	waitForCallSignal(t, checker.callSignal)

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("healthcheck loop did not stop after context cancellation")
	}

	if checker.CallCount() != 2 {
		t.Fatalf("expected 2 check calls, got %d", checker.CallCount())
	}
}

func TestStartHealthcheckNoConnReturnsImmediately(t *testing.T) {
	t.Parallel()

	client := &DefaultClient{}
	client.StartHealthcheck(context.Background(), healthcheckLogger())
}
